"""
tests.eth_ip_tcp_builders -- fabrique de trames Ethernet/IPv4/TCP
synthetiques pour tests/test_extract.py : aucun outil externe ni scapy
requis pour produire un pcap que tshark dissque correctement (memes
principes que pcap_builders.py, un niveau de plus : trame complete
plutot que juste le conteneur pcap).

Les checksums IP/TCP sont calcules mais tshark ne les VALIDE pas par
defaut (`tcp.check_checksum`/`ip.check_checksum` desactives par defaut
dans les preferences Wireshark) -- corrects ici par souci de rigueur,
mais leur exactitude n'est pas ce qui est teste.
"""

from __future__ import annotations

import struct

FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10

_ETH_SRC = bytes.fromhex("112233445566")
_ETH_DST = bytes.fromhex("aabbccddeeff")
_ETH_HEADER = _ETH_DST + _ETH_SRC + b"\x08\x00"


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _addr(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def _ip_header(src: str, dst: str, payload_len: int, ident: int) -> bytes:
    ver_ihl = 0x45
    total_len = 20 + payload_len
    base = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total_len, ident, 0, 64, 6, 0, _addr(src), _addr(dst))
    csum = _checksum16(base)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total_len, ident, 0, 64, 6, csum, _addr(src), _addr(dst))


def _tcp_header(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    offset_reserved = 5 << 4
    no_csum = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset_reserved, flags, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", _addr(src), _addr(dst), 0, 6, 20 + len(payload))
    csum = _checksum16(pseudo + no_csum + payload)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset_reserved, flags, 65535, csum, 0)


def tcp_frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    ident: int = 1,
) -> bytes:
    """Une trame Ethernet/IPv4/TCP complete, prete a passer a
    pcap_builders.pcap_bytes/write_pcap (avec un timestamp)."""
    tcp = _tcp_header(src, dst, sport, dport, seq, ack, flags, payload) + payload
    return _ETH_HEADER + _ip_header(src, dst, len(tcp), ident) + tcp


class TcpStreamBuilder:
    """Empile une poignee de main TCP + des segments applicatifs dans
    un sens ou l'autre, en gerant seq/ack automatiquement -- evite de
    recalculer les numeros de sequence a la main pour chaque test.

    Usage :
        b = TcpStreamBuilder("10.0.0.1", "10.0.0.2", 51000, 80)
        b.handshake()
        b.send_client(b"GET / HTTP/1.1\\r\\n\\r\\n")
        b.send_server(b"HTTP/1.1 200 OK\\r\\n\\r\\nHi")
        b.close()
        packets = b.packets  # [(ts_us, trame), ...]
    """

    def __init__(self, client: str, server: str, cport: int, sport: int, start_us: int = 1_700_000_000_000_000):
        self.client, self.server, self.cport, self.sport = client, server, cport, sport
        self.seq_c, self.seq_s = 1000, 5000
        self._ts = start_us
        self._ident_c = self._ident_s = 1
        self.packets: list[tuple[int, bytes]] = []

    def _tick(self) -> int:
        self._ts += 1000
        return self._ts

    def _emit(self, src, dst, sport, dport, seq, ack, flags, payload, is_client) -> None:
        if is_client:
            ident = self._ident_c
            self._ident_c += 1
        else:
            ident = self._ident_s
            self._ident_s += 1
        self.packets.append((self._tick(), tcp_frame(src, dst, sport, dport, seq, ack, flags, payload, ident)))

    def handshake(self) -> None:
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, 0, SYN, b"", True)
        self.seq_c += 1
        self._emit(self.server, self.client, self.sport, self.cport, self.seq_s, self.seq_c, SYN | ACK, b"", False)
        self.seq_s += 1
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, self.seq_s, ACK, b"", True)

    def send_client(self, payload: bytes) -> None:
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, self.seq_s, PSH | ACK, payload, True)
        self.seq_c += len(payload)
        self._emit(self.server, self.client, self.sport, self.cport, self.seq_s, self.seq_c, ACK, b"", False)

    def send_server(self, payload: bytes) -> None:
        self._emit(self.server, self.client, self.sport, self.cport, self.seq_s, self.seq_c, PSH | ACK, payload, False)
        self.seq_s += len(payload)
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, self.seq_s, ACK, b"", True)

    def close(self) -> None:
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, self.seq_s, FIN | ACK, b"", True)
        self.seq_c += 1
        self._emit(self.server, self.client, self.sport, self.cport, self.seq_s, self.seq_c, FIN | ACK, b"", False)
        self.seq_s += 1
        self._emit(self.client, self.server, self.cport, self.sport, self.seq_c, self.seq_s, ACK, b"", True)


__all__ = ["ACK", "FIN", "PSH", "SYN", "TcpStreamBuilder", "tcp_frame"]
