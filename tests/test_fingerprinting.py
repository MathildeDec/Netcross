"""
netcross_core.fingerprint -- tests de l'empreinte JA4 (TLS) et HASSH
(SSH), issue #143 (FLOW-2, parent #141).

Tout est synthetique : ClientHello TLS et SSH_MSG_KEXINIT fabriques
octet par octet (RFC 8446 §4.1.2, RFC 4253 §7.1), aucune capture ni
tshark -- comme le reste de la suite (voir conftest.py et
tests/test_banners.py).
"""

from __future__ import annotations

import struct

from conftest import make_pkt

from netcross_core.fingerprint import ssh_hassh, tls_ja4
from netcross_core.fingerprint.known import identify_tool, load_known_fingerprints
from netcross_core.fingerprint.report import build_fingerprint_records, compute_pkt_fingerprints
from netcross_core.models import ROLE_CLIENT, ROLE_SERVER, Report
from netcross_core.security.findings import apply_security_findings

# -- fabriques : ClientHello TLS -------------------------------------------


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _alpn_ext(protocols: list[str]) -> bytes:
    names = b"".join(bytes([len(p)]) + p.encode() for p in protocols)
    return _extension(0x0010, struct.pack(">H", len(names)) + names)


def _sni_ext(hostname: str = "example.com") -> bytes:
    name = hostname.encode()
    server_name = bytes([0]) + struct.pack(">H", len(name)) + name
    return _extension(0x0000, struct.pack(">H", len(server_name)) + server_name)


def _sigalgs_ext(algs: list[int]) -> bytes:
    body = struct.pack(">H", len(algs) * 2) + b"".join(struct.pack(">H", a) for a in algs)
    return _extension(0x000D, body)


def _supported_versions_ext(versions: list[int]) -> bytes:
    body = bytes([len(versions) * 2]) + b"".join(struct.pack(">H", v) for v in versions)
    return _extension(0x002B, body)


def _client_hello_record(
    ciphers: list[int],
    extensions: bytes,
    *,
    legacy_version: int = 0x0303,
    record_version: int = 0x0301,
) -> bytes:
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    body = (
        struct.pack(">H", legacy_version)
        + bytes(32)  # random
        + bytes([0])  # session_id vide
        + struct.pack(">H", len(cipher_bytes))
        + cipher_bytes
        + bytes([1, 0])  # 1 methode de compression : null
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return struct.pack(">BHH", 0x16, record_version, len(handshake)) + handshake


# -- fabriques : SSH_MSG_KEXINIT --------------------------------------------


def _name_list(names: list[str]) -> bytes:
    raw = ",".join(names).encode()
    return struct.pack(">I", len(raw)) + raw


def _kexinit_packet(
    kex: list[str],
    host_key: list[str],
    enc_c2s: list[str],
    enc_s2c: list[str],
    mac_c2s: list[str],
    mac_s2c: list[str],
    comp_c2s: list[str],
    comp_s2c: list[str],
) -> bytes:
    body = (
        bytes([20])  # SSH_MSG_KEXINIT
        + bytes(16)  # cookie
        + _name_list(kex)
        + _name_list(host_key)
        + _name_list(enc_c2s)
        + _name_list(enc_s2c)
        + _name_list(mac_c2s)
        + _name_list(mac_s2c)
        + _name_list(comp_c2s)
        + _name_list(comp_s2c)
        + _name_list([])  # languages c2s
        + _name_list([])  # languages s2c
        + bytes([0])  # first_kex_packet_follows
        + struct.pack(">I", 0)  # reserved
    )
    padding_length = 4
    packet_length = len(body) + padding_length
    return struct.pack(">IB", packet_length, padding_length) + body + bytes(padding_length)


_CURL_LIKE_HELLO = _client_hello_record(
    [0x1301, 0x1302, 0xC02B, 0xC02F],
    _sni_ext()
    + _alpn_ext(["h2", "http/1.1"])
    + _sigalgs_ext([0x0403, 0x0804])
    + _supported_versions_ext([0x0304, 0x0303]),
)

_OPENSSH_CLIENT_KEXINIT = _kexinit_packet(
    ["curve25519-sha256", "ecdh-sha2-nistp256"],
    ["rsa-sha2-512", "ssh-ed25519"],
    ["chacha20-poly1305@openssh.com", "aes128-ctr"],
    ["chacha20-poly1305@openssh.com", "aes128-ctr"],
    ["hmac-sha2-256", "hmac-sha1"],
    ["hmac-sha2-256", "hmac-sha1"],
    ["none"],
    ["none"],
)


# -- JA4 ---------------------------------------------------------------------


def test_parse_client_hello_extrait_ciphers_extensions_alpn_sigalgs():
    ch = tls_ja4.parse_client_hello(_CURL_LIKE_HELLO)
    assert ch is not None
    assert ch["cipher_suites"] == [0x1301, 0x1302, 0xC02B, 0xC02F]
    assert ch["sni"] is True
    assert ch["alpn"] == ["h2", "http/1.1"]
    assert ch["signature_algorithms"] == [0x0403, 0x0804]
    assert 0x0000 in ch["extensions"] and 0x0010 in ch["extensions"]


def test_parse_client_hello_sur_payload_non_tls_renvoie_none():
    assert tls_ja4.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None


def test_parse_client_hello_tronque_renvoie_none():
    assert tls_ja4.parse_client_hello(_CURL_LIKE_HELLO[:10]) is None


def test_ja4_version_est_13_avec_extension_supported_versions_1_3():
    ch = tls_ja4.parse_client_hello(_CURL_LIKE_HELLO)
    ja4 = tls_ja4.compute_ja4(ch)
    assert ja4.startswith("t13d")  # d = SNI present


def test_ja4_indique_absence_de_sni():
    hello = _client_hello_record([0x1301], _alpn_ext(["h2"]))
    ch = tls_ja4.parse_client_hello(hello)
    ja4 = tls_ja4.compute_ja4(ch)
    assert ja4[3] == "i"


def test_ja4_compte_les_ciphers_et_extensions_hors_grease():
    grease_cipher = 0x0A0A
    hello = _client_hello_record([grease_cipher, 0x1301, 0x1302], _sni_ext())
    ch = tls_ja4.parse_client_hello(hello)
    ja4 = tls_ja4.compute_ja4(ch)
    # t13i + nb_ciphers(2) -- GREASE ecarte, donc 2 et non 3.
    assert ja4[4:6] == "02"


def test_ja4_est_deterministe_et_insensible_a_l_ordre_des_ciphers():
    ch_a = tls_ja4.parse_client_hello(_client_hello_record([0x1301, 0x1302], _sni_ext()))
    ch_b = tls_ja4.parse_client_hello(_client_hello_record([0x1302, 0x1301], _sni_ext()))
    assert tls_ja4.compute_ja4(ch_a) == tls_ja4.compute_ja4(ch_b)


def test_ja4_alpn_code_premiere_valeur_seulement():
    ch = tls_ja4.parse_client_hello(_CURL_LIKE_HELLO)
    ja4 = tls_ja4.compute_ja4(ch)
    assert ja4[8:10] == "h2"  # premiere valeur ALPN = "h2"


def test_identify_sur_client_hello_renvoie_ja4_et_forme_lisible():
    result = tls_ja4.identify(_CURL_LIKE_HELLO)
    assert result is not None
    ja4, readable = result
    assert ja4.count("_") == 2
    assert "0x1301" in readable


def test_identify_sur_payload_sans_tls_renvoie_none():
    assert tls_ja4.identify(b"\x00" * 20) is None


# -- HASSH --------------------------------------------------------------------


def test_parse_kexinit_extrait_les_name_lists():
    kx = ssh_hassh.parse_kexinit(_OPENSSH_CLIENT_KEXINIT)
    assert kx is not None
    assert kx["kex_algorithms"] == ["curve25519-sha256", "ecdh-sha2-nistp256"]
    assert kx["encryption_algorithms_client_to_server"] == ["chacha20-poly1305@openssh.com", "aes128-ctr"]
    assert kx["mac_algorithms_client_to_server"] == ["hmac-sha2-256", "hmac-sha1"]


def test_parse_kexinit_accepte_la_banniere_ssh_devant_le_paquet():
    payload = b"SSH-2.0-OpenSSH_9.6\r\n" + _OPENSSH_CLIENT_KEXINIT
    kx = ssh_hassh.parse_kexinit(payload)
    assert kx is not None
    assert kx["kex_algorithms"][0] == "curve25519-sha256"


def test_parse_kexinit_sur_payload_non_ssh_renvoie_none():
    assert ssh_hassh.parse_kexinit(b"GET / HTTP/1.1\r\n\r\n") is None


def test_hassh_est_un_md5_hex_deterministe():
    kx = ssh_hassh.parse_kexinit(_OPENSSH_CLIENT_KEXINIT)
    h1 = ssh_hassh.compute_hassh(kx, ROLE_CLIENT)
    h2 = ssh_hassh.compute_hassh(kx, ROLE_CLIENT)
    assert h1 == h2
    assert len(h1) == 32
    int(h1, 16)  # leve ValueError si ce n'est pas de l'hexadecimal


def test_hassh_et_hasshserver_different_si_les_algos_different():
    kx = ssh_hassh.parse_kexinit(
        _kexinit_packet(
            ["curve25519-sha256"],
            ["ssh-ed25519"],
            ["aes128-ctr"],
            ["aes256-ctr"],
            ["hmac-sha1"],
            ["hmac-sha2-256"],
            ["none"],
            ["none"],
        )
    )
    assert ssh_hassh.compute_hassh(kx, ROLE_CLIENT) != ssh_hassh.compute_hassh(kx, ROLE_SERVER)


def test_identify_role_client_quand_le_port_destination_est_22():
    result = ssh_hassh.identify(_OPENSSH_CLIENT_KEXINIT, sport=51000, dport=22)
    assert result is not None
    _hassh, role, readable = result
    assert role == ROLE_CLIENT
    assert "curve25519-sha256" in readable


def test_identify_role_serveur_quand_le_port_source_est_22():
    result = ssh_hassh.identify(_OPENSSH_CLIENT_KEXINIT, sport=22, dport=51000)
    assert result is not None
    assert result[1] == ROLE_SERVER


# -- base de fingerprints connus ---------------------------------------------


def test_load_known_fingerprints_par_defaut_ne_leve_pas():
    known = load_known_fingerprints()
    assert "ja4" in known and "hassh" in known


def test_identify_tool_absent_de_la_base_renvoie_none():
    assert identify_tool("ja4", "t13d1516h2_deadbeefcafe_deadbeefcafe", {"ja4": {}, "hassh": {}}) is None


def test_identify_tool_present_dans_la_base():
    known = {"ja4": {}, "hassh": {"deadbeefdeadbeefdeadbeefdeadbeef": "OpenSSH (exemple synthetique)"}}
    assert identify_tool("hassh", "deadbeefdeadbeefdeadbeefdeadbeef", known) == "OpenSSH (exemple synthetique)"


# -- integration Pkt / Report.service_fingerprints --------------------------


def test_compute_pkt_fingerprints_sur_client_hello():
    fp = compute_pkt_fingerprints("TCP", 51000, 443, _CURL_LIKE_HELLO)
    assert fp["tls_ja4"] is not None
    assert fp["ssh_hassh"] is None


def test_compute_pkt_fingerprints_sur_kexinit():
    fp = compute_pkt_fingerprints("TCP", 51000, 22, _OPENSSH_CLIENT_KEXINIT)
    assert fp["ssh_hassh"] is not None
    assert fp["ssh_hassh_role"] == ROLE_CLIENT
    assert fp["tls_ja4"] is None


def test_compute_pkt_fingerprints_udp_ne_decode_rien():
    fp = compute_pkt_fingerprints("UDP", 51000, 443, _CURL_LIKE_HELLO)
    assert fp["tls_ja4"] is None


def test_build_fingerprint_records_deduplique_par_point_hote_empreinte():
    ja4, ja4_readable = tls_ja4.identify(_CURL_LIKE_HELLO)
    pk1 = make_pkt(src="10.0.0.5", tls_ja4=ja4, tls_ja4_readable=ja4_readable)
    pk2 = make_pkt(src="10.0.0.5", frame_number=2, tls_ja4=ja4, tls_ja4_readable=ja4_readable)
    records = build_fingerprint_records([pk1, pk2], known={"ja4": {}, "hassh": {}})
    assert len(records) == 1
    assert records[0]["service"] == "TLS/JA4"
    assert records[0]["host"] == "10.0.0.5"
    assert records[0]["fingerprint"] == ja4


def test_build_fingerprint_records_reconnait_un_outil_connu():
    ja4, _ = tls_ja4.identify(_CURL_LIKE_HELLO)
    pk = make_pkt(src="10.0.0.5", tls_ja4=ja4)
    records = build_fingerprint_records([pk], known={"ja4": {ja4: "curl (exemple synthetique)"}, "hassh": {}})
    assert records[0]["version"] == "curl (exemple synthetique)"


def test_apply_security_findings_ajoute_les_empreintes_a_service_fingerprints():
    hassh, role, readable = ssh_hassh.identify(_OPENSSH_CLIENT_KEXINIT, sport=51000, dport=22)
    pk = make_pkt(
        src="10.0.0.5", sport=51000, dport=22, ssh_hassh=hassh, ssh_hassh_role=role, ssh_hassh_readable=readable
    )
    report = Report(points=["A"])
    apply_security_findings(report, [pk])
    services = {e["service"] for e in report.service_fingerprints}
    assert "SSH/HASSH" in services
