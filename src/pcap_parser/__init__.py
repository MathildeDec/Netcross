"""
pcap_parser -- decodage de captures reseau via tshark -T ek (moteur
Wireshark en ligne de commande).

Package independant, sans dependance a netcross_core : reutilisable
tel quel dans n'importe quel projet ayant besoin de decoder des
paquets reseau (RTP/DHCP/SIP, tunnels VLAN/MPLS/GRE/VXLAN/GTP-U/
ERSPAN/CAPWAP) sans avoir a reimplementer les dissecteurs a la main.

Organisation en couches (bas en haut) :
    ek_source   -- E/S : subprocess tshark, flux NDJSON (fichier ou live)
    capfile     -- cadrage binaire pcap/pcapng (sans dissection), pour split_capture
    ek_fields   -- acces bas niveau aux champs EK (couches empilees, hex/int)
    tunnels     -- detection d'encapsulation + selection de la couche interne
    protocols   -- RTP / DHCP / SIP (lecture des champs deja disseques + repli heuristique)
    packet      -- assemblage du RawPacket normalise
    capture     -- API publique : parse_capture / parse_captures_parallel / iter_live
                   (+ merge_captures : fusion de fichiers via mergecap, sans decodage
                   + replay_capture : rejeu de trafic via tcpreplay, sans decodage
                   + split_capture : decoupage par duree, nombre de paquets ou taille
                   + iter_live_multi : capture simultanee sur plusieurs interfaces)

Utilisation typique :

    from pcap_parser import parse_capture, iter_live

    packets = parse_capture("lan.pcapng")          # lecture d'un fichier
    for pkt in iter_live("eth0"):                    # capture en direct
        ...

    from pcap_parser import split_capture

    segments = split_capture("gros.pcapng", "segments/", by="time", value=60.0)

    from pcap_parser import iter_live_multi

    # capture simultanee sur plusieurs interfaces : (label, interface)
    for label, pkt in iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]):
        ...
"""

from pcap_parser.capture import (
    TcpreplayError,
    TcpreplayNotFoundError,
    iter_live,
    iter_live_multi,
    merge_captures,
    parse_capture,
    parse_captures_parallel,
    replay_capture,
    split_capture,
)
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError
from pcap_parser.packet import RawPacket
from pcap_parser.protocols import (
    compute_mos,
    extract_dhcp,
    extract_dns,
    extract_rtp,
    extract_sip,
    extract_tls_certificate,
)
from pcap_parser.tunnels import detect_encapsulation, is_tunnel, select_innermost_layers

__all__ = [
    "CaptureRingBuffer",
    "RawPacket",
    "TcpreplayError",
    "TcpreplayNotFoundError",
    "TsharkError",
    "TsharkNotFoundError",
    "compute_mos",
    "detect_encapsulation",
    "extract_dhcp",
    "extract_dns",
    "extract_rtp",
    "extract_sip",
    "extract_tls_certificate",
    "is_tunnel",
    "iter_live",
    "iter_live_multi",
    "merge_captures",
    "parse_capture",
    "parse_captures_parallel",
    "replay_capture",
    "select_innermost_layers",
    "split_capture",
]
