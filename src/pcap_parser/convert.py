"""
pcap_parser.convert -- conversion de captures entre formats (Job 49, issue #169).

Deux familles de sorties, choisies par `format` :

  * formats de CAPTURE (pcap, pcapng, erf) -- re-encodage sans decodage par
    l'outil `mergecap` livre avec tshark, applique a UN seul fichier ;
  * exports STRUCTURES (csv, json) -- un enregistrement par paquet, produit
    a partir du decodage `tshark -T ek` (meme flux que parse_capture).

Module distinct de capture.py (deja volumineux) mais meme convention :
memes outils, memes exceptions (TsharkNotFoundError / TsharkError), ecriture
atomique dans le repertoire de sortie.
"""

from __future__ import annotations

import calendar
import csv
import datetime
import json
import os
import re
import tempfile
from collections.abc import Sequence

from pcap_parser.capture import _run_wireshark_tool, _wireshark_tool_path
from pcap_parser.ek_fields import g, hex_or_dec_to_int, layer
from pcap_parser.ek_source import EkRecord, iter_ek_records

# Formats de capture : re-encodes par mergecap -F.
CAPTURE_FORMATS = ("pcap", "pcapng", "erf")
# Exports structures : un enregistrement par paquet.
EXPORT_FORMATS = ("csv", "json")
CONVERT_FORMATS = (*CAPTURE_FORMATS, *EXPORT_FORMATS)

# Colonnes disponibles pour l'export CSV, et selection par defaut (celle de
# l'issue #169 : timestamp, src, dst, proto, length).
CSV_FIELDS = ("frame_number", "timestamp", "src", "dst", "proto", "length", "sport", "dport")
CSV_DEFAULT_FIELDS = ("timestamp", "src", "dst", "proto", "length")

# frame.time_epoch tel que rendu par `tshark -T ek` : ISO 8601 UTC, 9 decimales.
_ISO_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z?$")


def _epoch_string(iso: str | None, fallback: float) -> str:
    """Timestamp du paquet en secondes depuis l'epoch, en chaine decimale
    EXACTE (« 1700000000.500000000 »). Un float ne porte pas 9 decimales sur
    une epoch actuelle (~1,7e9) : reformater EkRecord.ts afficherait du bruit
    apres la 7e decimale, d'ou la relecture de la chaine ISO d'origine.
    `fallback` (EkRecord.ts, 6 decimales) si la chaine est absente/illisible."""
    m = _ISO_TIME_RE.match(iso) if iso else None
    if m is None:
        return f"{fallback:.6f}"
    y, mo, d, h, mi, se, frac = m.groups()
    dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=datetime.timezone.utc)
    return f"{calendar.timegm(dt.timetuple())}.{frac[:9].ljust(9, '0')}"


def _scalar(value):
    """Un champ EK repete (rare) est une liste : on garde la premiere valeur."""
    return value[0] if isinstance(value, list) and value else value


def _text(value) -> str:
    value = _scalar(value)
    return "" if value is None else str(value)


def _packet_summary(record: EkRecord) -> dict[str, str]:
    """Champs a plat d'un paquet pour l'export CSV. Valeurs de la couche la
    plus EXTERNE (ce qui est sur le fil, tunnels non depiles) ; adresses IP
    (v4 puis v6) sinon MAC Ethernet, chaine vide si rien -- un paquet non IP
    (ARP, STP, LLDP...) produit donc bien une ligne, contrairement a
    build_packet qui ignore ces trames."""
    layers = record.layers
    frame = layers.get("frame") or {}
    ip4, ip6, eth = layer(layers, "ip"), layer(layers, "ipv6"), layer(layers, "eth")
    transport = layer(layers, "tcp") or layer(layers, "udp")
    prefix = "tcp_tcp" if layer(layers, "tcp") else "udp_udp"
    length = hex_or_dec_to_int(_scalar(g(frame, "frame_frame_len")))
    # frame.protocols = "eth:ethertype:ip:udp:data" : le dernier maillon utile
    # est « udp » -- le pseudo-protocole « data » (charge non disseque) ne dit rien.
    protocols = [p for p in _text(g(frame, "frame_frame_protocols")).split(":") if p]
    while len(protocols) > 1 and protocols[-1] == "data":
        protocols.pop()
    return {
        "frame_number": _text(g(frame, "frame_frame_number")),
        "timestamp": _epoch_string(_text(g(frame, "frame_frame_time_epoch")) or None, record.ts),
        "src": _text(g(ip4, "ip_ip_src") or g(ip6, "ipv6_ipv6_src") or g(eth, "eth_eth_src")),
        "dst": _text(g(ip4, "ip_ip_dst") or g(ip6, "ipv6_ipv6_dst") or g(eth, "eth_eth_dst")),
        "proto": protocols[-1] if protocols else "",
        "length": "" if length is None else str(length),
        "sport": _text(g(transport, f"{prefix}_srcport")),
        "dport": _text(g(transport, f"{prefix}_dstport")),
    }


def _write_csv(path_in: str, dest: str, fields: Sequence[str]) -> None:
    with open(dest, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(fields)
        for record in iter_ek_records(path=path_in):
            summary = _packet_summary(record)
            writer.writerow([summary[name] for name in fields])


def _write_json(path_in: str, dest: str) -> None:
    """Tableau JSON valide, un objet par paquet sur sa propre ligne (ecrit au
    fil de l'eau : la memoire ne depend pas de la taille de la capture)."""
    with open(dest, "w", encoding="utf-8") as f:
        f.write("[")
        first = True
        for record in iter_ek_records(path=path_in):
            frame = record.layers.get("frame") or {}
            number = hex_or_dec_to_int(_scalar(g(frame, "frame_frame_number")))
            obj = {
                "frame_number": number,
                "timestamp": _epoch_string(_text(g(frame, "frame_frame_time_epoch")) or None, record.ts),
                "layers": record.layers,
            }
            f.write(("\n" if first else ",\n") + json.dumps(obj, ensure_ascii=False))
            first = False
        f.write("\n]\n")


def convert_capture(
    path_in: str,
    path_out: str,
    format: str = "pcapng",
    fields: Sequence[str] | None = None,
) -> None:
    """
    Convertit la capture `path_in` vers `path_out` au format `format`.

    Formats de capture -- "pcap" (libpcap), "pcapng", "erf" (Endace) :
    re-encodage sans decodage par `mergecap -F <format>` applique a UN seul
    fichier (l'ordre des paquets est conserve). Entrees acceptees : tout ce
    que Wireshark sait lire (pcap, pcapng, ERF, formats compresses...). Voir
    docs/capture-formats.md pour la table de compatibilite. mergecap plutot
    que `tshark -F`/`editcap -F` : ces deux-la refusent d'ecrire de l'ERF
    (« record type that can't be saved in a "erf" file », constate sur
    Wireshark 4.2.2) alors que mergecap l'ecrit -- et mergecap est deja requis
    par merge_captures. Un fichier ERF contient en plus un enregistrement
    « Provenance Metadata » (ajoute par Wireshark) qui n'est pas un paquet.

    Formats structures -- "csv", "json" (decodage `tshark -T ek`) :
      "csv"  -- une ligne d'en-tete puis UNE ligne par paquet de la capture
                (paquets non IP compris), colonnes `fields` parmi CSV_FIELDS
                (defaut : CSV_DEFAULT_FIELDS = timestamp, src, dst, proto,
                length). timestamp = secondes epoch UTC, 9 decimales ; src/dst
                = IP de la couche la plus externe, sinon MAC ; proto = couche
                la plus haute reconnue par tshark (hors « data ») ; length = taille sur le fil.
      "json" -- tableau JSON, UN objet par paquet {"frame_number",
                "timestamp", "layers"} ou "layers" reprend tels quels tous les
                champs EK de tshark. `fields` n'a pas de sens ici.

    Ecriture atomique : les intermediaires vivent dans un repertoire
    temporaire du dossier de sortie puis os.replace -- en cas d'echec,
    path_out n'est ni cree ni modifie (une sortie preexistante est intacte).

    Leve ValueError (format inconnu, fields invalide ou donne hors csv, sortie
    identique a l'entree), FileNotFoundError (entree absente ou repertoire de
    sortie inexistant), TsharkNotFoundError (outil absent du PATH) ou
    TsharkError (l'outil a echoue -- entree illisible, conversion non
    supportee par Wireshark comme pcapng multi-interfaces -> pcap...).
    """
    if format not in CONVERT_FORMATS:
        raise ValueError(f"format doit valoir l'un de {CONVERT_FORMATS} (recu : {format!r})")
    if fields is not None:
        if format != "csv":
            raise ValueError(f"fields n'a de sens que pour format='csv' (recu : format={format!r})")
        if isinstance(fields, str) or not fields:
            raise ValueError("fields doit etre une liste non vide de noms de colonnes")
        unknown = [name for name in fields if name not in CSV_FIELDS]
        if unknown:
            raise ValueError(f"colonne(s) CSV inconnue(s) {unknown} -- disponibles : {CSV_FIELDS}")
    if not os.path.isfile(path_in):
        raise FileNotFoundError(f"fichier de capture introuvable : {path_in}")
    output_real = os.path.realpath(path_out)
    if os.path.realpath(path_in) == output_real:
        raise ValueError(f"le fichier de sortie ne peut pas etre le fichier d'entree : {path_in}")
    output_dir = os.path.dirname(output_real)
    if not os.path.isdir(output_dir):
        raise FileNotFoundError(f"repertoire de sortie introuvable : {output_dir}")

    mergecap = _wireshark_tool_path("mergecap") if format in CAPTURE_FORMATS else None

    with tempfile.TemporaryDirectory(dir=output_dir, prefix=".netcross-convert-") as tmp:
        result = os.path.join(tmp, "converted")
        if mergecap is not None:
            _run_wireshark_tool([mergecap, "-F", format, "-w", result, path_in])
        elif format == "csv":
            _write_csv(path_in, result, tuple(fields) if fields is not None else CSV_DEFAULT_FIELDS)
        else:
            _write_json(path_in, result)
        os.replace(result, output_real)
