"""
netcross_core.extract.carver -- carving generique par magic bytes sur
n'importe quel flux TCP (issue #150, SCENARIO-4).

Complementaire de http.py/email.py/smb.py/ftp.py (qui s'appuient tous
sur un dissecteur applicatif connu de tshark) : ce module ne suppose
AUCUN protocole applicatif -- il reassemble chaque flux TCP via
`tshark -z follow,tcp,raw,N` (memes octets bruts que "Suivre le flux
TCP" de Wireshark, les deux sens confondus dans l'ordre temporel) et
recherche des signatures de fichiers connues (magic bytes) a n'importe
quel decalage -- utile pour un transfert sur un port non standard, ou un
protocole que tshark ne dissecte pas nativement.

Detection de fin de fichier volontairement conservatrice, par type :
  - ZIP : fin de l'enregistrement "End Of Central Directory" (signature
    PK\\x05\\x06, 22 octets + longueur de commentaire declaree) ;
  - PDF : marqueur %%EOF ;
  - PNG : chunk IEND (8 octets, CRC fixe car IEND ne porte jamais de
    donnees) ;
  - sans marqueur de fin connu (EXE, GIF, JPEG...) : le reste du flux
    est pris integralement -- mieux vaut un fichier trop long
    (verifiable/tronque a la main en aval) qu'un fichier tronque a tort.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable

from netcross_core.extract._common import (
    TsharkError,
    detect_type,
    file_hashes,
    run_fields,
    tshark_path,
    write_extracted,
)
from netcross_core.extract.models import ExtractedFile


def _find_zip_end(data: bytes, start: int) -> int | None:
    """Fin de l'enregistrement End Of Central Directory (EOCD)."""
    idx = data.find(b"PK\x05\x06", start)
    if idx == -1 or idx + 22 > len(data):
        return None
    comment_len = int.from_bytes(data[idx + 20 : idx + 22], "little")
    return min(idx + 22 + comment_len, len(data))


def _find_pdf_end(data: bytes, start: int) -> int | None:
    marker = b"%%EOF"
    idx = data.find(marker, start)
    if idx == -1:
        return None
    return idx + len(marker)


def _find_png_end(data: bytes, start: int) -> int | None:
    marker = b"IEND\xae\x42\x60\x82"
    idx = data.find(marker, start)
    if idx == -1:
        return None
    return idx + len(marker)


_EndFinder = Callable[[bytes, int], "int | None"]

# Ordre indifferent : le balayage (_carve) retient toujours la
# signature qui apparait en PREMIER dans le flux, quel que soit son
# rang dans ce tuple.
_SIGNATURES: tuple[tuple[str, bytes, _EndFinder | None], ...] = (
    ("ZIP", b"PK\x03\x04", _find_zip_end),
    ("PDF", b"%PDF-", _find_pdf_end),
    ("PNG", b"\x89PNG\r\n\x1a\n", _find_png_end),
    ("EXE", b"MZ", None),
    ("GIF", b"GIF8", None),
    ("JPEG", b"\xff\xd8\xff", None),
)


def _carve(data: bytes) -> list[tuple[str, int, int]]:
    """Retourne les segments (type, debut, fin) trouves dans `data`, sans
    chevauchement, dans l'ordre d'apparition."""
    matches: list[tuple[str, int, int]] = []
    cursor = 0
    while cursor < len(data):
        best: tuple[str, int, _EndFinder | None] | None = None
        for type_name, magic, end_finder in _SIGNATURES:
            idx = data.find(magic, cursor)
            if idx == -1:
                continue
            if best is None or idx < best[1]:
                best = (type_name, idx, end_finder)
        if best is None:
            break
        type_name, start, end_finder = best
        end = end_finder(data, start) if end_finder else None
        if end is None or end <= start:
            end = len(data)
        matches.append((type_name, start, end))
        cursor = max(end, start + 1)
    return matches


def _list_tcp_streams(pcap_path: str) -> list[int]:
    rows = run_fields(pcap_path, ["tcp.stream"], "tcp")
    streams: set[int] = set()
    for row in rows:
        if row and row[0]:
            streams.add(int(row[0]))
    return sorted(streams)


_HEX_LINE_RE = re.compile(r"^[0-9a-fA-F]+$")


def _follow_tcp_raw(pcap_path: str, stream_id: int) -> bytes:
    """Octets bruts reassembles du flux TCP `stream_id`, les deux sens
    confondus dans l'ordre temporel (`tshark -z follow,tcp,raw,N`)."""
    args = [tshark_path(), "-r", pcap_path, "-q", "-z", f"follow,tcp,raw,{stream_id}"]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark follow,tcp,raw a echoue (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )
    hex_chunks = [line.strip() for line in proc.stdout.splitlines() if _HEX_LINE_RE.match(line.strip())]
    return bytes.fromhex("".join(hex_chunks))


def _stream_start_meta(pcap_path: str, stream_id: int) -> tuple[int | None, float | None, str | None, str | None]:
    rows = run_fields(
        pcap_path,
        ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"],
        f"tcp.stream == {stream_id}",
    )
    if not rows:
        return None, None, None, None
    row = rows[0]
    frame_number = int(row[0]) if len(row) > 0 and row[0] else None
    ts = float(row[1]) if len(row) > 1 and row[1] else None
    ip_src = row[2] if len(row) > 2 and row[2] else None
    ip_dst = row[3] if len(row) > 3 and row[3] else None
    return frame_number, ts, ip_src, ip_dst


def carve_generic(pcap_path: str, dest_dir: str, *, point: str = "") -> list[ExtractedFile]:
    """Carving generique par magic bytes sur tous les flux TCP de
    `pcap_path`. Retourne un ExtractedFile par segment reconnu (zero si
    aucun flux TCP ou aucune signature connue)."""
    results: list[ExtractedFile] = []
    for stream_id in _list_tcp_streams(pcap_path):
        data = _follow_tcp_raw(pcap_path, stream_id)
        if not data:
            continue
        frame_number, ts, ip_src, ip_dst = _stream_start_meta(pcap_path, stream_id)
        for index, (type_name, start, end) in enumerate(_carve(data)):
            chunk = data[start:end]
            md5, sha256 = file_hashes(chunk)
            filename = f"carve_stream{stream_id}_{index}.{type_name.lower()}"
            output_path = write_extracted(dest_dir, filename, chunk)
            results.append(
                ExtractedFile(
                    protocol="carving",
                    point=point,
                    frame_number=frame_number,
                    ts=ts,
                    src=ip_src,
                    dst=ip_dst,
                    filename=filename,
                    content_type=None,
                    detected_type=detect_type(chunk),
                    size_bytes=len(chunk),
                    md5=md5,
                    sha256=sha256,
                    output_path=output_path,
                )
            )
    return results


__all__ = ["carve_generic"]
