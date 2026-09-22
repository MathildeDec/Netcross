"""
netcross_core.extract.ftp -- extraction des fichiers transferes via FTP
(canal de donnees RETR/STOR, issue #150, SCENARIO-4).

Delegue le reassemblage du canal de donnees ftp-data (port actif/passif
negocie sur le canal de controle) au dissecteur natif de tshark via
`--export-objects ftp-data,DIR` -- aucune reimplementation du protocole
FTP ici.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from netcross_core.extract._common import (
    detect_type,
    file_hashes,
    run_export_objects,
    run_fields,
    scratch_dir,
    write_extracted,
)
from netcross_core.extract.models import ExtractedFile

_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"]
# Emise sur la trame de reponse du canal de CONTROLE qui recapitule le
# transfert ftp-data acheve (nombre d'octets, trames de premiere/derniere
# trame) -- une ligne par transfert complete, meme granularite qu'un
# fichier exporte.
_FILTER = "ftp.command-response.bytes"


def extract_ftp_files(pcap_path: str, dest_dir: str, *, point: str = "") -> list[ExtractedFile]:
    """Extrait les fichiers transferes via FTP (RETR/STOR) de
    `pcap_path` vers `dest_dir`. Retourne un ExtractedFile par transfert
    reconstruit."""
    tmp = scratch_dir()
    try:
        run_export_objects(pcap_path, "ftp-data", tmp)
        rows = run_fields(pcap_path, _FIELDS, _FILTER)

        written = sorted(Path(tmp).iterdir(), key=lambda p: p.stat().st_mtime_ns)
        results: list[ExtractedFile] = []
        for i, src_path in enumerate(written):
            data = src_path.read_bytes()
            md5, sha256 = file_hashes(data)
            row = rows[i] if i < len(rows) else []
            frame_number = int(row[0]) if len(row) > 0 and row[0] else None
            ts = float(row[1]) if len(row) > 1 and row[1] else None
            ip_src = row[2] if len(row) > 2 and row[2] else None
            ip_dst = row[3] if len(row) > 3 and row[3] else None
            output_path = write_extracted(dest_dir, src_path.name, data)
            results.append(
                ExtractedFile(
                    protocol="FTP",
                    point=point,
                    frame_number=frame_number,
                    ts=ts,
                    src=ip_src,
                    dst=ip_dst,
                    filename=src_path.name,
                    content_type=None,
                    detected_type=detect_type(data),
                    size_bytes=len(data),
                    md5=md5,
                    sha256=sha256,
                    output_path=output_path,
                )
            )
        return results
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


__all__ = ["extract_ftp_files"]
