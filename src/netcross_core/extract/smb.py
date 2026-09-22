"""
netcross_core.extract.smb -- extraction des fichiers transferes via
SMB2/3 (issue #150, SCENARIO-4).

Delegue integralement le reassemblage (segments Read/Write SMB2,
credits, MID/MessageId) au dissecteur natif de tshark via
`--export-objects smb,DIR` -- aucune reimplementation du protocole
SMB2/3 ici.
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
_FILTER = "smb2.filename"


def extract_smb_files(pcap_path: str, dest_dir: str, *, point: str = "") -> list[ExtractedFile]:
    """Extrait les fichiers transferes via SMB2/3 de `pcap_path` vers
    `dest_dir`. Retourne un ExtractedFile par fichier reconstruit."""
    tmp = scratch_dir()
    try:
        run_export_objects(pcap_path, "smb", tmp)
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
                    protocol="SMB",
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


__all__ = ["extract_smb_files"]
