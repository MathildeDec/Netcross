"""
netcross_core.extract.http -- extraction et reconstruction des objets
transferes en HTTP (issue #150, SCENARIO-4).

Exploite le dissecteur HTTP natif de tshark via
`--export-objects http,DIR` : le reassemblage du corps (y compris
Transfer-Encoding: chunked et Content-Encoding compresse -- tshark ecrit
le corps DECOMPRESSE et REASSEMBLE) est entierement delegue a tshark,
aucun decodage HTTP n'est reimplemente ici.

Les metadonnees (frame, timestamp, IP, Content-Type declare) sont
recuperees par une requete `-T fields` separee, filtree sur les trames
ou `http.file_data` est present -- ce champ ne porte le corps REASSEMBLE
complet que sur la trame qui acheve le reassemblage (comportement
Wireshark), verifie empiriquement suivre le MEME ordre de trames que
`--export-objects` (voir tests/test_extract.py::test_http_integration).
Appariement par POSITION (meme index dans les deux listes) : best-effort,
peut se desynchroniser sur des captures avec de nombreux objets HTTP
fortement entrelaces -- documente plutot que garanti absolument.
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

_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "http.content_type"]
_FILTER = "http.file_data"


def extract_http_files(pcap_path: str, dest_dir: str, *, point: str = "") -> list[ExtractedFile]:
    """Extrait les objets HTTP (telechargements, images, documents...) de
    `pcap_path` vers `dest_dir`. Retourne un ExtractedFile par objet
    reconstruit, liste vide si aucun objet HTTP n'est present."""
    tmp = scratch_dir()
    try:
        run_export_objects(pcap_path, "http", tmp)
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
            content_type = row[4] if len(row) > 4 and row[4] else None
            output_path = write_extracted(dest_dir, src_path.name, data)
            results.append(
                ExtractedFile(
                    protocol="HTTP",
                    point=point,
                    frame_number=frame_number,
                    ts=ts,
                    src=ip_src,
                    dst=ip_dst,
                    filename=src_path.name,
                    content_type=content_type,
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


__all__ = ["extract_http_files"]
