"""
netcross_core.extract.email -- extraction des pieces jointes email
(SMTP/IMAP/POP3, issue #150, SCENARIO-4).

tshark reconstruit le message complet (corps MIME, TOUJOURS encode tel
que transporte -- base64/quoted-printable jamais decode par tshark) via
`--export-objects imf,DIR` : un fichier .eml par message dissequ.
Le decodage des pieces jointes (base64, quoted-printable, 7bit/8bit,
RFC 2045/2046) est ensuite delegue au module standard `email` de Python
-- PAS reimplemente ici, et `email` fait partie de la bibliotheque
standard (aucune dependance externe supplementaire).
"""

from __future__ import annotations

import email as email_stdlib
import shutil
from email import policy
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
# Emise une fois par piece jointe (Content-Disposition: attachment),
# meme granularite qu'une piece jointe individuelle -- contrairement a
# --export-objects imf qui produit un .eml PAR MESSAGE (pouvant contenir
# plusieurs pieces jointes), d'ou l'appariement par index de piece jointe
# (row_index) plutot que par index de message dans extract_email_attachments.
_FILTER = 'mime_multipart.header.content-disposition contains "attachment"'


def extract_email_attachments(pcap_path: str, dest_dir: str, *, point: str = "") -> list[ExtractedFile]:
    """Extrait les pieces jointes des messages email (SMTP/IMAP/POP3) de
    `pcap_path` vers `dest_dir`. Retourne un ExtractedFile par piece
    jointe (un message peut en porter plusieurs, ou aucune)."""
    tmp = scratch_dir()
    try:
        run_export_objects(pcap_path, "imf", tmp)
        rows = run_fields(pcap_path, _FIELDS, _FILTER)

        results: list[ExtractedFile] = []
        row_index = 0
        for eml_path in sorted(Path(tmp).iterdir(), key=lambda p: p.stat().st_mtime_ns):
            msg = email_stdlib.message_from_bytes(eml_path.read_bytes(), policy=policy.default)
            for part in msg.walk():
                if part.get_content_disposition() != "attachment":
                    continue
                data = part.get_payload(decode=True) or b""
                filename = part.get_filename() or f"piece_jointe_{row_index + 1}"
                md5, sha256 = file_hashes(data)
                row = rows[row_index] if row_index < len(rows) else []
                row_index += 1
                frame_number = int(row[0]) if len(row) > 0 and row[0] else None
                ts = float(row[1]) if len(row) > 1 and row[1] else None
                ip_src = row[2] if len(row) > 2 and row[2] else None
                ip_dst = row[3] if len(row) > 3 and row[3] else None
                output_path = write_extracted(dest_dir, filename, data)
                results.append(
                    ExtractedFile(
                        protocol="email",
                        point=point,
                        frame_number=frame_number,
                        ts=ts,
                        src=ip_src,
                        dst=ip_dst,
                        filename=filename,
                        content_type=part.get_content_type(),
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


__all__ = ["extract_email_attachments"]
