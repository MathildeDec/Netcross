"""
netcross_core.extract._common -- utilitaires partages par les
extracteurs (execution de tshark en sous-processus, calcul de hash,
detection de type par magic bytes, ecriture des fichiers extraits).

Prive au package extract : aucun de ces noms n'est reexporte par
extract/__init__.py. Memes conventions d'erreur que
pcap_parser.capture._wireshark_tool_path/_run_wireshark_tool
(TsharkNotFoundError/TsharkError) -- reutilisees telles quelles plutot
que redefinies ici.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from pcap_parser.ek_source import TsharkError, TsharkNotFoundError

# Signatures (magic bytes) utilisees a la fois par le carving generique
# (carver.py) et pour determiner detected_type sur les fichiers extraits
# par les dissecteurs applicatifs (http.py/email.py/smb.py/ftp.py) -- un
# desalignement entre le Content-Type declare et le contenu reel reste
# toujours possible (mensonger ou absent).
MAGIC_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("ZIP", b"PK\x03\x04"),
    ("PDF", b"%PDF-"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("GIF", b"GIF8"),
    ("JPEG", b"\xff\xd8\xff"),
    ("EXE", b"MZ"),
)


def detect_type(data: bytes) -> str:
    """Type detecte par signature (magic bytes) en tete de `data`,
    independant de ce que le protocole applicatif a pu annoncer.
    "unknown" si aucune signature connue ne correspond."""
    for name, magic in MAGIC_SIGNATURES:
        if data.startswith(magic):
            return name
    return "unknown"


def file_hashes(data: bytes) -> tuple[str, str]:
    """(md5, sha256) hexdigest du contenu -- integrite forensique
    uniquement, jamais un usage de mot de passe."""
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()  # noqa: S324


def tshark_path() -> str:
    """Meme exception et meme message d'installation que
    pcap_parser.ek_source._tshark_path/pcap_parser.capture._wireshark_tool_path."""
    path = shutil.which("tshark")
    if path is None:
        raise TsharkNotFoundError(
            "tshark introuvable dans le PATH -- installer le paquet "
            "'tshark' (apt install tshark / dnf install wireshark-cli)."
        )
    return path


def run_export_objects(pcap_path: str, object_type: str, dest_dir: str) -> None:
    """Lance `tshark --export-objects TYPE,DEST_DIR` sur pcap_path.

    dest_dir doit deja exister. Aucune erreur n'est levee si tshark ne
    trouve aucun objet du type demande (dest_dir reste alors vide) --
    seul un code de retour non nul (fichier illisible, type invalide...)
    leve TsharkError.
    """
    args = [tshark_path(), "-r", pcap_path, "-q", "--export-objects", f"{object_type},{dest_dir}"]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark --export-objects {object_type} a echoue (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )


def run_fields(pcap_path: str, fields: list[str], display_filter: str) -> list[list[str]]:
    """Lance `tshark -T fields -e ... -Y filter` et retourne une liste de
    valeurs de champs par trame correspondante, dans l'ordre des trames
    (memes valeurs et ordre que la sortie de tshark, une ligne = une
    trame)."""
    args = [tshark_path(), "-r", pcap_path, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-Y", display_filter]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise TsharkError(
            f"tshark -T fields a echoue (code {proc.returncode}) : {proc.stderr.strip()}",
            returncode=proc.returncode,
            stderr=proc.stderr,
        )
    rows: list[list[str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


def write_extracted(dest_dir: str, filename: str, data: bytes) -> str:
    """Ecrit `data` sous dest_dir/filename (nom desambiguise en cas de
    collision, jamais d'ecrasement silencieux), retourne le chemin
    ecrit. `os.path.basename` protege contre un nom de fichier porteur
    d'un chemin (traversal) recu depuis le protocole source."""
    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    safe_name = os.path.basename(filename) or "fichier_sans_nom"
    target = Path(dest_dir) / safe_name
    stem, suffix = target.stem, target.suffix
    counter = 1
    while target.exists():
        target = Path(dest_dir) / f"{stem}_{counter}{suffix}"
        counter += 1
    target.write_bytes(data)
    return str(target)


def scratch_dir() -> str:
    """Repertoire temporaire pour les exports intermediaires
    (--export-objects) avant relecture et copie vers le repertoire final
    (dest_dir peut etre partage entre protocoles, un scratch par appel
    evite tout melange)."""
    return tempfile.mkdtemp(prefix="netcross-extract-")


__all__ = [
    "MAGIC_SIGNATURES",
    "TsharkError",
    "TsharkNotFoundError",
    "detect_type",
    "file_hashes",
    "run_export_objects",
    "run_fields",
    "scratch_dir",
    "tshark_path",
    "write_extracted",
]
