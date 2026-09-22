"""
netcross_core.extract -- extraction et reconstruction de fichiers
transferes dans les flux reseau (issue #150, SCENARIO-4).

Point d'entree unique : extract_all(pcap_path, dest_dir). Chaque
protocole applicatif (HTTP, email, SMB, FTP) delegue son reassemblage au
dissecteur natif de tshark (voir les sous-modules) ; carver.py complete
avec un carving generique par magic bytes, independant de tout
dissecteur applicatif. Aucune dependance a un outil externe autre que
tshark (deja necessaire au reste de netcross -- voir pcap_parser).

Ecrit reellement les fichiers reconstruits sur disque, a la difference
de netcross_core.content (objets HTTP en mode metadata SEULEMENT, jamais
de corps conserve) : usage explicitement demande par l'analyste
(repertoire --extract-dir), le reste de netcross restant "metadata
first" par defaut -- voir netcross_core.content pour la distinction.
"""

from __future__ import annotations

from netcross_core.extract._common import TsharkError
from netcross_core.extract.carver import carve_generic
from netcross_core.extract.email import extract_email_attachments
from netcross_core.extract.ftp import extract_ftp_files
from netcross_core.extract.http import extract_http_files
from netcross_core.extract.models import ExtractedFile, extracted_files_to_dicts
from netcross_core.extract.smb import extract_smb_files

ALL_PROTOCOLS: tuple[str, ...] = ("http", "email", "smb", "ftp", "carving")

_EXTRACTORS = {
    "http": extract_http_files,
    "email": extract_email_attachments,
    "smb": extract_smb_files,
    "ftp": extract_ftp_files,
    "carving": carve_generic,
}


def extract_all(
    pcap_path: str,
    dest_dir: str,
    *,
    point: str = "",
    protocols: list[str] | None = None,
) -> list[ExtractedFile]:
    """Lance tous les extracteurs (ou seulement `protocols`, sous-liste de
    ALL_PROTOCOLS) sur `pcap_path` et ecrit les fichiers reconstruits
    sous `dest_dir`. Retourne la liste combinee des ExtractedFile.

    Chaque extracteur est independant : l'echec de l'un (TsharkError --
    p.ex. type d'objet non supporte par cette version de tshark) n'empeche
    pas les autres de s'executer ; les resultats deja obtenus sont
    conserves, le protocole en echec produit simplement zero fichier.
    TsharkNotFoundError (tshark absent du PATH) n'est PAS rattrapee ici :
    aucun extracteur ne pourrait fonctionner, l'appelant doit le savoir.
    """
    selected = protocols if protocols is not None else list(ALL_PROTOCOLS)
    unknown = set(selected) - set(ALL_PROTOCOLS)
    if unknown:
        raise ValueError(f"protocole(s) d'extraction inconnu(s) : {sorted(unknown)}")

    results: list[ExtractedFile] = []
    for proto in selected:
        try:
            results.extend(_EXTRACTORS[proto](pcap_path, dest_dir, point=point))
        except TsharkError:  # noqa: PERF203 -- l'independance des extracteurs
            # (un echec n'empeche pas les autres) est le comportement voulu,
            # pas un detail d'implementation a optimiser : le cout d'un
            # try/except par protocole (au plus 5 iterations) est negligeable.
            continue
    return results


__all__ = [
    "ALL_PROTOCOLS",
    "ExtractedFile",
    "carve_generic",
    "extract_all",
    "extract_email_attachments",
    "extract_ftp_files",
    "extract_http_files",
    "extract_smb_files",
    "extracted_files_to_dicts",
]
