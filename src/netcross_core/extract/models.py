"""
netcross_core.extract.models -- structures partagees du module
d'extraction/carving de fichiers (issue #150, SCENARIO-4).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ExtractedFile:
    """Un fichier reconstruit depuis un flux reseau (HTTP, email, SMB,
    FTP, ou carving generique par magic bytes).

    protocol : source de l'extraction -- "HTTP", "email", "SMB", "FTP",
        ou "carving" (flux TCP quelconque, hors dissecteur applicatif).
    point : label du point de capture (meme convention que Pkt.point),
        vide si non fourni par l'appelant.
    frame_number : numero de trame tshark associe (derniere trame de
        reassemblage cote HTTP/email/SMB/FTP, premiere trame du flux cote
        carving generique). None si indisponible.
    ts : horodatage epoch (secondes) de frame_number ci-dessus, None si
        indisponible.
    src / dst : adresses IP source/destination du flux porteur, None si
        indisponibles.
    filename : nom du fichier tel qu'observe (URI HTTP, piece jointe
        email, nom SMB/FTP...) ou nom genere pour le carving generique.
    content_type : Content-Type/MIME declare par le protocole applicatif,
        None si le protocole ne le porte pas (SMB, FTP, carving).
    detected_type : type reellement detecte par signature (magic bytes),
        independant de ce que le protocole a pu annoncer -- "unknown" si
        aucune signature connue n'a ete reconnue.
    size_bytes : taille du fichier ecrit sur disque.
    md5 / sha256 : empreintes du contenu ecrit.
    output_path : chemin du fichier ecrit sous le repertoire d'extraction
        (--extract-dir).
    """

    protocol: str
    point: str
    frame_number: int | None
    ts: float | None
    src: str | None
    dst: str | None
    filename: str
    content_type: str | None
    detected_type: str
    size_bytes: int
    md5: str
    sha256: str
    output_path: str


def extracted_files_to_dicts(files: list[ExtractedFile]) -> list[dict]:
    """Serialisation JSON/CSV stable -- meme convention que
    netcross_core.content.objects_to_dicts."""
    return [asdict(f) for f in files]


__all__ = ["ExtractedFile", "extracted_files_to_dicts"]
