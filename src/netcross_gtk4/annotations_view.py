"""netcross_gtk4.annotations_view -- logique de presentation pour
l'etiquetage/signets sur paquets (Job 40 / issue #160, section
"Metadonnees et annotation").

Etat de PRESENTATION / interaction UI, mais pur Python (aucun import
Gtk) : testable sans display, meme discipline que stats_view.py et
dashboard_context.py. Le cablage des widgets GTK reels (clic droit sur
une ligne de paquet -> menu contextuel "ajouter une etiquette", vue
filtrable par tag) reste a faire dans app.py -- ce module fournit les
fonctions pures necessaires (ajout/suppression d'annotation, filtrage
par tag, liste des tags disponibles pour peupler les toggles) pour que
ce cablage n'ait aucune logique metier a porter lui-meme.

Ne duplique pas `netcross_core.forensic.annotations_by_tag` (regroupement
utilise aussi par la section annotations du rapport texte) : ce module
construit dessus pour les besoins propres a l'UI (options de filtre,
ligne affichable, ajout/suppression avant ecriture du sidecar).
"""

from __future__ import annotations

from netcross_core.forensic import annotations_by_tag
from netcross_core.models import PacketAnnotation
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


def available_tags(annotations: list[PacketAnnotation]) -> list[str]:
    """Liste triee des tags distincts presents, pour peupler la ListBox
    de filtre (un toggle par tag, voir docstring du module)."""
    return sorted(annotations_by_tag(annotations).keys())


def filter_by_tags(annotations: list[PacketAnnotation], selected_tags: set[str]) -> list[PacketAnnotation]:
    """Filtre les annotations dont le tag est dans `selected_tags`.

    Un `selected_tags` vide retourne la liste complete (aucun filtre
    actif) -- convention coherente avec les autres filtres de ce projet
    (ex. stats_view.build_query), plutot qu'une liste vide qui forcerait
    l'appelant a distinguer "aucun tag coche" de "aucune annotation"."""
    if not selected_tags:
        return list(annotations)
    return [ann for ann in annotations if ann.tag in selected_tags]


def format_annotation_row(annotation: PacketAnnotation) -> str:
    """Formate une annotation pour une ligne de ListBox."""
    suffix = f" -- {annotation.comment}" if annotation.comment else ""
    return f"[{annotation.tag}] trame #{annotation.frame_number}{suffix}"


def add_annotation(
    annotations: list[PacketAnnotation],
    frame_number: int,
    tag: str,
    comment: str = "",
    color: str | None = None,
) -> list[PacketAnnotation]:
    """Retourne une NOUVELLE liste avec l'annotation ajoutee (fonction
    pure, ne modifie pas `annotations` en place -- l'appelant ecrit le
    resultat via `netcross_core.forensic.write_annotations`).

    Un tag vide ou blanc est rejete (`ValueError`) : c'est la seule
    validation portee par ce module -- le clic droit GUI declenche cette
    fonction avec le texte saisi par l'analyste, qui peut etre vide."""
    tag = tag.strip()
    if not tag:
        raise ValueError("le tag d'une annotation ne peut pas etre vide")
    return [*annotations, PacketAnnotation(frame_number=frame_number, tag=tag, comment=comment, color=color)]


def remove_annotation(annotations: list[PacketAnnotation], frame_number: int, tag: str) -> list[PacketAnnotation]:
    """Retourne une NOUVELLE liste sans l'annotation (frame_number, tag)
    -- supprime au plus une entree meme si plusieurs annotations
    partagent (frame_number, tag) par erreur amont (ecriture defensive,
    jamais cense arriver via `add_annotation` seul)."""
    result = list(annotations)
    for i, ann in enumerate(result):
        if ann.frame_number == frame_number and ann.tag == tag:
            del result[i]
            break
    return result
