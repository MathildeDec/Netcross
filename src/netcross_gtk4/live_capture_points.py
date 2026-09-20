"""netcross_gtk4.live_capture_points -- points de capture en direct de la
GUI (Job 48, issue #168) : une ligne du panneau de capture live peut
porter PLUSIEURS interfaces d'une meme machine ("eth0, eth1"), chacune
devenant son propre point de capture.

Module sans GTK (aucun import de gi) : la logique est testable sans
interface graphique, meme principe que stats_view.py et
dashboard_context.py.

Convention de nommage : une ligne a UNE interface garde son nom tel quel
(comportement historique) ; une ligne a PLUSIEURS interfaces produit un
point "NOM:interface" par interface (ex. "GW:eth0", "GW:eth1"), ce qui
garantit des noms distincts meme si deux machines ont une interface de
meme nom (eth0 sur chacune).
"""

from __future__ import annotations

from collections.abc import Sequence


def split_interfaces(text: str) -> list[str]:
    """Decoupe le champ interface d'une ligne en noms d'interface.

    Separateurs : virgule ou point-virgule (pas l'espace : un nom
    d'interface peut en contenir) ; espaces autour ignores ; entrees
    vides et doublons retires, ordre de premiere apparition conserve
    (l'ordre des points suit le chemin physique du reseau).
    """
    interfaces: list[str] = []
    for part in text.replace(";", ",").split(","):
        name = part.strip()
        if name and name not in interfaces:
            interfaces.append(name)
    return interfaces


def expand_live_points(
    rows: Sequence[tuple[str, str, str | None]],
) -> list[tuple[str, str, str | None]]:
    """Transforme les lignes du panneau en points de capture unitaires.

    `rows` : (nom de ligne, texte du champ interface, filtre BPF ou None),
    dans l'ordre visuel. Renvoie (label du point, interface, filtre BPF) :
    une ligne a une interface donne un point du meme nom ; une ligne a
    plusieurs interfaces donne un point "NOM:interface" par interface, le
    filtre BPF de la ligne s'appliquant a chacune.

    Une ligne sans aucune interface est conservee telle quelle (interface
    vide) pour que l'appelant continue de signaler "interface manquante".
    """
    points: list[tuple[str, str, str | None]] = []
    for label, interfaces_text, bpf_filter in rows:
        interfaces = split_interfaces(interfaces_text)
        if not interfaces:
            points.append((label, "", bpf_filter))
        elif len(interfaces) == 1:
            points.append((label, interfaces[0], bpf_filter))
        else:
            points.extend((f"{label}:{interface}", interface, bpf_filter) for interface in interfaces)
    return points


def duplicate_labels(points: Sequence[tuple[str, str, str | None]]) -> list[str]:
    """Labels portes par plusieurs points (tries, sans repetition).

    Deux points de meme nom fusionneraient leurs paquets en un seul point
    de capture -- analyse faussee sans aucun message d'erreur.
    """
    labels = [label for label, _interface, _bpf in points]
    return sorted({label for label in labels if labels.count(label) > 1})
