"""
netcross_core.forensic -- index de correlation bidirectionnel evenement ↔
flow ↔ paquet (Job 8/issue #5, §6.3 et §6.14 de FEATURES.md).

Construit une couche d'indexation permettant de naviguer dans les deux
sens :

- **Evenement → flows → paquets** : partant d'un `ExpertEvent`, retrouver
  les flux puis les paquets qui le justifient.
- **Paquet → flow → evenement** : partant d'un paquet (point + numero de
  trame), retrouver le flux auquel il appartient, puis les evenements qui
  concernent ce flux ou ce segment.

L'index est construit a partir de trois sources deja disponibles :
1. `all_packets` (liste de `Pkt`) — pour l'index paquet → flow
2. `flows` (dict produit par `correlate()`) — pour l'index flow → paquets
3. `events` (liste d'`ExpertEvent`) — pour l'index event → flows/paquets

Strategie de mapping event → flow (par ordre de priorite) :
1. Si `ExpertEvent.flow_keys` est non vide (source "tshark"), matching
   direct par cle de flux.
2. Sinon, si `ExpertEvent.evidence` contient des `EvidenceLink.packet`
   (`PacketEvidence`), matching par paquet → flow_key.
3. Sinon, matching par segment : les flows qui passent par le point
   nomme dans `event.segment` (ex: "A", "B") ou par la paire "A -> B".

Ce module est un CONSOMMATEUR des donnees deja calculees (Pkt, Flow,
ExpertEvent) — il ne recalcule rien, ne reparse aucune capture, et ne
modifie pas les objets sources. L'index est construit en UNE passe sur
chaque source a l'initialisation.

Seule exception, en bas de fichier : detect_cross_capture_duplicates()
(Job 41/issue #161) MARQUE `Pkt.is_duplicate` en place -- c'est son role,
et elle est appelee AVANT correlate()/analyse(), pas sur leurs sorties.
"""

from __future__ import annotations

from collections import defaultdict, deque

from netcross_core.correlate import flow_key
from netcross_core.expert_model import ExpertEvent, Flow, PacketEvidence
from netcross_core.models import Pkt


class ForensicIndex:
    """Index bidirectionnel evenement ↔ flow ↔ paquet.

    Construit en une passe a l'initialisation. Toutes les methodes de
    recherche sont en O(1) ou O(k) ou k est le nombre de resultats.
    """

    def __init__(
        self,
        all_packets: list[Pkt],
        flows: dict[tuple, dict[str, list[Pkt]]],
        events: list[ExpertEvent],
        nat_tolerant: bool = False,
        nat_window_ms: int = 200,
    ):
        # Index paquet → flow_key : (point, frame_number) -> flow_key
        self._packet_to_key: dict[tuple[str, int], tuple] = {}
        for pk in all_packets:
            if pk.frame_number is not None:
                k = flow_key(pk, nat_tolerant, nat_window_ms)
                self._packet_to_key[(pk.point, pk.frame_number)] = k

        # Index flow_key → Flow (objet type)
        self._flow_by_key: dict[tuple, Flow] = {}
        # Index flow_key → paquets par point
        self._packets_by_key: dict[tuple, dict[str, list[Pkt]]] = {}
        for fkey, per_point in flows.items():
            self._packets_by_key[fkey] = per_point
            f = Flow(key=fkey)
            for point, pkts in per_point.items():
                if not pkts:
                    continue
                f.points.append(point)
                f.packet_count[point] = len(pkts)
                f.byte_count[point] = sum(pk.length for pk in pkts)
                f.first_ts[point] = min(pk.ts for pk in pkts)
                f.last_ts[point] = max(pk.ts for pk in pkts)
                if f.endpoints is None:
                    f.endpoints = (min(pkts[0].src, pkts[0].dst), max(pkts[0].src, pkts[0].dst))
            self._flow_by_key[fkey] = f

        # Index segment → events
        self._events_by_segment: dict[str, list[ExpertEvent]] = defaultdict(list)
        # Index flow_key → events (quand flow_keys est peuple)
        self._events_by_flow_key: dict[tuple, list[ExpertEvent]] = defaultdict(list)
        for ev in events:
            self._events_by_segment[ev.segment].append(ev)
            for fk in ev.flow_keys:
                self._events_by_flow_key[fk].append(ev)

    # -- Evenement → flows ------------------------------------------------

    def event_to_flows(self, event: ExpertEvent) -> list[Flow]:
        """Retourne les flux lies a un ExpertEvent, par priorite :
        1. flow_keys de l'evenement (source "tshark")
        2. paquets d'evidence → flow_key
        3. flows passant par le segment (point ou paire "A -> B")
        """
        flows: list[Flow] = []
        seen_keys: set[tuple] = set()

        # 1. flow_keys direct (tshark)
        for fk in event.flow_keys:
            if fk in self._flow_by_key and fk not in seen_keys:
                flows.append(self._flow_by_key[fk])
                seen_keys.add(fk)

        # 2. evidence → PacketEvidence → flow_key
        if not flows:
            for link in event.evidence:
                if link.packet and link.packet.point and link.packet.frame_number is not None:
                    pk_key = (link.packet.point, link.packet.frame_number)
                    found_key: tuple | None = self._packet_to_key.get(pk_key)
                    if found_key and found_key not in seen_keys:
                        flows.append(self._flow_by_key[found_key])
                        seen_keys.add(found_key)

        # 3. matching par segment (point ou paire "A -> B")
        if not flows:
            segment = event.segment
            points: list[str] = []
            if " -> " in segment:
                parts = segment.split(" -> ")
                points = [p.strip() for p in parts if p.strip()]
            else:
                points = [segment]

            for fk, flow in self._flow_by_key.items():
                if any(p in flow.points for p in points) and fk not in seen_keys:
                    flows.append(flow)
                    seen_keys.add(fk)

        return flows

    # -- Evenement → paquets -----------------------------------------------

    def event_to_packets(self, event: ExpertEvent) -> list[PacketEvidence]:
        """Retourne les paquets qui justifient un ExpertEvent : d'abord
        ceux references dans evidence/packet_evidence, puis les paquets
        des flows lies (complement)."""
        pkts: list[PacketEvidence] = []
        seen: set[tuple[str, int]] = set()

        # 1. packet_evidence (tshark, liste complete)
        for pe in event.packet_evidence:
            key = (pe.point, pe.frame_number)
            if key not in seen:
                pkts.append(pe)
                seen.add(key)

        # 2. evidence → EvidenceLink.packet
        for link in event.evidence:
            if link.packet:
                key = (link.packet.point, link.packet.frame_number)
                if key not in seen:
                    pkts.append(link.packet)
                    seen.add(key)

        # 3. complement : paquets des flows lies
        for flow in self.event_to_flows(event):
            per_point = self._packets_by_key.get(flow.key, {})
            for point, pk_list in per_point.items():
                for pk in pk_list:
                    if pk.frame_number is not None:
                        key = (point, pk.frame_number)
                        if key not in seen:
                            pkts.append(PacketEvidence(point=point, frame_number=pk.frame_number))
                            seen.add(key)

        return pkts

    # -- Paquet → flow ------------------------------------------------------

    def packet_to_flow(self, point: str, frame_number: int) -> Flow | None:
        """Retourne le flow auquel appartient un paquet (point + numero
        de trame), ou None si le paquet n'est pas indexe."""
        pk_key = (point, frame_number)
        fk = self._packet_to_key.get(pk_key)
        if fk is None:
            return None
        return self._flow_by_key.get(fk)

    # -- Flow → evenements --------------------------------------------------

    def flow_to_events(self, flow: Flow) -> list[ExpertEvent]:
        """Retourne les evenements lies a un flow : d'abord par flow_keys
        direct (tshark), puis par segment (les points du flow)."""
        events: list[ExpertEvent] = []
        seen: set[int] = set()

        # 1. flow_key direct (tshark)
        for ev in self._events_by_flow_key.get(flow.key, []):
            if id(ev) not in seen:
                events.append(ev)
                seen.add(id(ev))

        # 2. matching par segment : les points du flow
        if not events:
            for point in flow.points:
                for ev in self._events_by_segment.get(point, []):
                    if id(ev) not in seen:
                        events.append(ev)
                        seen.add(id(ev))

        return events

    # -- Flow → paquets -----------------------------------------------------

    def flow_to_packets(self, flow: Flow) -> list[Pkt]:
        """Retourne tous les paquets d'un flow, tous points confondus,
        dans l'ordre de point puis d'arrivee."""
        per_point = self._packets_by_key.get(flow.key, {})
        result: list[Pkt] = []
        for point in flow.points:
            result.extend(per_point.get(point, []))
        return result


# -- Detection de doublons inter-captures (Job 41/issue #161) ---------------

# Delta maximal (ms) entre deux observations du meme payload a deux points
# differents pour les considerer comme UN doublon plutot que comme le meme
# paquet vu successivement le long du chemin. Valeur volontairement basse :
# une capture multi-points sert justement a voir le meme paquet a plusieurs
# points, avec la latence qui les separe -- un seuil trop large marquerait
# ce trafic normal comme doublon. A regler sous la plus petite latence
# attendue entre deux points (voir detect_cross_capture_duplicates).
DEFAULT_DUPLICATE_THRESHOLD_MS = 1.0


def detect_cross_capture_duplicates(
    packets: list[Pkt],
    threshold_ms: float = DEFAULT_DUPLICATE_THRESHOLD_MS,
) -> dict[tuple[str, str], int]:
    """Detecte et marque les paquets dupliques entre points de capture.

    Cas vise : un port miroir (SPAN) qui renvoie le meme trafic a deux
    sondes, si bien que le meme paquet est capture deux fois presque
    simultanement -- les compteurs de paquets/octets sont alors doubles.

    Critere de doublon (Job 41) : meme `payload_hash` ET `ts` a moins de
    `threshold_ms` d'un paquet DEJA vu a un AUTRE point. Le plus ancien
    paquet du groupe est l'« original » ; le ou les suivants (a un autre
    point, dans la fenetre) recoivent `is_duplicate = True`. A egalite
    stricte de `ts`, l'ordre de la liste `packets` departage (tri stable).
    Un doublon n'est compare qu'aux ORIGINAUX, jamais a un autre doublon :
    pas de derive en chaine (A -> B a 0,9 ms -> C a 1,8 ms de A n'est pas
    un doublon de C).

    Ne compte jamais deux paquets d'un MEME point (c'est le domaine de la
    detection de retransmissions, deja couverte ailleurs) ni les paquets
    sans `payload_hash` (ACK purs, SYN...) -- sans contenu, rien ne permet
    d'affirmer que deux paquets sont le meme.

    LIMITE ASSUMEE : la seule difference entre un doublon et le meme paquet
    vu en deux points successifs du chemin est le delai entre les deux
    observations. Si la latence reelle entre deux points est inferieure a
    `threshold_ms`, le trafic normal de ce segment sera marque doublon :
    ajuster le seuil (et/ou ne pas activer la detection) en connaissance
    de la topologie.

    Effets de bord : REINITIALISE `is_duplicate` a False sur tous les
    paquets de `packets` avant de recalculer (rappeler avec un autre seuil
    ne laisse aucune marque perimee), puis marque les doublons en place --
    contrairement a ForensicIndex, ce n'est pas un consommateur passif.

    Retourne le nombre de doublons par paire de points NON ORDONNEE
    (tuple trie alphabetiquement), forme attendue par
    `Report.duplicate_count`. Dict vide si aucun doublon.

    Raises ValueError si `threshold_ms` est negatif (0 est accepte et ne
    detecte rien : le critere est un delta STRICTEMENT inferieur).
    """
    if threshold_ms < 0:
        raise ValueError(f"threshold_ms doit etre >= 0, recu {threshold_ms!r}")

    by_hash: dict[str, list[Pkt]] = defaultdict(list)
    for pk in packets:
        pk.is_duplicate = False
        if pk.payload_hash is not None:
            by_hash[pk.payload_hash].append(pk)

    threshold_s = threshold_ms / 1000.0
    counts: dict[tuple[str, str], int] = defaultdict(int)

    for group in by_hash.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda pk: pk.ts)
        # originaux encore dans la fenetre : trie par ts croissant, donc tout
        # original trop ancien pour le paquet courant l'est aussi pour tous
        # les suivants -- on le retire une fois pour toutes (O(n) par groupe
        # au lieu de O(n^2) sur un payload tres repete, ex: keepalive).
        window: deque[Pkt] = deque()
        for pk in group:
            while window and pk.ts - window[0].ts >= threshold_s:
                window.popleft()
            original = next((o for o in window if o.point != pk.point), None)
            if original is None:
                window.append(pk)
                continue
            pk.is_duplicate = True
            pair = (original.point, pk.point) if original.point <= pk.point else (pk.point, original.point)
            counts[pair] += 1

    return dict(counts)
