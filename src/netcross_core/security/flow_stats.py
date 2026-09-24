"""
netcross_core.security.flow_stats -- issue #145 (FLOW-4, parent #141) :
analyse statistique des flux pour detecter les comportements anormaux.

Metriques calculees PAR FLUX (groupe par paire source->destination) :

- **SPLT** (Sequence of Packet Lengths and Times) : les N premiers
  paquets du flux, chacun decrit par (taille, delta_t depuis le precedent).
  Un flux SSH interactif a des petits paquets reguliers (< 100 octets),
  un transfert a de gros paquets unidirectionnels, un flux obfusque a
  une distribution aleatoire des tailles.
- **Distribution des octets** : histogramme 0-255 des octets de la charge
  utile (payload_hash est un hash, pas le payload -- on utilise la taille
  des paquets comme proxy de la distribution).
- **Entropie de Shannon** sur la distribution des tailles de paquets.
- **Ratio up/down** : volume envoye vs recu par flux.
- **Regularite temporelle** : ecart-type des intervalles entre paquets
  (un flux de beaconing a une regularite elevee).

Classification produite :
- **interactif** : petits paquets (< 100 octets en mediane), reguliers
- **transfert** : gros paquets (> 500 octets en mediane), unidirectionnel
- **obfusque** : entropie elevee sur les tailles (> 4.0 bits)
- **normal** : aucun des criteres ci-dessus

Comme dns_tunnel et beaconing, ce module ne fait que produire des
donnees : la traduction en constats du rapport de securite se fait dans
``security.findings``.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from statistics import mean, median, pstdev

from netcross_core.models import Pkt

# -- Constantes ---------------------------------------------------------------

# Nombre de paquets conserves dans le SPLT.
_SPLT_MAX_PACKETS = 20

# Seuils de classification (voir docstring du module).
_SMALL_PACKET_THRESHOLD = 100  # octets
_LARGE_PACKET_THRESHOLD = 500  # octets
_HIGH_ENTROPY_THRESHOLD = 3.5  # bits/caractere sur la distribution des tailles

CLASSIFICATION_INTERACTIVE = "interactif"
CLASSIFICATION_TRANSFER = "transfert"
CLASSIFICATION_OBFUSCATED = "obfusque"
CLASSIFICATION_NORMAL = "normal"


@dataclass(frozen=True)
class FlowStatsThresholds:
    """Seuils de classification (voir la docstring du module)."""

    small_packet_threshold: int = _SMALL_PACKET_THRESHOLD
    large_packet_threshold: int = _LARGE_PACKET_THRESHOLD
    high_entropy_threshold: float = _HIGH_ENTROPY_THRESHOLD
    splt_max_packets: int = _SPLT_MAX_PACKETS
    # Issue #346 : en dessous de ce nombre de paquets, les statistiques
    # (mediane, regularite, entropie) n'ont pas de sens -- un SYN/RST de
    # scan de 3 paquets etait classe « interactif ». Le flux reste liste,
    # classe `normal`.
    min_packets: int = 10


DEFAULT_THRESHOLDS = FlowStatsThresholds()


@dataclass
class FlowStat:
    """Statistiques d'un flux (paire source->destination)."""

    src: str
    dst: str
    # point de capture (issue #346) : les flux sont calcules par point,
    # un meme flux vu sur 3 points ne se cumule plus en un seul
    point: str | None = None
    packet_count: int = 0
    byte_count: int = 0
    # SPLT : liste de (taille, delta_t) pour les N premiers paquets
    splt: list[tuple[int, float]] = field(default_factory=list)
    # Distribution des tailles de paquets (histogramme)
    size_distribution: Counter = field(default_factory=Counter)
    # Ratio up/down (bytes src->dst / bytes dst->src)
    upload_bytes: int = 0
    download_bytes: int = 0
    # Intervalles entre paquets (pour regularite temporelle)
    inter_arrivals: list[float] = field(default_factory=list)
    # Classification
    classification: str = CLASSIFICATION_NORMAL
    # Metriques derivees
    entropy: float = 0.0
    median_size: float = 0.0
    upload_ratio: float = 0.0
    regularity_cv: float = 0.0  # coefficient de variation des intervalles

    def to_dict(self) -> dict:
        return {
            "point": self.point,
            "src": self.src,
            "dst": self.dst,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "splt": list(self.splt),
            "size_distribution": dict(self.size_distribution),
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            "inter_arrivals": list(self.inter_arrivals),
            "classification": self.classification,
            "entropy": self.entropy,
            "median_size": self.median_size,
            "upload_ratio": self.upload_ratio,
            "regularity_cv": self.regularity_cv,
        }


@dataclass
class FlowStatsResult:
    """Sortie de `analyze_flow_stats`, meme forme que les autres detecteurs."""

    flows: list[FlowStat] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"flows": [f.to_dict() for f in self.flows]}


def _shannon_entropy(counter: Counter) -> float:
    """Entropie de Shannon sur une distribution (Counter), en bits."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def _classify_flow(flow: FlowStat, thresholds: FlowStatsThresholds) -> str:
    """Classifie un flux selon les seuils."""
    sizes = list(flow.size_distribution.elements())
    if not sizes:
        return CLASSIFICATION_NORMAL

    flow.median_size = median(sizes)
    flow.entropy = _shannon_entropy(flow.size_distribution)
    total_bytes = flow.upload_bytes + flow.download_bytes
    flow.upload_ratio = flow.upload_bytes / total_bytes if total_bytes > 0 else 0.0

    # Regularite temporelle : coefficient de variation des intervalles
    if len(flow.inter_arrivals) >= 2:
        m = mean(flow.inter_arrivals)
        if m > 0:
            sd = pstdev(flow.inter_arrivals)
            flow.regularity_cv = sd / m

    # Classification (metriques ci-dessus calculees dans tous les cas)
    if flow.packet_count < thresholds.min_packets:
        return CLASSIFICATION_NORMAL
    if flow.entropy > thresholds.high_entropy_threshold:
        return CLASSIFICATION_OBFUSCATED
    if flow.median_size < thresholds.small_packet_threshold and flow.regularity_cv < 0.5:
        return CLASSIFICATION_INTERACTIVE
    if flow.median_size > thresholds.large_packet_threshold and flow.upload_ratio > 0.8:
        return CLASSIFICATION_TRANSFER
    return CLASSIFICATION_NORMAL


def analyze_flow_stats(
    packets: Iterable[Pkt],
    thresholds: FlowStatsThresholds = DEFAULT_THRESHOLDS,
) -> FlowStatsResult:
    """
    Calcule les statistiques de flux par (point, source, destination).

    Groupe les paquets par (point, src, dst), calcule SPLT, distribution des
    tailles, entropie, ratio up/down, regularite temporelle, et
    classifie chaque flux.
    """
    flows: dict[tuple[str, str, str], FlowStat] = {}
    # Garder les timestamps par flux pour calculer les inter-arrivees
    flow_timestamps: dict[tuple[str, str, str], list[float]] = defaultdict(list)

    for pk in packets:
        key = (pk.point, pk.src, pk.dst)
        flow = flows.get(key)
        if flow is None:
            flow = FlowStat(src=pk.src, dst=pk.dst, point=pk.point)
            flows[key] = flow

        flow.packet_count += 1
        flow.byte_count += pk.length
        flow.size_distribution[pk.length] += 1

        # SPLT : garder les N premiers paquets
        if len(flow.splt) < thresholds.splt_max_packets:
            delta = pk.ts - flow_timestamps[key][-1] if flow_timestamps[key] else 0.0
            flow.splt.append((pk.length, delta))

        # Upload/download
        flow.upload_bytes += pk.length

        # Timestamps pour inter-arrivees
        flow_timestamps[key].append(pk.ts)

        # Download : paquets dans l'autre sens (dst->src)
        rev_key = (pk.point, pk.dst, pk.src)
        rev_flow = flows.get(rev_key)
        if rev_flow is not None:
            rev_flow.download_bytes += pk.length

    # Recalculer download pour tous les flux
    for key, flow in flows.items():
        rev_key = (key[0], key[2], key[1])
        if rev_key in flows:
            flow.download_bytes = flows[rev_key].upload_bytes

    # Calculer les inter-arrivees et classifier
    for key, flow in flows.items():
        timestamps = flow_timestamps[key]
        if len(timestamps) >= 2:
            flow.inter_arrivals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        flow.classification = _classify_flow(flow, thresholds)

    return FlowStatsResult(flows=list(flows.values()))
