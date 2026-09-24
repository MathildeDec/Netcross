"""
netcross_core.security.fast_flux -- issue #152 (SCENARIO-6, parent #141) :
detection d'infrastructures a flux rapide (fast flux) utilisees par les
botnets et C2.

Le fast flux consiste a faire resiloudre un meme domaine vers de
nombreuses IP differentes en peu de temps (rotation d'IPs), rendant
le blocage par IP inefficace. Les TTL DNS sont typiquement tres courts
(< 300s), mais comme Pkt ne porte pas le TTL DNS, le module utilise
une corrélation DNS + TCP :

1. Suivre les requetes DNS par domaine (domaine → timestamps + NXDOMAIN).
2. Suivre les connexions TCP par source (source → (dst, ts)).
3. Si une source requête un domaine puis se connecte à N IPs differentes
   dans une fenêtre de T minutes, le domaine est suspect de fast flux.

Deux signaux :

- **ip_rotation** : un domaine mène à >= ``min_ips`` IPs differentes
  en ``window_seconds`` (defaut : 5 IPs en 600s). Signal central.
- **high_nxdomain** : un domaine a un ratio NXDOMAIN >=
  ``nxdomain_ratio_min`` (defaut : 0.7). Les domaines DGA generent
  beaucoup de NXDOMAIN car tous les domaines generes ne sont pas
  enregistres. Signal faible (aggrave, jamais suffisant seul).

Anti faux positifs :
- liste blanche des memes domaines legitimes que dga.py (CDN, cloud...) ;
- domaines ignores (in-addr.arpa, local...) ;
- minimum de ``min_ips`` IPs differentes requises (pas 2-3, qui est
  normal pour un CDN/load balancer) ;
- la fenêtre glissante evite les fausses alertes sur un domaine legitime
  qui change d'IP sur plusieurs heures.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.models import Pkt
from netcross_core.security.dga import _WHITELIST_DOMAINS
from netcross_core.security.dns_tunnel import _is_ignored, split_domain
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class FastFluxThresholds:
    """Seuils de detection fast flux (tous configurables)."""

    # IP rotation
    min_ips: int = 5  # minimum d'IPs differentes
    window_seconds: float = 600.0  # fenêtre glissante (10 min)
    # NXDOMAIN
    nxdomain_ratio_min: float = 0.7
    nxdomain_min_responses: int = 5  # minimum de reponses pour evaluer le ratio


@dataclass
class FastFluxAlert:
    """Une alerte fast flux pour un domaine suspect.

    Issue #343 : un domaine suspect vu depuis plusieurs points de capture
    est UN evenement -- `points` liste tous les points ou il a ete
    observe (`point` reste un alias retro-compatible : premier point
    trie, ou None si `points` est vide)."""

    domain: str
    alert_type: str  # ip_rotation | high_nxdomain
    score: float  # 0.0 a 1.0
    reason: str
    points: tuple[str, ...] = ()
    ips: list[str] = field(default_factory=list)
    nxdomain_ratio: float = 0.0

    @property
    def point(self) -> str | None:
        return self.points[0] if self.points else None


@dataclass
class FastFluxResult:
    """Resultat de la detection fast flux."""

    alerts: list[FastFluxAlert] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.alerts)


def detect_fast_flux(
    packets: Iterable[Pkt],
    thresholds: FastFluxThresholds | None = None,
) -> FastFluxResult:
    """Detection d'infrastructures fast flux par corrélation DNS + TCP.

    Parcourt les paquets en deux passes :
    1. Indexe les requetes DNS par domaine et par source (domaine →
       source → timestamps, NXDOMAIN count, response count).
    2. Indexe les connexions TCP par source (source → (dst, ts)).
    3. Pour chaque domaine, regarde si une source qui l'a requete s'est
       ensuite connectee à >= ``min_ips`` IPs differentes dans la fenêtre.
    4. Calcule le ratio NXDOMAIN par domaine (signal faible).
    """
    logger.debug("detect_fast_flux(packets={packets}, thresholds={thresholds})")
    if thresholds is None:
        thresholds = FastFluxThresholds()

    packets = list(packets)

    # Passe 1 : DNS par domaine (nom complet)
    # full_domain -> {point -> set, sources -> set, nxdomain -> int, responses -> int}
    domain_dns: dict[str, dict] = defaultdict(
        lambda: {
            "points": set(),
            "sources": set(),
            "nxdomain": 0,
            "responses": 0,
            "query_ts": [],  # (source, ts) pour chaque requete
        }
    )

    for pkt in packets:
        if not pkt.dns_qry_name:
            continue
        name = pkt.dns_qry_name.lower().strip(".")
        if _is_ignored(name):
            continue

        registered, _sub = split_domain(name)
        if not registered:
            continue
        if registered in _WHITELIST_DOMAINS:
            continue

        # Utiliser le nom complet comme cle pour les alertes.
        info = domain_dns[name]
        info["points"].add(pkt.point)
        info["sources"].add(pkt.src)

        if pkt.dns_is_response:
            info["responses"] += 1
            if pkt.dns_rcode == 3:
                info["nxdomain"] += 1
        else:
            info["query_ts"].append((pkt.src, pkt.ts))

    # Passe 2 : connexions TCP par source
    # source -> list of (dst, ts)
    tcp_conns: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for pkt in packets:
        if pkt.proto != "TCP":
            continue
        if not pkt.dst:
            continue
        tcp_conns[pkt.src].append((pkt.dst, pkt.ts))

    # Passe 3 : corrélation DNS + TCP
    alerts: list[FastFluxAlert] = []

    for full_domain, info in domain_dns.items():
        # Signal 1 : IP rotation
        # Pour chaque source qui a requete ce domaine, compter les IPs
        # distinctes connectees dans la fenêtre après la requete DNS.
        for source in info["sources"]:
            source_conns = tcp_conns.get(source, [])
            if len(source_conns) < thresholds.min_ips:
                continue

            # Pour chaque requete DNS de cette source pour ce domaine,
            # collecter les IPs connectees dans la fenêtre suivante.
            all_ips: set[str] = set()
            for src, dns_ts in info["query_ts"]:
                if src != source:
                    continue
                for dst_ip, tcp_ts in source_conns:
                    if dns_ts <= tcp_ts <= dns_ts + thresholds.window_seconds:
                        all_ips.add(dst_ip)

            if len(all_ips) >= thresholds.min_ips:
                # Verifier que les IPs sont differentes (pas juste le meme IP N fois)
                unique_ips = {ip for ip in all_ips if ip != source}
                if len(unique_ips) >= thresholds.min_ips:
                    score = min(1.0, len(unique_ips) / (thresholds.min_ips * 2))
                    alerts.append(
                        FastFluxAlert(
                            domain=full_domain,
                            alert_type="ip_rotation",
                            score=round(score, 3),
                            reason=(
                                f"rotation d'IPs : {len(unique_ips)} IPs differentes "
                                f"en {thresholds.window_seconds:.0f}s"
                            ),
                            points=tuple(sorted(info["points"])),
                            ips=sorted(unique_ips)[:20],
                        )
                    )
                    break  # une alerte par domaine suffit

        # Signal 2 : ratio NXDOMAIN eleve
        if info["responses"] >= thresholds.nxdomain_min_responses:
            nxdomain_ratio = info["nxdomain"] / info["responses"]
            if nxdomain_ratio >= thresholds.nxdomain_ratio_min:
                score = min(1.0, nxdomain_ratio)
                alerts.append(
                    FastFluxAlert(
                        domain=full_domain,
                        alert_type="high_nxdomain",
                        score=round(score, 3),
                        reason=(
                            f"ratio NXDOMAIN eleve : {info['nxdomain']}/{info['responses']} ({nxdomain_ratio:.2f})"
                        ),
                        points=tuple(sorted(info["points"])),
                        nxdomain_ratio=round(nxdomain_ratio, 3),
                    )
                )

    return FastFluxResult(alerts=alerts)
