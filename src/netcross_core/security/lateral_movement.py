"""
netcross_core.security.lateral_movement -- issue #149 (SCENARIO-3, parent
#141) : detection de mouvements lateraux internes (scans, propagation,
brute force) entre hotes d'un meme reseau prive.

Le module exploite uniquement les champs deja decodes de `Pkt` (`ts`,
`src`, `dst`, `sport`, `dport`, `proto`, `flags`, `frame_number`) : aucune
nouvelle dissection tshark. Independant de #143/#145 (fingerprints, flow
stats) et de #144 (tunneling DNS, deja couvert separement).

Perimetre : uniquement le trafic INTERNE-INTERNE (source ET destination
sur une adresse privee -- RFC 1918/RFC 4193 -- ni loopback ni multicast ni
link-local) : un mouvement lateral est par definition une reconnaissance
ou une propagation AU SEIN du reseau, pas vers Internet (deja couvert par
`beaconing`/`dns_tunnel` pour les destinations externes).

Cinq signaux, calcules PAR POINT DE CAPTURE puis PAR SOURCE interne
(`LateralMovementThresholds`) :

- **port_scan** : une source contacte au moins `min_ports` ports
  distincts sur au moins `min_hosts` hotes distincts (motif en eventail),
  via des tentatives de connexion SYN sans ACK (RFC 793 -- un scan ne va
  pas au bout du handshake).
- **host_scan** : une source contacte au moins `min_hosts_subnet` adresses
  distinctes d'un MEME sous-reseau /24 (balayage horizontal). Approxime
  la « plage d'IPs consecutives » de l'issue par une densite de contacts
  dans le /24 plutot qu'une stricte contiguite (aucune liste d'adresses
  attribuees n'est disponible depuis une capture passive pour distinguer
  un balayage strictement sequentiel d'un balayage qui saute quelques
  adresses).
- **brute_force** : une source tente des connexions SYN vers au moins
  `min_targets_brute_force` hotes internes DISTINCTS sur un port
  d'administration a distance (`brute_force_ports`, SSH/RDP par defaut)
  -- brute force credential-stuffing typique d'une propagation, par
  opposition a des tentatives repetees vers un seul hote (deja visible
  via `syn_no_synack`/`rst_count`, voir `netcross_core.analysis`).
- **unusual_protocol** : une source utilise un protocole d'administration
  (`admin_fanout_ports`, WinRM/SMB par defaut -- RDP est deja couvert par
  `brute_force_ports`) vers au moins `min_targets_admin_protocol` hotes
  internes distincts. Approxime le critere « poste utilisateur, pas un
  serveur » de l'issue : sans annuaire ni inventaire, aucune capture
  passive ne peut classer fiablement un hote comme poste ou serveur ; le
  fait qu'UNE MEME source administre plusieurs hotes distincts est en
  revanche directement observable et deja un indice de propagation
  (pivot), quel que soit le role habituel de cette source.
- **new_connection** : un couple (source, destination) interne dont le
  premier paquet SYN survient apres le milieu de la capture (a ce point),
  alors qu'un ensemble de reference (`min_baseline_pairs` couples au
  moins) etait deja etabli avant ce milieu -- approxime la « baseline des
  paires normales » de l'issue par une COUPURE TEMPORELLE interne a la
  capture (aucun historique multi-session n'est disponible ici) : sans
  base de reference externe, une capture unique ne peut distinguer un
  couple durablement nouveau d'un couple simplement pas encore observe.
  Signal volontairement le plus faible des cinq (voir severites dans
  `security.findings.lateral_movement_findings`).

Chaque evenement porte un score de confiance 0-1 (poids par signal, voir
les constantes `_SCORE_*` ci-dessous) : un evenement reste un INDICE a
confirmer, jamais une compromission averee -- un balayage d'inventaire
legitime (Nessus, Nmap planifie), une sauvegarde qui contacte de
nombreux hotes, ou un outil d'administration centralise (Ansible,
GPO/WinRM de domaine) produisent les memes signaux. Les seuils par
defaut sont prudents (critere « aucun faux positif sur trafic interne
normal »).

Sortie pure (`detect_lateral_movement`) : `events`
(`list[LateralMovementEvent]`, voir `netcross_core.models`).
`apply_lateral_movement` recopie le resultat dans `Report.
lateral_movement_events` (remplacement, pas ajout), appelee depuis
`netcross_core.analysis.analyse()`. `security.findings` la convertit
ensuite en constats du rapport de securite consolide (CVE-5, #139).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.models import (
    LATERAL_KIND_BRUTE_FORCE,
    LATERAL_KIND_HOST_SCAN,
    LATERAL_KIND_NEW_CONNECTION,
    LATERAL_KIND_PORT_SCAN,
    LATERAL_KIND_UNUSUAL_PROTOCOL,
    LateralMovementEvent,
    Pkt,
    Report,
)

# Nombre maximal de numeros de trame conserves comme preuve par evenement.
_MAX_FRAMES = 10

# Poids du score de confiance (voir la docstring du module).
_SCORE_PORT_SCAN_BASE = 0.4
_SCORE_PORT_SCAN_PER_PORT = 0.02
_SCORE_PORT_SCAN_PER_HOST = 0.05
_SCORE_HOST_SCAN_BASE = 0.4
_SCORE_HOST_SCAN_PER_HOST = 0.01
_SCORE_BRUTE_FORCE_BASE = 0.5
_SCORE_BRUTE_FORCE_PER_TARGET = 0.05
_SCORE_ADMIN_FANOUT_BASE = 0.4
_SCORE_ADMIN_FANOUT_PER_TARGET = 0.05
_SCORE_NEW_CONNECTION = 0.4  # indice le plus faible des cinq, voir la docstring du module


@dataclass(frozen=True)
class LateralMovementThresholds:
    """Seuils des cinq signaux (voir la docstring du module). Tous parametrables."""

    min_ports_port_scan: int = 15
    min_hosts_port_scan: int = 4
    min_hosts_host_scan: int = 20
    brute_force_ports: frozenset[int] = frozenset({22, 3389})
    min_targets_brute_force: int = 3
    admin_fanout_ports: frozenset[int] = frozenset({445, 5985, 5986})
    min_targets_admin_protocol: int = 3
    baseline_fraction: float = 0.5
    min_baseline_pairs: int = 10
    min_baseline_duration_s: float = 60.0


DEFAULT_THRESHOLDS = LateralMovementThresholds()


@dataclass
class LateralMovementResult:
    """Sortie de `detect_lateral_movement`, meme forme que les autres detecteurs de securite."""

    events: list[LateralMovementEvent] = field(default_factory=list)


def _is_internal(address: str) -> bool:
    """Adresse privee (RFC 1918/RFC 4193) hors loopback/multicast/link-local."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback and not ip.is_multicast and not ip.is_link_local


def _is_syn_scan(pk: Pkt) -> bool:
    """Tentative de connexion (SYN sans ACK) : deja au vocabulaire de
    l'issue (« SYN sans ACK = scan »), reutilise aussi pour les hotes
    contactes en brute force/fan-out administratif (une tentative par
    SYN, qu'elle aboutisse ou non)."""
    return pk.proto == "TCP" and bool(pk.flags) and "S" in pk.flags and "A" not in pk.flags


def _subnet24(address: str) -> str:
    return str(ipaddress.ip_network(f"{address}/24", strict=False))


def _frames(frames: Iterable[int | None]) -> tuple[int, ...]:
    return tuple(f for f in frames if f is not None)[:_MAX_FRAMES]


@dataclass
class _SourceState:
    # (dst, dport, ts, frame) pour chaque tentative SYN interne->interne.
    attempts: list[tuple[str, int, float, int | None]] = field(default_factory=list)


def detect_lateral_movement(
    packets: Iterable[Pkt], thresholds: LateralMovementThresholds = DEFAULT_THRESHOLDS
) -> LateralMovementResult:
    """Applique les cinq signaux de la docstring du module a `packets`."""
    t = thresholds
    by_point_src: dict[tuple[str, str], _SourceState] = defaultdict(_SourceState)
    # (point, src, dst) -> (premier ts, premier frame, nombre de paquets) --
    # tout le trafic TCP/UDP interne->interne, pas seulement les SYN, pour
    # le signal new_connection (une connexion existante peut ne plus avoir
    # de SYN visible si la capture demarre en cours de session).
    pairs: dict[tuple[str, str, str], list] = {}
    span_start: dict[str, float] = {}
    span_end: dict[str, float] = {}

    for pk in packets:
        if pk.proto not in ("TCP", "UDP") or pk.sport is None or pk.dport is None:
            continue
        span_start[pk.point] = min(span_start.get(pk.point, pk.ts), pk.ts)
        span_end[pk.point] = max(span_end.get(pk.point, pk.ts), pk.ts)
        if not (_is_internal(pk.src) and _is_internal(pk.dst)) or pk.src == pk.dst:
            continue

        pair_key = (pk.point, pk.src, pk.dst)
        entry = pairs.get(pair_key)
        if entry is None:
            pairs[pair_key] = [pk.ts, pk.frame_number, 1]
        else:
            entry[2] += 1
            if pk.ts < entry[0]:
                entry[0], entry[1] = pk.ts, pk.frame_number

        if _is_syn_scan(pk):
            by_point_src[(pk.point, pk.src)].attempts.append((pk.dst, pk.dport, pk.ts, pk.frame_number))

    result = LateralMovementResult()

    for (point, src), state in sorted(by_point_src.items()):
        attempts = state.attempts
        hosts = sorted({dst for dst, _p, _t, _f in attempts})
        ports = sorted({p for _d, p, _t, _f in attempts})

        if len(ports) >= t.min_ports_port_scan and len(hosts) >= t.min_hosts_port_scan:
            result.events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    kind=LATERAL_KIND_PORT_SCAN,
                    detail=(
                        f"{src} a contacte {len(hosts)} hote(s) interne(s) distinct(s) sur "
                        f"{len(ports)} port(s) distincts (tentatives SYN sans ACK) -- scan de ports probable"
                    ),
                    score=round(
                        min(
                            1.0,
                            _SCORE_PORT_SCAN_BASE
                            + _SCORE_PORT_SCAN_PER_PORT * len(ports)
                            + _SCORE_PORT_SCAN_PER_HOST * len(hosts),
                        ),
                        3,
                    ),
                    frames=_frames(f for _d, _p, _t, f in attempts),
                )
            )

        by_subnet: dict[str, set[str]] = defaultdict(set)
        for dst in hosts:
            by_subnet[_subnet24(dst)].add(dst)
        subnet, subnet_hosts = max(by_subnet.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if subnet is not None and len(subnet_hosts) >= t.min_hosts_host_scan:
            subnet_frames = [f for dst, _p, _t, f in attempts if dst in subnet_hosts]
            result.events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    kind=LATERAL_KIND_HOST_SCAN,
                    detail=(
                        f"{src} a contacte {len(subnet_hosts)} adresse(s) interne(s) distinctes du "
                        f"sous-reseau {subnet} -- scan d'hotes (balayage horizontal) probable"
                    ),
                    score=round(min(1.0, _SCORE_HOST_SCAN_BASE + _SCORE_HOST_SCAN_PER_HOST * len(subnet_hosts)), 3),
                    frames=_frames(subnet_frames),
                )
            )

        by_port: dict[int, set[str]] = defaultdict(set)
        for dst, port, _t, _f in attempts:
            by_port[port].add(dst)
        for port in sorted(t.brute_force_ports):
            targets = by_port.get(port, set())
            if len(targets) >= t.min_targets_brute_force:
                port_frames = [f for dst, p, _t, f in attempts if p == port and dst in targets]
                result.events.append(
                    LateralMovementEvent(
                        point=point,
                        source=src,
                        kind=LATERAL_KIND_BRUTE_FORCE,
                        detail=(
                            f"{src} a tente des connexions sur le port {port} vers {len(targets)} "
                            f"hote(s) interne(s) distinct(s) -- brute force SSH/RDP probable"
                        ),
                        score=round(
                            min(1.0, _SCORE_BRUTE_FORCE_BASE + _SCORE_BRUTE_FORCE_PER_TARGET * len(targets)), 3
                        ),
                        frames=_frames(port_frames),
                    )
                )

        admin_targets: set[str] = set()
        admin_ports_hit: set[int] = set()
        admin_frames: list[int | None] = []
        for dst, port, _t, f in attempts:
            if port in t.admin_fanout_ports:
                admin_targets.add(dst)
                admin_ports_hit.add(port)
                admin_frames.append(f)
        if len(admin_targets) >= t.min_targets_admin_protocol:
            result.events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    kind=LATERAL_KIND_UNUSUAL_PROTOCOL,
                    detail=(
                        f"{src} utilise un protocole d'administration (port(s) "
                        f"{', '.join(str(p) for p in sorted(admin_ports_hit))}) vers {len(admin_targets)} "
                        f"hote(s) interne(s) distinct(s) -- pivot/administration inhabituelle probable"
                    ),
                    score=round(
                        min(1.0, _SCORE_ADMIN_FANOUT_BASE + _SCORE_ADMIN_FANOUT_PER_TARGET * len(admin_targets)), 3
                    ),
                    frames=_frames(admin_frames),
                )
            )

    # -- new_connection : baseline temporelle par point --
    pairs_by_point: dict[str, list[tuple[str, str, list]]] = defaultdict(list)
    for (point, src, dst), entry in pairs.items():
        pairs_by_point[point].append((src, dst, entry))

    for point, point_pairs in sorted(pairs_by_point.items()):
        duration = span_end.get(point, 0.0) - span_start.get(point, 0.0)
        if len(point_pairs) < t.min_baseline_pairs or duration < t.min_baseline_duration_s:
            continue
        midpoint = span_start[point] + duration * t.baseline_fraction
        baseline = [p for p in point_pairs if p[2][0] <= midpoint]
        if len(baseline) < t.min_baseline_pairs:
            continue
        for src, dst, entry in sorted(point_pairs):
            first_ts, first_frame, _count = entry
            if first_ts <= midpoint:
                continue
            elapsed = first_ts - span_start[point]
            result.events.append(
                LateralMovementEvent(
                    point=point,
                    source=src,
                    kind=LATERAL_KIND_NEW_CONNECTION,
                    detail=(
                        f"{src} -> {dst} : nouvelle connexion interne, jamais observee dans les "
                        f"{midpoint - span_start[point]:.0f} premieres secondes de la capture "
                        f"(apparue a {elapsed:.0f}s, {len(baseline)} connexion(s) de reference)"
                    ),
                    score=_SCORE_NEW_CONNECTION,
                    frames=_frames([first_frame]),
                )
            )

    result.events.sort(key=lambda e: (e.point, e.kind, e.source))
    return result


def apply_lateral_movement(
    r: Report, all_packets: Iterable[Pkt], thresholds: LateralMovementThresholds = DEFAULT_THRESHOLDS
) -> None:
    """Calcule la detection et recopie le resultat dans `Report.
    lateral_movement_events` (remplacement, pas ajout : deux appels
    donnent le meme resultat, meme discipline que `apply_expert_
    correlation`)."""
    r.lateral_movement_events = detect_lateral_movement(all_packets, thresholds).events
