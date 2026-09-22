"""
netcross_core.security.exfiltration -- issue #148 (SCENARIO-2, parent #141) :
detection d'exfiltration de donnees (transferts sortants anormaux).

Objectif : reperer, PAR FLUX FRONTIERE (une adresse interne, une adresse
externe), un volume de donnees sortant qui pourrait trahir une
exfiltration -- sauvegarde cloud non autorisee, tunnel de fuite de
donnees, transfert vers une destination compromise. Comme dns_tunnel, le
module exploite uniquement les champs deja decodes de `Pkt` (`src`,
`dst`, `sport`, `dport`, `length`, `ts`, `proto`, et les champs
applicatifs DNS/ICMP/HTTP deja presents) : aucune nouvelle dissection
tshark.

Notion de FRONTIERE : une adresse "interne" (RFC 1918, loopback,
link-local -- `ipaddress.ip_address(...).is_private`) qui echange avec
une adresse PUBLIQUE. Un paquet dont les deux adresses sont du meme cote
(deux internes, ou deux publiques) n'apporte aucune information sur une
fuite VERS l'exterieur et est ignore ; de meme pour les adresses
multicast (jamais une destination d'exfiltration ponctuelle) et les
adresses non IP (ARP, STP...). Un flux est identifie par `(point,
adresse interne, adresse externe, port du service externe, protocole)`
-- port et adresse INTERNES volontairement absents de la cle : un client
qui ouvre plusieurs connexions ephemeres vers le meme service externe
(retry, pagination) doit compter comme UN SEUL flux, pas un par
connexion TCP.

Signaux, chacun parametrable (`ExfiltrationThresholds`) :

Signaux FORTS (suffisent seuls a lever une suspicion, comme dans
dns_tunnel) :
- **upload_ratio** : volume interne -> externe au moins `ratio_min` fois
  le volume retour (ou tout volume sortant sans AUCUN retour), a
  condition d'atteindre `ratio_min_bytes` sortants -- un flux minuscule
  et asymetrique (une seule requete UDP sans reponse) ne suffit pas.
- **large_volume** : volume interne -> externe superieur a
  `volume_bytes` (100 Mo par defaut) vers une meme destination.

Signaux FAIBLES (jamais suffisants seuls -- ils aggravent une suspicion
deja levee par un signal fort) :
- **off_hours** : au moins `off_hours_ratio` du volume sortant du flux
  survient dans la plage horaire `[off_hours_start, off_hours_end[`
  (20h-8h UTC par defaut), au-dela de `off_hours_min_bytes` -- limite
  assumee : heure UTC du paquet, pas le fuseau horaire de l'analyste ni
  celui du reseau observe (aucune metadonnee de fuseau dans `Pkt`).
- **new_destination** : l'adresse externe n'appartient pas a
  `known_destinations` (baseline d'IPs deja vues, fournie par l'appelant
  -- None desactive ce signal, jamais de faux positif par defaut faute
  de baseline).
- **dns_large_volume** : flux DNS avec au moins `dns_min_responses`
  reponses de plus de `dns_response_bytes` octets -- approxime "TXT
  volumineux" comme `dns_tunnel.SIGNAL_LARGE_RESPONSE` (`Pkt` ne porte
  pas le type d'enregistrement).
- **icmp_payload** : flux ICMP/ICMPv6 avec au moins `icmp_min_packets`
  paquets de plus de `icmp_payload_bytes` octets -- un ping normal ne
  transporte quasiment aucune charge utile.
- **http_cloud_upload** : au moins une requete HTTP POST sortante dont
  l'URI (forme complete "http://hote/chemin", cf. `Pkt.http_uri`) cible
  un domaine de stockage cloud connu (`_CLOUD_STORAGE_HINTS`) -- liste
  volontairement courte et explicite, jamais une heuristique sur le seul
  chemin.

Score de risque (`risk_score`, 0-100) : somme de poids fixes par signal
declenche (voir `_SIGNAL_WEIGHT`), plafonnee -- indicateur de tri et de
priorisation pour l'analyste, PAS une probabilite calibree.

Comme dns_tunnel/expert_correlation, une suspicion est un INDICE a
confirmer : les seuils par defaut sont prudents (critere « aucun faux
positif sur trafic normal »). Sortie pure (`detect_exfiltration`) :
`suspicions` (un par flux frontiere suspect) et `flow_stats` (volume de
CHAQUE flux frontiere observe, suspect ou non, comme
`dns_tunnel.domain_entropy`). `security.findings` la convertit en
constats du rapport de securite.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.models import Pkt

KIND_FLOW = "flow"

SIGNAL_RATIO = "upload_ratio"
SIGNAL_VOLUME = "large_volume"
SIGNAL_OFF_HOURS = "off_hours"
SIGNAL_NEW_DESTINATION = "new_destination"
SIGNAL_DNS_VOLUME = "dns_large_volume"
SIGNAL_ICMP_PAYLOAD = "icmp_payload"
SIGNAL_HTTP_CLOUD_UPLOAD = "http_cloud_upload"

STRONG_SIGNALS = (SIGNAL_RATIO, SIGNAL_VOLUME)
WEAK_SIGNALS = (
    SIGNAL_OFF_HOURS,
    SIGNAL_NEW_DESTINATION,
    SIGNAL_DNS_VOLUME,
    SIGNAL_ICMP_PAYLOAD,
    SIGNAL_HTTP_CLOUD_UPLOAD,
)

# Poids du score de risque (voir docstring du module) : les signaux forts
# comptent plus que les corroborants, mais jamais 100% pour un seul signal
# fort isole -- laisse de la place aux corroborants pour distinguer les cas.
_SIGNAL_WEIGHT: dict[str, int] = {
    SIGNAL_RATIO: 40,
    SIGNAL_VOLUME: 35,
    SIGNAL_OFF_HOURS: 10,
    SIGNAL_NEW_DESTINATION: 10,
    SIGNAL_DNS_VOLUME: 15,
    SIGNAL_ICMP_PAYLOAD: 15,
    SIGNAL_HTTP_CLOUD_UPLOAD: 15,
}
_MAX_RISK_SCORE = 100

# Nombre maximal de numeros de trame conserves comme preuve par suspicion.
_MAX_FRAMES = 10

# Domaines de stockage cloud connus, pour le signal http_cloud_upload --
# liste courte et explicite (voir docstring), jamais une heuristique sur
# le chemin seul. Suffixes compares en minuscules sur l'hote de
# `Pkt.http_uri`.
_CLOUD_STORAGE_HINTS = (
    "amazonaws.com",
    "storage.googleapis.com",
    "googleapis.com",
    "blob.core.windows.net",
    "dropboxapi.com",
    "dropbox.com",
    "drive.google.com",
    "backblazeb2.com",
    "wasabisys.com",
    "b2cdn.com",
)


@dataclass(frozen=True)
class ExfiltrationThresholds:
    """Seuils des signaux (voir la docstring du module). Tous parametrables."""

    ratio_min: float = 10.0
    ratio_min_bytes: int = 1_000_000  # 1 Mo : plancher pour ignorer un flux minuscule et asymetrique
    volume_bytes: int = 100 * 1024 * 1024  # 100 Mo
    off_hours_start: int = 20  # heure UTC (incluse) de debut de plage hors heures ouvrees
    off_hours_end: int = 8  # heure UTC (exclue) de fin de plage hors heures ouvrees
    off_hours_ratio: float = 0.5
    off_hours_min_bytes: int = 10 * 1024 * 1024  # 10 Mo
    dns_response_bytes: int = 512
    dns_min_responses: int = 5
    icmp_payload_bytes: int = 200
    icmp_min_packets: int = 20


DEFAULT_THRESHOLDS = ExfiltrationThresholds()


@dataclass
class ExfiltrationResult:
    """Sortie de `detect_exfiltration`, meme forme de dicts que les autres detecteurs de securite."""

    suspicions: list[dict] = field(default_factory=list)
    flow_stats: list[dict] = field(default_factory=list)


def _parse_ip(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """`None` si `addr` n'est pas une adresse IP (ARP/STP...) ou est vide."""
    if not addr:
        return None
    try:
        return ipaddress.ip_address(addr)
    except ValueError:
        return None


def _is_off_hours(ts: float, t: ExfiltrationThresholds) -> bool:
    """Heure UTC de `ts` dans `[off_hours_start, off_hours_end[` (limite assumee, voir docstring)."""
    hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
    if t.off_hours_start <= t.off_hours_end:
        return t.off_hours_start <= hour < t.off_hours_end
    return hour >= t.off_hours_start or hour < t.off_hours_end  # plage a cheval sur minuit (defaut 20h-8h)


def _http_targets_cloud_storage(uri: str | None) -> bool:
    if not uri:
        return False
    host = uri.split("://", 1)[-1].split("/", 1)[0].lower()
    return any(host == hint or host.endswith("." + hint) for hint in _CLOUD_STORAGE_HINTS)


def _is_cloud_post(pk: Pkt) -> bool:
    return pk.http_is_request and (pk.http_method or "").upper() == "POST" and _http_targets_cloud_storage(pk.http_uri)


def _frames(frames: Iterable[int | None]) -> list[int]:
    return [f for f in frames if f is not None][:_MAX_FRAMES]


@dataclass
class _FlowState:
    bytes_out: int = 0
    bytes_in: int = 0
    out_events: list[tuple[float, int, int | None]] = field(default_factory=list)  # (ts, octets, frame)
    dns_large_responses: int = 0
    icmp_large_packets: int = 0
    http_cloud_upload: bool = False


def detect_exfiltration(
    packets: Iterable[Pkt],
    thresholds: ExfiltrationThresholds = DEFAULT_THRESHOLDS,
    known_destinations: frozenset[str] | None = None,
) -> ExfiltrationResult:
    """Applique les signaux de la docstring du module a `packets`.

    `known_destinations` : baseline d'adresses externes deja vues (IPs),
    a fournir par l'appelant (aucune notion d'historique dans ce module
    pur) ; None desactive le signal `new_destination`, jamais de faux
    positif par defaut faute de baseline.
    """
    t = thresholds
    flows: dict[tuple[str, str, str, int | None, str], _FlowState] = defaultdict(_FlowState)

    for pk in packets:
        src_ip, dst_ip = _parse_ip(pk.src), _parse_ip(pk.dst)
        if src_ip is None or dst_ip is None or src_ip.is_multicast or dst_ip.is_multicast:
            continue
        src_private, dst_private = src_ip.is_private, dst_ip.is_private
        if src_private == dst_private:
            continue  # meme cote de la frontiere : rien a dire sur une fuite vers l'exterieur

        if src_private:
            internal, external, ext_port, outbound = pk.src, pk.dst, pk.dport, True
        else:
            internal, external, ext_port, outbound = pk.dst, pk.src, pk.sport, False

        state = flows[(pk.point, internal, external, ext_port, pk.proto)]
        if outbound:
            state.bytes_out += pk.length
            state.out_events.append((pk.ts, pk.length, pk.frame_number))
            if _is_cloud_post(pk):
                state.http_cloud_upload = True
        else:
            state.bytes_in += pk.length

        if pk.dns_txn_id is not None and pk.dns_is_response and pk.length > t.dns_response_bytes:
            state.dns_large_responses += 1
        if pk.proto in ("ICMP", "ICMPv6") and pk.length > t.icmp_payload_bytes:
            state.icmp_large_packets += 1

    result = ExfiltrationResult()
    # `ext_port` est None pour ICMP/ICMPv6 : trie explicitement (None avant tout entier) plutot que de
    # comparer les tuples de cle directement (None et int ne sont pas ordonnables entre eux en Python).
    def _sort_key(item):
        (point, internal, external, ext_port, proto), _state = item
        return (point, internal, external, ext_port is None, ext_port or 0, proto)

    for (point, internal, external, ext_port, proto), state in sorted(flows.items(), key=_sort_key):
        if state.bytes_out + state.bytes_in == 0:
            continue
        ratio = round(state.bytes_out / state.bytes_in, 2) if state.bytes_in > 0 else None
        result.flow_stats.append(
            {
                "point": point,
                "internal": internal,
                "external": external,
                "ext_port": ext_port,
                "proto": proto,
                "bytes_out": state.bytes_out,
                "bytes_in": state.bytes_in,
                "ratio": ratio,
            }
        )

        signals: list[str] = []
        if state.bytes_out >= t.ratio_min_bytes and (ratio is None or ratio > t.ratio_min):
            signals.append(SIGNAL_RATIO)
        if state.bytes_out > t.volume_bytes:
            signals.append(SIGNAL_VOLUME)
        if not signals:
            continue  # aucun signal fort : les signaux faibles seuls ne levent rien

        if state.bytes_out >= t.off_hours_min_bytes:
            off_hours_bytes = sum(n for ts, n, _f in state.out_events if _is_off_hours(ts, t))
            if off_hours_bytes / state.bytes_out >= t.off_hours_ratio:
                signals.append(SIGNAL_OFF_HOURS)
        if known_destinations is not None and external not in known_destinations:
            signals.append(SIGNAL_NEW_DESTINATION)
        if state.dns_large_responses >= t.dns_min_responses:
            signals.append(SIGNAL_DNS_VOLUME)
        if state.icmp_large_packets >= t.icmp_min_packets:
            signals.append(SIGNAL_ICMP_PAYLOAD)
        if state.http_cloud_upload:
            signals.append(SIGNAL_HTTP_CLOUD_UPLOAD)

        weak = [s for s in signals if s in WEAK_SIGNALS]
        risk_score = min(_MAX_RISK_SCORE, sum(_SIGNAL_WEIGHT[s] for s in signals))
        result.suspicions.append(
            {
                "kind": KIND_FLOW,
                "point": point,
                "internal": internal,
                "external": external,
                "ext_port": ext_port,
                "proto": proto,
                "signals": signals,
                "severity": "elevee" if weak else "moyenne",
                "risk_score": risk_score,
                "bytes_out": state.bytes_out,
                "bytes_in": state.bytes_in,
                "ratio": ratio,
                "frames": _frames(f for _ts, _n, f in state.out_events),
            }
        )

    result.suspicions.sort(key=lambda d: (-d["risk_score"], d["point"], d["external"]))
    result.flow_stats.sort(key=lambda d: (-d["bytes_out"], d["point"], d["external"]))
    return result
