"""
netcross_core.security.exfiltration -- issue #148 (SCENARIO-2, parent #141) :
detection d'exfiltration de données (transferts sortants anormaux).

Detecte les transferts volumineux vers l'exterieur qui pourraient indiquer
une exfiltration de donnees. Exploite les champs deja disponibles sur `Pkt`
(`src`, `dst`, `length`, `ts`, `proto`, `dport`) : aucune nouvelle dissection.

Signaux calcules PAR FLUX (paire source->destination) puis PAR POINT :

Signaux FORTS (suffisent seuls a lever une suspicion) :
- **high_volume** : volume total par flux > seuil (defaut 10 Mo)
- **asymmetric_ratio** : ratio upload/download > seuil (defaut 10:1)

Signaux FAIBLES (aggravent une suspicion deja levee) :
- **off_hours** : transfert en dehors des heures ouvrables (configurable)
- **new_destination** : destination non vue dans la baseline
- **unusual_protocol_volume** : gros volume sur protocole inhabituel
  (DNS, ICMP, HTTP POST)

Leve limites assumees :
- Une destination "nouvelle" est relative a la baseline fournie par
  l'appelant (liste d'IPs connues). Sans baseline, ce signal n'est
  jamais emis.
- Les "heures ouvrables" sont definies par `business_hours` (start, end)
  en UTC, par defaut 8h-18h.
- Le volume est mesure en octets de paquets (payload + headers), pas en
  payload utile uniquement -- approximation conservatrice.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netcross_core.models import Pkt

# -- Constantes ---------------------------------------------------------------

SIGNAL_HIGH_VOLUME = "high_volume"
SIGNAL_ASYMMETRIC_RATIO = "asymmetric_ratio"
SIGNAL_OFF_HOURS = "off_hours"
SIGNAL_NEW_DESTINATION = "new_destination"
SIGNAL_UNUSUAL_PROTOCOL = "unusual_protocol_volume"

STRONG_SIGNALS = (SIGNAL_HIGH_VOLUME, SIGNAL_ASYMMETRIC_RATIO)
WEAK_SIGNALS = (SIGNAL_OFF_HOURS, SIGNAL_NEW_DESTINATION, SIGNAL_UNUSUAL_PROTOCOL)

# Protocoles inhabituels pour un gros volume sortant.
_UNUSUAL_VOLUME_PROTOCOLS = {"DNS", "ICMP", "ICMPv6"}

# Ports HTTP/HTTPS consideres comme cloud storage (approximation).
_CLOUD_STORAGE_PORTS = {443, 80}

_MAX_FRAMES = 10


@dataclass(frozen=True)
class ExfiltrationThresholds:
    """Seuils des signaux (voir la docstring du module). Tous parametrables."""

    min_volume_bytes: int = 10_000_000  # 10 Mo
    min_asymmetric_ratio: float = 10.0  # 10:1 upload/download
    business_hours_start: int = 8  # 8h UTC
    business_hours_end: int = 18  # 18h UTC
    min_packets_for_volume: int = 5  # minimum pour lever high_volume
    min_bytes_for_protocol: int = 1_000_000  # 1 Mo sur protocole inhabituel


DEFAULT_THRESHOLDS = ExfiltrationThresholds()


@dataclass
class ExfiltrationAlert:
    """Une suspicion d'exfiltration sur un flux."""

    src: str
    dst: str
    signals: list[str] = field(default_factory=list)
    volume_bytes: int = 0
    upload_bytes: int = 0
    download_bytes: int = 0
    ratio: float = 0.0
    protocols: set[str] = field(default_factory=set)
    frames: list[int | None] = field(default_factory=list)

    @property
    def is_strong(self) -> bool:
        return any(s in STRONG_SIGNALS for s in self.signals)

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "signals": list(self.signals),
            "volume_bytes": self.volume_bytes,
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            "ratio": round(self.ratio, 2),
            "protocols": sorted(self.protocols),
            "frames": self.frames[:_MAX_FRAMES],
            "strong": self.is_strong,
        }


@dataclass
class ExfiltrationResult:
    """Sortie de `detect_exfiltration`, meme forme que les autres detecteurs."""

    alerts: list[dict] = field(default_factory=list)
    flow_stats: list[dict] = field(default_factory=list)


def _is_off_hours(ts: float, thresholds: ExfiltrationThresholds) -> bool:
    """Verifie si le timestamp tombe hors des heures ouvrables (UTC)."""
    hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
    return hour < thresholds.business_hours_start or hour >= thresholds.business_hours_end


def detect_exfiltration(
    packets: Iterable[Pkt],
    thresholds: ExfiltrationThresholds = DEFAULT_THRESHOLDS,
    known_destinations: frozenset[str] | None = None,
) -> ExfiltrationResult:
    """
    Detecte les transferts sortants anormaux pouvant indiquer une
    exfiltration de donnees.

    `known_destinations` : ensemble d'IPs de destinations connues
    (baseline). Si fourni, les destinations non listees declenchent le
    signal faible `new_destination`.
    """
    # Regrouper par flux (src, dst)
    flow_data: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "upload_bytes": 0,
            "download_bytes": 0,
            "protocols": set(),
            "frames": [],
            "timestamps": [],
            "proto_bytes": defaultdict(int),
        }
    )

    for pk in packets:
        key = (pk.src, pk.dst)
        data = flow_data[key]
        data["upload_bytes"] += pk.length
        data["protocols"].add(pk.proto)
        data["frames"].append(pk.frame_number)
        data["timestamps"].append(pk.ts)
        data["proto_bytes"][pk.proto] += pk.length

        # Download : paquets dans l'autre sens
        rev_key = (pk.dst, pk.src)
        if rev_key in flow_data:
            flow_data[rev_key]["download_bytes"] += pk.length

    # Recalculer download pour tous les flux
    for key, data in flow_data.items():
        rev_key = (key[1], key[0])
        if rev_key in flow_data:
            data["download_bytes"] = flow_data[rev_key]["upload_bytes"]

    alerts: list[ExfiltrationAlert] = []

    for (src, dst), data in flow_data.items():
        upload = data["upload_bytes"]
        download = data["download_bytes"]
        volume = upload + download
        ratio = upload / download if download > 0 else float("inf") if upload > 0 else 0.0
        packet_count = len(data["frames"])

        alert = ExfiltrationAlert(
            src=src,
            dst=dst,
            volume_bytes=volume,
            upload_bytes=upload,
            download_bytes=download,
            ratio=ratio,
            protocols=data["protocols"],
        )

        # -- Signaux forts --
        if volume > thresholds.min_volume_bytes and packet_count >= thresholds.min_packets_for_volume:
            alert.signals.append(SIGNAL_HIGH_VOLUME)

        if download > 0 and ratio > thresholds.min_asymmetric_ratio:
            alert.signals.append(SIGNAL_ASYMMETRIC_RATIO)
        elif download == 0 and upload > thresholds.min_volume_bytes:
            # Upload massif unidirectionnel
            alert.signals.append(SIGNAL_ASYMMETRIC_RATIO)

        # -- Signaux faibles (uniquement si au moins un signal fort) --
        if alert.signals:
            if any(_is_off_hours(ts, thresholds) for ts in data["timestamps"]):
                alert.signals.append(SIGNAL_OFF_HOURS)

            if known_destinations is not None and dst not in known_destinations:
                alert.signals.append(SIGNAL_NEW_DESTINATION)

            for proto, proto_bytes in data["proto_bytes"].items():
                if proto in _UNUSUAL_VOLUME_PROTOCOLS and proto_bytes > thresholds.min_bytes_for_protocol:
                    alert.signals.append(SIGNAL_UNUSUAL_PROTOCOL)
                    break

        if alert.signals:
            alert.frames = data["frames"]
            alerts.append(alert)

    # Stats de flux (pour diagnostic, meme sans alerte)
    flow_stats = []
    for (src, dst), data in flow_data.items():
        upload = data["upload_bytes"]
        download = data["download_bytes"]
        volume = upload + download
        ratio = upload / download if download > 0 else float("inf") if upload > 0 else 0.0
        flow_stats.append(
            {
                "src": src,
                "dst": dst,
                "upload_bytes": upload,
                "download_bytes": download,
                "volume_bytes": volume,
                "ratio": round(ratio, 2),
                "packet_count": len(data["frames"]),
                "protocols": sorted(data["protocols"]),
            }
        )

    return ExfiltrationResult(
        alerts=[a.to_dict() for a in alerts],
        flow_stats=flow_stats,
    )
