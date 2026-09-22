"""
Tests de netcross_core.security.exfiltration (issue #148, SCENARIO-2).
Detection d'exfiltration : volume anormal, ratio asymetrique,
heures ouvrables, destination nouvelle, protocole inhabituel.
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.security.exfiltration import (
    SIGNAL_ASYMMETRIC_RATIO,
    SIGNAL_HIGH_VOLUME,
    SIGNAL_NEW_DESTINATION,
    SIGNAL_OFF_HOURS,
    SIGNAL_UNUSUAL_PROTOCOL,
    ExfiltrationThresholds,
    detect_exfiltration,
)

CLIENT = "192.168.1.10"
SERVER = "10.0.0.1"
EXTERNAL = "93.184.216.34"

# Seuil de volume bas pour les tests
_VOL = 100_000  # 100 Ko


def _upload(src, dst, count=100, size=1400, ts_start=43200.0):
    """Paquets src->dst a 12h UTC (heures ouvrables)."""
    return [make_pkt(src=src, dst=dst, length=size, ts=ts_start + i, proto="TCP") for i in range(count)]


def _download(src, dst, count=5, size=100, ts_start=53200.0):
    """Paquets dst->src."""
    return [make_pkt(src=dst, dst=src, length=size, ts=ts_start + i, proto="TCP") for i in range(count)]


def _thresholds(**overrides):
    defaults = {"min_volume_bytes": _VOL, "min_packets_for_volume": 5}
    defaults.update(overrides)
    return ExfiltrationThresholds(**defaults)


# -- Tests: volume eleve ------------------------------------------------------


def test_high_volume_detected():
    """Volume total > seuil -> signal high_volume."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)  # 140 Ko > 100 Ko
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_HIGH_VOLUME in alert["signals"]
    assert alert["volume_bytes"] > _VOL


def test_low_volume_no_alert():
    """Volume faible -> pas d'alerte."""
    pkts = _upload(CLIENT, SERVER, count=3, size=100)  # 300 octets
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    assert result.alerts == []


# -- Tests: ratio asymetrique -------------------------------------------------


def test_asymmetric_ratio_detected():
    """Ratio upload/download > 10:1 -> signal asymmetric_ratio."""
    upload = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    download = _download(CLIENT, EXTERNAL, count=2, size=100)
    result = detect_exfiltration(upload + download, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_ASYMMETRIC_RATIO in alert["signals"]
    assert alert["ratio"] > 10.0


def test_balanced_flow_no_asymmetry():
    """Flux equilibre -> pas de signal asymmetric_ratio."""
    upload = _upload(CLIENT, SERVER, count=10, size=1000)
    download = _download(CLIENT, SERVER, count=10, size=1000)
    # Volume trop faible pour declencher high_volume
    result = detect_exfiltration(upload + download, thresholds=_thresholds(min_volume_bytes=999_999_999))

    asym = [a for a in result.alerts if SIGNAL_ASYMMETRIC_RATIO in a["signals"]]
    assert len(asym) == 0


def test_unidirectional_upload_triggers_asymmetry():
    """Upload massif unidirectionnel (download=0) -> asymmetric_ratio."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_ASYMMETRIC_RATIO in alert["signals"]


# -- Tests: heures ouvrables --------------------------------------------------


def test_off_hours_detected():
    """Transfert nocturne -> signal off_hours."""
    # 2h UTC = 7200 secondes depuis minuit
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=2000, ts=7200.0 + i, proto="TCP") for i in range(100)]
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_OFF_HOURS in alert["signals"]


def test_business_hours_no_off_hours_signal():
    """Transfert a midi -> pas de signal off_hours."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)  # 12h UTC
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_OFF_HOURS not in alert["signals"]


# -- Tests: destination nouvelle ----------------------------------------------


def test_new_destination_detected():
    """Destination non dans baseline -> signal new_destination."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    baseline = frozenset({SERVER})
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=baseline)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION in alert["signals"]


def test_known_destination_no_new_signal():
    """Destination dans baseline -> pas de signal new_destination."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    baseline = frozenset({EXTERNAL})
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=baseline)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION not in alert["signals"]


def test_no_baseline_no_new_signal():
    """Sans baseline -> signal new_destination jamais emis."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=None)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION not in alert["signals"]


# -- Tests: protocole inhabituel ----------------------------------------------


def test_unusual_protocol_dns_volume():
    """Gros volume DNS -> signal unusual_protocol_volume."""
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=500, ts=43200.0 + i, proto="DNS") for i in range(2000)]
    result = detect_exfiltration(pkts, thresholds=_thresholds(min_bytes_for_protocol=100_000))

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_UNUSUAL_PROTOCOL in alert["signals"]


def test_tcp_not_unusual_protocol():
    """TCP n'est pas un protocole inhabituel."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_UNUSUAL_PROTOCOL not in alert["signals"]


# -- Tests: alertes fortes vs faibles -----------------------------------------


def test_strong_alert_flag():
    """Une alerte avec un signal fort a strong=True."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert alert["strong"] is True


def test_weak_only_alert_not_strong():
    """Une alerte avec seulement des signaux faibles a strong=False."""
    # Volume faible mais destination nouvelle + off-hours
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=100, ts=7200.0, proto="TCP")]
    # Seuil volume tres haut pour ne pas declencher high_volume
    # Mais off_hours + new_destination sont des signaux faibles
    # qui ne declenchent pas d'alerte seuls (apres la correction)
    result = detect_exfiltration(
        pkts,
        thresholds=_thresholds(min_volume_bytes=999_999_999, min_packets_for_volume=999),
        known_destinations=frozenset({SERVER}),
    )
    # Pas d'alerte car pas de signal fort
    assert result.alerts == []


# -- Tests: flow_stats --------------------------------------------------------


def test_flow_stats_returned():
    """flow_stats contient tous les flux, meme sans alerte."""
    pkts = _upload(CLIENT, SERVER, count=5, size=100)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    assert len(result.flow_stats) >= 1
    stat = next(s for s in result.flow_stats if s["dst"] == SERVER)
    assert stat["upload_bytes"] == 500
    assert stat["packet_count"] == 5


# -- Tests: vide --------------------------------------------------------------


def test_empty_input():
    """Aucun paquet -> aucun flux, aucune alerte."""
    result = detect_exfiltration([])
    assert result.alerts == []
    assert result.flow_stats == []
