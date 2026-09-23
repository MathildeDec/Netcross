"""Tests du module netcross_gtk4.analysis_runner (issue #246).

Verifie que l'orchestration du pipeline d'analyse extraite de app.py
fonctionne correctement sans GTK4.
"""
from __future__ import annotations

import pytest

from netcross_gtk4.analysis_runner import (
    AnalysisConfig,
    DiffConfig,
    AnalysisResult,
    DiffResult,
    run_analysis,
    run_diff,
    merge_dashboard_events,
    find_flow_by_key,
)
from tests.conftest import make_pkt


def _sample_packets():
    """Paquets TCP simples pour les tests."""
    return [
        make_pkt(proto="TCP", point="A", ts=1.0, src="10.0.0.1", dst="10.0.0.2", sport=50000, dport=80),
        make_pkt(proto="TCP", point="A", ts=1.1, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=50000),
    ]


def test_analysis_config_defaults():
    """AnalysisConfig a les bonnes valeurs par defaut."""
    c = AnalysisConfig()
    assert c.bucket_ms == 100.0
    assert c.rtp_rate == 8
    assert c.nat_tolerant is True
    assert c.parallel is False
    assert c.auto_topology is True
    assert c.triage is False
    assert c.tls is False
    assert c.quic is False
    assert c.redact is False
    assert c.topn == 20
    assert c.detect_duplicates is False
    assert c.exclude_duplicates is False
    assert c.duplicate_threshold_ms == 2.0


def test_diff_config_defaults():
    """DiffConfig a les bonnes valeurs par defaut."""
    c = DiffConfig()
    assert c.bucket_ms == 100.0
    assert c.rtp_rate == 8
    assert c.nat_tolerant is True
    assert c.parallel is False
    assert c.auto_topology is True
    assert c.loss_min_pp == 1.0
    assert c.latency_min_ms == 5.0
    assert c.redact is False
    assert c.tls is False
    assert c.quic is False


def test_analysis_result_defaults():
    """AnalysisResult a les bonnes valeurs par defaut."""
    r = AnalysisResult()
    assert r.report is None
    assert r.flows == []
    assert r.findings is None
    assert r.tls_findings is None
    assert r.quic_findings is None
    assert r.wireshark_expert_events == []
    assert r.result_text == ""
    assert r.duplicate_indicator == ""
    assert r.mode == "single"


def test_diff_result_defaults():
    """DiffResult a les bonnes valeurs par defaut."""
    r = DiffResult()
    assert r.findings is None
    assert r.baseline_report is None
    assert r.current_report is None
    assert r.tls_findings_baseline is None
    assert r.tls_findings_current is None
    assert r.quic_findings_baseline is None
    assert r.quic_findings_current is None
    assert r.result_text == ""
    assert r.mode == "diff"


def test_run_analysis_simple():
    """run_analysis() execute le pipeline complet en mode single."""
    packets = _sample_packets()
    config = AnalysisConfig()
    result = run_analysis([("A", "fake.pcap")], packets, config)

    assert result.report is not None
    assert len(result.flows) > 0
    assert result.result_text != ""
    assert result.mode == "single"
    assert result.wireshark_expert_events is not None


def test_run_analysis_with_triage():
    """run_analysis() avec triage=True produit des findings."""
    packets = _sample_packets()
    config = AnalysisConfig(triage=True)
    result = run_analysis([("A", "fake.pcap")], packets, config)

    assert result.findings is not None
    assert "TRIAGE" in result.result_text


def test_run_analysis_with_detect_duplicates():
    """run_analysis() avec detect_duplicates=True produit un indicateur."""
    packets = _sample_packets()
    config = AnalysisConfig(detect_duplicates=True)
    result = run_analysis([("A", "fake.pcap")], packets, config)

    assert result.duplicate_indicator != ""


def test_run_analysis_auto_topology_false():
    """run_analysis() avec auto_topology=False utilise points_order explicite."""
    packets = _sample_packets()
    config = AnalysisConfig(auto_topology=False)
    result = run_analysis([("A", "fake.pcap")], packets, config)

    assert result.report is not None


def test_merge_dashboard_events():
    """merge_dashboard_events() fusionne correctement les listes."""
    findings = [{"id": 1}]
    tls = [{"id": 2}]
    quic = [{"id": 3}]
    expert = [{"id": 4}]

    events = merge_dashboard_events(findings, tls, quic, expert)
    assert len(events) == 4
    assert events[0]["id"] == 1
    assert events[1]["id"] == 2
    assert events[2]["id"] == 3
    assert events[3]["id"] == 4


def test_merge_dashboard_events_with_none():
    """merge_dashboard_events() gere les listes None."""
    events = merge_dashboard_events(None, None, None, None)
    assert events == []


def test_merge_dashboard_events_partial():
    """merge_dashboard_events() gere les listes partielles."""
    events = merge_dashboard_events([1], None, [3], None)
    assert events == [1, 3]


def test_find_flow_by_key_found():
    """find_flow_by_key() trouve un flux par sa cle."""
    class FakeFlow:
        def __init__(self, key):
            self.key = key

    flows = [FakeFlow("a->b:80"), FakeFlow("c->d:443")]
    assert find_flow_by_key(flows, "c->d:443") is flows[1]


def test_find_flow_by_key_not_found():
    """find_flow_by_key() retourne None si la cle n'existe pas."""
    class FakeFlow:
        def __init__(self, key):
            self.key = key

    flows = [FakeFlow("a->b:80")]
    assert find_flow_by_key(flows, "inexistant") is None


def test_find_flow_by_key_empty():
    """find_flow_by_key() retourne None pour une liste vide."""
    assert find_flow_by_key([], "key") is None


def test_find_flow_by_key_none():
    """find_flow_by_key() retourne None pour flows=None."""
    assert find_flow_by_key(None, "key") is None


def test_run_analysis_redact():
    """run_analysis() avec redact=True anonymise les adresses."""
    packets = _sample_packets()
    config = AnalysisConfig(redact=True)
    result = run_analysis([("A", "fake.pcap")], packets, config)

    assert result.report is not None


def test_analysis_config_custom():
    """AnalysisConfig accepte des valeurs personnalisees."""
    c = AnalysisConfig(
        bucket_ms=50.0,
        rtp_rate=16,
        nat_tolerant=False,
        parallel=True,
        auto_topology=False,
        triage=True,
        triage_topn=10,
        tls=True,
        quic=True,
        redact=True,
        topn=50,
        detect_duplicates=True,
        exclude_duplicates=True,
        duplicate_threshold_ms=5.0,
    )
    assert c.bucket_ms == 50.0
    assert c.rtp_rate == 16
    assert c.nat_tolerant is False
    assert c.parallel is True
    assert c.auto_topology is False
    assert c.triage is True
    assert c.triage_topn == 10
    assert c.tls is True
    assert c.quic is True
    assert c.redact is True
    assert c.topn == 50
    assert c.detect_duplicates is True
    assert c.exclude_duplicates is True
    assert c.duplicate_threshold_ms == 5.0
