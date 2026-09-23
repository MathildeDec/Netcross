"""Tests pour netcross_gtk4.analysis_pipeline (issue #285, lot 6).

Valide l'extraction de l'orchestration analyse/diff hors de app.py.
Aucune dépendance GTK ni GLib : les fonctions prennent un callable ``log``
au lieu d'appeler ``GLib.idle_add``.

Les paquets sont construits synthétiquement via ``make_pkt`` (conftest) et
``parse_capture`` / ``parse_captures_parallel`` sont mockés via monkeypatch
pour retourner ces paquets — même approche que les tests existants.
"""

from __future__ import annotations

import pytest

from conftest import make_pkt

from netcross_gtk4.analysis_pipeline import (
    run_single_analysis,
    run_diff_analysis,
    AnalysisResult,
    DiffResult,
)


def _scenario_pkts():
    """Quatre paquets TCP entre A et B, deux flux minimum."""
    return [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=0.0, length=100, payload_hash="h1"),
        make_pkt(point="B", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=0.05, length=100, payload_hash="h1"),
        make_pkt(point="A", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=1.0, length=100, payload_hash="h2"),
        make_pkt(point="B", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=1.05, length=100, payload_hash="h2"),
    ]


CAPTURES = [("A", "/fake/a.pcap"), ("B", "/fake/b.pcap")]


def test_run_single_analysis_minimal(monkeypatch):
    """Analyse simple sans options : report + flows + texte de rapport."""
    pkts = _scenario_pkts()
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts[:2] if label == "A" else pkts[2:],
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts, []),
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_comments",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_infos",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.build_wireshark_expert_events",
        lambda pkts: [],
    )

    logs: list[str] = []
    result = run_single_analysis(
        captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        triage=False,
        triage_topn=5,
        tls=False,
        quic=False,
        redact=False,
        topn=10,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=1.0,
        log=logs.append,
    )

    assert isinstance(result, AnalysisResult)
    assert result.report is not None
    assert len(result.flows) >= 1
    assert "Analyse" in result.text or "Rapport" in result.text or len(result.text) > 0
    assert result.findings is None
    assert result.tls_findings is None
    assert result.quic_findings is None
    assert result.wireshark_expert_events == []

    # Le log callback a bien reçu des messages
    assert len(logs) > 0
    assert any("Correlation" in msg or "Corrélation" in msg for msg in logs)


def test_run_single_analysis_with_redact(monkeypatch):
    """L'anonymisation --redact ne plante pas et anonymise les adresses."""
    pkts = _scenario_pkts()
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts[:2] if label == "A" else pkts[2:],
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts, []),
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_comments",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_infos",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.build_wireshark_expert_events",
        lambda pkts: [],
    )

    logs: list[str] = []
    result = run_single_analysis(
        captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=True,
        auto_topology=False,
        triage=False,
        triage_topn=5,
        tls=False,
        quic=False,
        redact=True,
        topn=10,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=1.0,
        log=logs.append,
    )

    assert result.report is not None
    assert any("anonymis" in msg.lower() for msg in logs)


def test_run_single_analysis_with_triage(monkeypatch):
    """Le triage produit des findings non-None."""
    pkts = _scenario_pkts()
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts[:2] if label == "A" else pkts[2:],
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts, []),
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_comments",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_infos",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.build_wireshark_expert_events",
        lambda pkts: [],
    )

    result = run_single_analysis(
        captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        triage=True,
        triage_topn=5,
        tls=False,
        quic=False,
        redact=False,
        topn=10,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=1.0,
        log=lambda _msg: None,
    )

    assert result.findings is not None
    assert "TRIAGE" in result.text


def test_run_single_analysis_auto_topology(monkeypatch):
    """auto_topology=True → points_order=None (déduction automatique)."""
    pkts = _scenario_pkts()
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts[:2] if label == "A" else pkts[2:],
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts, []),
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_comments",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.read_capture_infos",
        lambda captures: {},
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.build_wireshark_expert_events",
        lambda pkts: [],
    )

    result = run_single_analysis(
        captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        triage=False,
        triage_topn=5,
        tls=False,
        quic=False,
        redact=False,
        topn=10,
        detect_duplicates=False,
        exclude_duplicates=False,
        duplicate_threshold_ms=1.0,
        log=lambda _msg: None,
    )

    # Le report a été construit avec points_order=None
    assert result.report is not None


def test_run_single_analysis_error_propagates(monkeypatch):
    """Une erreur dans le pipeline remonte au caller (le thread GTK l'attrape)."""
    def _boom(label, path):
        raise RuntimeError("Fichier illisible")

    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture", _boom
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: ([], []),
    )

    with pytest.raises(RuntimeError, match="Fichier illisible"):
        run_single_analysis(
            captures=CAPTURES,
            bucket_ms=100.0,
            rtp_rate=0,
            nat_tolerant=False,
            parallel=False,
            auto_topology=True,
            triage=False,
            triage_topn=5,
            tls=False,
            quic=False,
            redact=False,
            topn=10,
            detect_duplicates=False,
            exclude_duplicates=False,
            duplicate_threshold_ms=1.0,
            log=lambda _msg: None,
        )


def test_run_diff_analysis_minimal(monkeypatch):
    """Comparaison baseline/courant : findings de diff + texte de rapport."""
    pkts_baseline = _scenario_pkts()
    pkts_current = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=0.0, length=100, payload_hash="h1"),
        make_pkt(point="B", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=0.05, length=100, payload_hash="h1"),
        make_pkt(point="A", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=1.0, length=100, payload_hash="h3"),
        make_pkt(point="B", proto="TCP", src="10.0.0.1", dst="10.0.0.2",
                 sport=1234, dport=80, ts=1.05, length=100, payload_hash="h3"),
    ]

    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts_baseline if "baseline" in path else pkts_current,
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts_baseline if len(captures) == 2 else pkts_current, []),
    )

    logs: list[str] = []
    result = run_diff_analysis(
        baseline_captures=CAPTURES,
        current_captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        loss_min_pp=0.0,
        latency_min_ms=0.0,
        redact=False,
        tls=False,
        quic=False,
        log=logs.append,
    )

    assert isinstance(result, DiffResult)
    assert result.findings is not None
    assert result.baseline_report is not None
    assert result.current_report is not None
    assert len(result.text) > 0
    assert any("CHARGEMENT" in msg for msg in logs)


def test_run_diff_analysis_with_redact(monkeypatch):
    """L'anonymisation --redact en mode diff : un seul redactor pour les deux."""
    pkts = _scenario_pkts()
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture",
        lambda label, path: pkts,
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: (pkts, []),
    )

    logs: list[str] = []
    result = run_diff_analysis(
        baseline_captures=CAPTURES,
        current_captures=CAPTURES,
        bucket_ms=100.0,
        rtp_rate=0,
        nat_tolerant=False,
        parallel=False,
        auto_topology=True,
        loss_min_pp=0.0,
        latency_min_ms=0.0,
        redact=True,
        tls=False,
        quic=False,
        log=logs.append,
    )

    assert result.baseline_report is not None
    assert any("anonymis" in msg.lower() for msg in logs)


def test_run_diff_analysis_error_propagates(monkeypatch):
    """Une erreur dans le diff remonte au caller."""
    def _boom(label, path):
        raise RuntimeError("Capture corrompue")

    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_capture", _boom
    )
    monkeypatch.setattr(
        "netcross_gtk4.analysis_pipeline.parse_captures_parallel",
        lambda captures: ([], []),
    )

    with pytest.raises(RuntimeError, match="Capture corrompue"):
        run_diff_analysis(
            baseline_captures=CAPTURES,
            current_captures=CAPTURES,
            bucket_ms=100.0,
            rtp_rate=0,
            nat_tolerant=False,
            parallel=False,
            auto_topology=True,
            loss_min_pp=0.0,
            latency_min_ms=0.0,
            redact=False,
            tls=False,
            quic=False,
            log=lambda _msg: None,
        )
