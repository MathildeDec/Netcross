"""
netcross_gtk4.analysis_runner -- orchestration du pipeline d'analyse
(issue #246, extraction de app.py).

Cette module contient la logique d'analyse qui etait auparavant
incorporee dans MainWindow._run_analysis_thread et _run_diff_thread.
L'extraction permet de tester l'orchestration sans GTK4.

Le pipeline :
1. Chargement des paquets
2. Detection des doublons inter-captures
3. Anonymisation (redact)
4. Correlation des flux
5. Analyse (pertes, latence, TTL, QoS, fragmentation, etc.)
6. Signaux d'expertise tshark
7. Metadonnees de capture
8. Triage (optionnel)
9. Diagnostic TLS (optionnel)
10. Diagnostic QUIC (optionnel)
11. Mise en forme du rapport texte
"""
from __future__ import annotations

import contextlib
import io
from dataclasses import dataclass, field
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class AnalysisConfig:
    """Parametres d'une analyse simple (mode single)."""
    bucket_ms: float = 100.0
    rtp_rate: int = 8
    nat_tolerant: bool = True
    parallel: bool = False
    auto_topology: bool = True
    triage: bool = False
    triage_topn: int = 5
    tls: bool = False
    quic: bool = False
    redact: bool = False
    topn: int = 20
    detect_duplicates: bool = False
    exclude_duplicates: bool = False
    duplicate_threshold_ms: float = 2.0


@dataclass
class DiffConfig:
    """Parametres d'une analyse differentielle (mode diff)."""
    bucket_ms: float = 100.0
    rtp_rate: int = 8
    nat_tolerant: bool = True
    parallel: bool = False
    auto_topology: bool = True
    loss_min_pp: float = 1.0
    latency_min_ms: float = 5.0
    redact: bool = False
    tls: bool = False
    quic: bool = False


@dataclass
class AnalysisResult:
    """Resultat d'une analyse simple."""
    report: Any = None
    flows: list = field(default_factory=list)
    findings: list | None = None
    tls_findings: list | None = None
    quic_findings: list | None = None
    wireshark_expert_events: list = field(default_factory=list)
    result_text: str = ""
    duplicate_indicator: str = ""
    mode: str = "single"


@dataclass
class DiffResult:
    """Resultat d'une analyse differentielle."""
    findings: Any = None
    baseline_report: Any = None
    current_report: Any = None
    tls_findings_baseline: list | None = None
    tls_findings_current: list | None = None
    quic_findings_baseline: list | None = None
    quic_findings_current: list | None = None
    result_text: str = ""
    mode: str = "diff"


def run_analysis(
    captures: list[tuple[str, str]],
    all_packets: list,
    config: AnalysisConfig,
) -> AnalysisResult:
    """Execute le pipeline d'analyse simple.

    captures : liste de (label, path)
    all_packets : paquets deja charges (via _load_packets)
    config : parametres d'analyse
    """
    from netcross_core import analyse, correlate
    from netcross_core.forensic import detect_cross_capture_duplicates
    from netcross_core.redact import AddressRedactor, redact_packets
    from netcross_core import print_report, read_capture_comments, read_capture_infos
    from netcross_core.wireshark_expert import build_wireshark_expert_events

    result = AnalysisResult()

    # 1. Detection des doublons inter-captures
    duplicate_counts = None
    if config.detect_duplicates:
        duplicate_counts = detect_cross_capture_duplicates(
            all_packets, config.duplicate_threshold_ms
        )
        duplicate_total = sum(duplicate_counts.values())
        result.duplicate_indicator = f"{duplicate_total} paquet(s) dupliqué(s)"

    # 2. Anonymisation
    redactor = None
    if config.redact:
        redactor = redact_packets(all_packets)

    # 3. Correlation des flux
    flows = correlate(
        all_packets,
        config.nat_tolerant,
        200,
        config.exclude_duplicates,
    )
    result.flows = flows

    # 4. Analyse
    points_order = (
        None if config.auto_topology else [label for label, _ in captures]
    )
    report = analyse(
        flows,
        points_order,
        all_packets,
        config.bucket_ms / 1000.0,
        config.nat_tolerant,
        config.rtp_rate,
        config.topn,
        exclude_duplicates=config.exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )
    result.report = report

    # 5. Signaux d'expertise tshark
    result.wireshark_expert_events = build_wireshark_expert_events(all_packets)

    # 6. Metadonnees de capture
    if captures:
        report.capture_comments = read_capture_comments(captures)
        report.capture_infos = read_capture_infos(captures)

    # 7. Mise en forme du rapport texte
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(report)

    # 8. Triage (optionnel)
    if config.triage:
        from netcross_report import (
            build_findings,
            format_health_line,
            health_score,
            print_triage,
            rank_segments,
        )

        result.findings = build_findings(report)
        ranked = rank_segments(result.findings)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("TRIAGE -- PAR OU COMMENCER")
            print("=" * 70)
            print_triage(ranked, config.triage_topn)
            print(format_health_line(health_score(ranked)))

    # 9. Diagnostic TLS (optionnel)
    if config.tls:
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        tls_events = []
        for label, path in captures:
            tls_events.extend(parse_tls_capture(label, path))
        status_by_point = build_handshake_status(tls_events)
        result.tls_findings = diagnose_tls(status_by_point, report.points)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS")
            print("=" * 70)
            print_tls_diagnostics(result.tls_findings)

    # 10. Diagnostic QUIC (optionnel)
    if config.quic:
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )

            quic_events = []
            for label, path in captures:
                quic_events.extend(parse_quic_capture(label, path))
            result.quic_findings = diagnose_quic(quic_events, report.points)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC")
                print("=" * 70)
                print_quic_diagnostics(result.quic_findings)
        except Exception:
            logger.exception("Exception")

    result.result_text = buf.getvalue()
    return result


def run_diff(
    baseline_captures: list[tuple[str, str]],
    current_captures: list[tuple[str, str]],
    baseline_packets: list,
    current_packets: list,
    config: DiffConfig,
) -> DiffResult:
    """Execute le pipeline d'analyse differentielle.

    baseline_captures/current_captures : liste de (label, path)
    baseline_packets/current_packets : paquets deja charges
    config : parametres de diff
    """
    from netcross_core import analyse, correlate
    from netcross_core.redact import AddressRedactor
    from netcross_report.diff_report import diff_reports, print_diff_report

    result = DiffResult()

    redactor = AddressRedactor() if config.redact else None

    # Baseline
    baseline_points_order = (
        None if config.auto_topology else [label for label, _ in baseline_captures]
    )
    if redactor is not None:
        redactor.redact(baseline_packets)
    baseline_flows = correlate(baseline_packets, config.nat_tolerant, 200)
    baseline_report = analyse(
        baseline_flows,
        baseline_points_order,
        baseline_packets,
        config.bucket_ms / 1000.0,
        config.nat_tolerant,
        config.rtp_rate,
    )
    result.baseline_report = baseline_report

    # Courant
    current_points_order = (
        None if config.auto_topology else [label for label, _ in current_captures]
    )
    if redactor is not None:
        redactor.redact(current_packets)
    current_flows = correlate(current_packets, config.nat_tolerant, 200)
    current_report = analyse(
        current_flows,
        current_points_order,
        current_packets,
        config.bucket_ms / 1000.0,
        config.nat_tolerant,
        config.rtp_rate,
    )
    result.current_report = current_report

    # Comparaison
    result.findings = diff_reports(
        baseline_report,
        current_report,
        loss_min_pp=config.loss_min_pp,
        latency_min_ms=config.latency_min_ms,
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_diff_report(result.findings)

    # Diagnostic TLS (optionnel)
    if config.tls:
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        def _tls_findings(captures, points_order):
            events = []
            for label, path in captures:
                events.extend(parse_tls_capture(label, path))
            return diagnose_tls(build_handshake_status(events), points_order)

        result.tls_findings_baseline = _tls_findings(baseline_captures, baseline_points_order)
        result.tls_findings_current = _tls_findings(current_captures, current_points_order)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- BASELINE")
            print("=" * 70)
            print_tls_diagnostics(result.tls_findings_baseline)
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- COURANT")
            print("=" * 70)
            print_tls_diagnostics(result.tls_findings_current)

    # Diagnostic QUIC (optionnel)
    if config.quic:
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )

            def _quic_findings(captures, points_order):
                events = []
                for label, path in captures:
                    events.extend(parse_quic_capture(label, path))
                return diagnose_quic(events, points_order)

            result.quic_findings_baseline = _quic_findings(baseline_captures, baseline_points_order)
            result.quic_findings_current = _quic_findings(current_captures, current_points_order)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC -- BASELINE")
                print("=" * 70)
                print_quic_diagnostics(result.quic_findings_baseline)
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC -- COURANT")
                print("=" * 70)
                print_quic_diagnostics(result.quic_findings_current)
        except Exception:
            logger.exception("Exception")

    result.result_text = buf.getvalue()
    return result


def merge_dashboard_events(
    findings: list | None,
    tls_findings: list | None,
    quic_findings: list | None,
    wireshark_expert_events: list | None,
) -> list:
    """Fusionne les listes d'evenements pour le dashboard.

    Logique auparavant dans MainWindow._dashboard_events().
    """
    events = list(findings or [])
    events.extend(tls_findings or [])
    events.extend(quic_findings or [])
    events.extend(wireshark_expert_events or [])
    return events


def find_flow_by_key(flows: list, key: str):
    """Trouve un flux par sa cle.

    Logique auparavant dans MainWindow._flow_by_key().
    """
    for f in flows or []:
        if f.key == key:
            return f
    return None
