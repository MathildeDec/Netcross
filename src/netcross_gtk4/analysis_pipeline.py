"""netcross_gtk4.analysis_pipeline -- extraction de l'orchestration analyse/diff.

Extrait de ``app.py`` (issue #285, lot 6) pour rendre l'orchestration testable
sans dépendance GTK ni boucle d'événements GLib.

Deux fonctions pures :

- :func:`run_single_analysis` : pipeline complet d'une analyse simple
  (lecture, corrélation, analyse, triage, TLS, QUIC, expert tshark, formatage).
- :func:`run_diff_analysis` : pipeline de comparaison baseline/courant.

Chaque fonction prend un ``log`` callable (``Callable[[str], None]``) au lieu
d'appeler ``GLib.idle_add`` directement. Le thread d'arrière-plan dans
``app.py`` passe ``lambda msg: GLib.idle_add(self._log, msg)`` ; les tests
passent une simple liste ou ``print``.

Les valeurs de retour sont des :class:`~netcross_gtk4.run_outcome.RunOutcome`
exactement comme ``app.py`` les construisait -- le thread n'a plus qu'à appeler
``GLib.idle_add(self._appliquer_outcome, outcome)``.
"""

from __future__ import annotations

import contextlib
import io
from typing import Callable, NamedTuple

from netcross_core import (
    AddressRedactor,
    analyse,
    build_wireshark_expert_events,
    correlate,
    parse_capture,
    parse_captures_parallel,
    print_report,
    read_capture_comments,
    read_capture_infos,
    redact_packets,
)
from netcross_core.baseline_diff import diff_reports, print_diff_report
from netcross_core.forensic import detect_cross_capture_duplicates
from netcross_gtk4.run_outcome import analysis_outcome, diff_outcome



from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
class AnalysisResult(NamedTuple):
    """Résultat d'une analyse simple — transmis au thread GTK via idle_add."""

    outcome: object  # RunOutcome
    report: object
    flows: list
    findings: object | None
    text: str
    tls_findings: object | None
    quic_findings: object | None
    wireshark_expert_events: object | None


class DiffResult(NamedTuple):
    """Résultat d'une comparaison baseline/courant — transmis au thread GTK."""

    outcome: object  # RunOutcome
    findings: object
    baseline_report: object
    current_report: object
    text: str
    tls_findings_baseline: object | None
    tls_findings_current: object | None
    quic_findings_baseline: object | None
    quic_findings_current: object | None


def _load_packets(captures, parallel, log: Callable[[str], None]):
    """Lecture séquentielle ou parallèle — équivalent de _load_packets des CLIs."""
    all_packets = []
    if parallel:
        all_packets, per_file_stats = parse_captures_parallel(captures)
        for s in per_file_stats:
            if s["error"]:
                log(f"  [{s['label']}] ECHEC sur {s['path']} : {s['error']}")
            else:
                log(
                    f"  [{s['label']}] {s['count']} paquets chargés "
                    f"depuis {s['path']} ({s['seconds']:.2f}s)"
                )
    else:
        import os

        for label, path in captures:
            log(f"Lecture de {os.path.basename(path)} ({label})...")
            pkts = parse_capture(label, path)
            all_packets.extend(pkts)
            log(f"  -> {len(pkts)} paquets chargés")
    return all_packets


def run_single_analysis(
    captures,
    bucket_ms,
    rtp_rate,
    nat_tolerant,
    parallel,
    auto_topology,
    triage,
    triage_topn,
    tls,
    quic,
    redact,
    topn,
    detect_duplicates,
    exclude_duplicates,
    duplicate_threshold_ms,
    log: Callable[[str], None] = lambda _msg: None,
) -> AnalysisResult:
    """Pipeline complet d'une analyse simple, sans dépendance GTK.

    Reprend exactement la séquence de ``MainWindow._run_analysis_thread`` en
    remplaçant les ``GLib.idle_add(self._log, ...)`` par ``log(...)``.

    Lève :class:`Exception` en cas d'erreur — le thread GTK l'attrape et la
    remonte au journal via ``_on_analysis_error``.
    """
    points_order = None if auto_topology else [label for label, _ in captures]

    all_packets = _load_packets(captures, parallel, log)

    duplicate_counts = None
    if detect_duplicates:
        log(
            f"Détection des doublons inter-captures "
            f"(seuil {duplicate_threshold_ms:.1f} ms)..."
        )
        duplicate_counts = detect_cross_capture_duplicates(
            all_packets, duplicate_threshold_ms
        )
        duplicate_total = sum(duplicate_counts.values())
        log(f"  -> {duplicate_total} paquet(s) dupliqué(s) détecté(s)")

    if redact:
        log("Anonymisation des adresses IP/MAC (--redact)...")
        redactor = redact_packets(all_packets)
        log(f"  -> {len(redactor)} adresse(s) anonymisée(s)")

    log("Corrélation des flux entre points de capture...")
    flows = correlate(all_packets, nat_tolerant, 200, exclude_duplicates)
    log(f"  -> {len(flows)} flux identifiés")

    log(
        "Analyse (pertes, latence, TTL, QoS, fragmentation, débit, "
        "TCP, VLAN, RTP, DHCP, SIP...)..."
    )
    report = analyse(
        flows,
        points_order,
        all_packets,
        bucket_ms / 1000.0,
        nat_tolerant,
        rtp_rate,
        topn,
        exclude_duplicates=exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )

    log("Expertise tshark (signaux bruts)...")
    wireshark_expert_events = build_wireshark_expert_events(all_packets)
    log(f"  -> {len(wireshark_expert_events)} signal(aux) d'expertise")

    if captures:
        report.capture_comments = read_capture_comments(captures)
        report.capture_infos = read_capture_infos(captures)

    log("Mise en forme du rapport...")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(report)

    findings = None
    tls_findings = None
    quic_findings = None

    if triage:
        log("Triage des segments...")
        from netcross_report import (
            build_findings,
            format_health_line,
            health_score,
            print_triage,
            rank_segments,
        )

        findings = build_findings(report)
        ranked = rank_segments(findings)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("TRIAGE -- PAR OÙ COMMENCER")
            print("=" * 70)
            print_triage(ranked, triage_topn)
            print(format_health_line(health_score(ranked)))

    if tls:
        log("Diagnostic TLS (relecture des captures via tshark)...")
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
        tls_findings = diagnose_tls(status_by_point, report.points)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS")
            print("=" * 70)
            print_tls_diagnostics(tls_findings)

    if quic:
        log("Diagnostic QUIC (relecture des captures via tshark)...")
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            with contextlib.redirect_stdout(buf):
                print(
                    "\n--quic nécessite cryptography : "
                    "pip install cryptography --break-system-packages"
                )
        else:
            quic_events = []
            for label, path in captures:
                quic_events.extend(parse_quic_capture(label, path))
            quic_findings = diagnose_quic(quic_events, report.points)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3")
                print("=" * 70)
                print_quic_diagnostics(quic_findings)

    text = buf.getvalue()

    outcome = analysis_outcome(
        "single",
        report,
        flows,
        findings,
        text,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
    )

    return AnalysisResult(
        outcome=outcome,
        report=report,
        flows=flows,
        findings=findings,
        text=text,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
    )


def run_diff_analysis(
    baseline_captures,
    current_captures,
    bucket_ms,
    rtp_rate,
    nat_tolerant,
    parallel,
    auto_topology,
    loss_min_pp,
    latency_min_ms,
    redact,
    tls,
    quic,
    log: Callable[[str], None] = lambda _msg: None,
) -> DiffResult:
    """Pipeline de comparaison baseline/courant, sans dépendance GTK.

    Reprend exactement la séquence de ``MainWindow._run_diff_thread`` en
    remplaçant les ``GLib.idle_add(self._log, ...)`` par ``log(...)``.
    """
    redactor = AddressRedactor() if redact else None
    points_order = (
        None if auto_topology else [label for label, _ in baseline_captures]
    )

    log("=== CHARGEMENT DU BASELINE ===")
    baseline_packets = _load_packets(baseline_captures, parallel, log)
    if redactor is not None:
        redactor.redact(baseline_packets)
    baseline_flows = correlate(baseline_packets, nat_tolerant, 200)
    baseline_report = analyse(
        baseline_flows,
        points_order,
        baseline_packets,
        bucket_ms / 1000.0,
        nat_tolerant,
        rtp_rate,
    )

    points_order_current = (
        None if auto_topology else [label for label, _ in current_captures]
    )

    log("=== CHARGEMENT DU RUN COURANT ===")
    current_packets = _load_packets(current_captures, parallel, log)
    if redactor is not None:
        redactor.redact(current_packets)
        log(
            f"{len(redactor)} adresse(s) anonymisée(s) (IP/MAC) "
            "-- baseline et courant."
        )
    current_flows = correlate(current_packets, nat_tolerant, 200)
    current_report = analyse(
        current_flows,
        points_order_current,
        current_packets,
        bucket_ms / 1000.0,
        nat_tolerant,
        rtp_rate,
    )

    log("Comparaison baseline / courant...")
    findings = diff_reports(
        baseline_report,
        current_report,
        loss_min_pp=loss_min_pp,
        latency_min_ms=latency_min_ms,
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_diff_report(findings)

    tls_findings_baseline = tls_findings_current = None
    quic_findings_baseline = quic_findings_current = None

    if tls:
        log("Diagnostic TLS (relecture des captures via tshark)...")
        from netcross_core.tls_diagnostics import (
            build_handshake_status,
            diagnose_tls,
            parse_tls_capture,
            print_tls_diagnostics,
        )

        def _tls_findings(captures):
            events = []
            for label, path in captures:
                events.extend(parse_tls_capture(label, path))
            return diagnose_tls(build_handshake_status(events), points_order)

        tls_findings_baseline = _tls_findings(baseline_captures)
        tls_findings_current = _tls_findings(current_captures)
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- BASELINE")
            print("=" * 70)
            print_tls_diagnostics(tls_findings_baseline)
            print("\n" + "=" * 70)
            print("DIAGNOSTIC TLS -- COURANT")
            print("=" * 70)
            print_tls_diagnostics(tls_findings_current)

    if quic:
        log("Diagnostic QUIC (relecture des captures via tshark)...")
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            with contextlib.redirect_stdout(buf):
                print(
                    "\n--quic nécessite cryptography : "
                    "pip install cryptography --break-system-packages"
                )
        else:

            def _quic_findings(captures):
                events = []
                for label, path in captures:
                    events.extend(parse_quic_capture(label, path))
                return diagnose_quic(events, points_order)

            quic_findings_baseline = _quic_findings(baseline_captures)
            quic_findings_current = _quic_findings(current_captures)
            with contextlib.redirect_stdout(buf):
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3 -- BASELINE")
                print("=" * 70)
                print_quic_diagnostics(quic_findings_baseline)
                print("\n" + "=" * 70)
                print("DIAGNOSTIC QUIC/HTTP3 -- COURANT")
                print("=" * 70)
                print_quic_diagnostics(quic_findings_current)

    text = buf.getvalue()

    outcome = diff_outcome(
        findings,
        baseline_report,
        current_report,
        text,
        tls_findings_baseline=tls_findings_baseline,
        tls_findings_current=tls_findings_current,
        quic_findings_baseline=quic_findings_baseline,
        quic_findings_current=quic_findings_current,
    )

    return DiffResult(
        outcome=outcome,
        findings=findings,
        baseline_report=baseline_report,
        current_report=current_report,
        text=text,
        tls_findings_baseline=tls_findings_baseline,
        tls_findings_current=tls_findings_current,
        quic_findings_baseline=quic_findings_baseline,
        quic_findings_current=quic_findings_current,
    )
