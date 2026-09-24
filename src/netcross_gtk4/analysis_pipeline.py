"""
netcross_gtk4.analysis_pipeline -- pipeline d'analyse extrait de MainWindow
(issue #246, #285 -- lot supplémentaire).

Le thread d'analyse (MainWindow._run_analysis_thread) mélangeait logique
métier (chargement des paquets, corrélation, analyse, diagnostics) et
appels GLib.idle_add pour la mise à jour de l'interface. Ce module porte
toute la logique vérifiable, sans aucune dépendance GTK : le thread de
la fenêtre ne fait que l'appeler avec un callback de progression.

Le pipeline est une fonction pure : mêmes entrées -> mêmes sorties, aucun
effet de bord sur l'interface. Le callback `on_progress` remplace les
GLib.idle_add(self._log, ...) du code original.
"""

from __future__ import annotations

import contextlib
import io
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable

from netcross_core.correlate import correlate
from netcross_core.logging_config import get_logger
from netcross_core.models import Report
from netcross_core.parsing import parse_capture
from netcross_core.report_text import print_report
from netcross_core.wireshark_expert import build_wireshark_expert_events

logger = get_logger(__name__)


@dataclass
class AnalysisOptions:
    """Options du pipeline d'analyse, miroir des checkboxes de la GUI."""

    bucket_ms: float = 1000.0
    rtp_rate: int = 8000
    nat_tolerant: bool = False
    parallel: bool = True
    auto_topology: bool = True
    triage: bool = False
    triage_topn: int = 10
    tls: bool = False
    quic: bool = False
    # Issue #357 : analyse de securite (detecteurs, signatures d'exploit, CVE)
    security: bool = False
    redact: bool = False
    topn: int = 25
    detect_duplicates: bool = False
    exclude_duplicates: bool = False
    duplicate_threshold_ms: float = 2.0


@dataclass
class AnalysisResult:
    """Résultat du pipeline d'analyse, transmis à MainWindow._on_analysis_done."""

    mode: str = "single"
    report: Report | None = None
    flows: list = field(default_factory=list)
    findings: list | None = None
    text: str = ""
    tls_findings: list | None = None
    quic_findings: list | None = None
    wireshark_expert_events: list = field(default_factory=list)


def load_packets(
    captures: Sequence[tuple[str, str]],
    parallel: bool,
    on_progress: Callable[[str], None] | None = None,
) -> list:
    """Charge les paquets depuis une liste de (label, chemin).

    Remplace MainWindow._load_packets : même logique, sans dépendance GTK.
    Supporte le mode parallèle via parse_captures_parallel.
    """
    if parallel:
        from pcap_parser.capture import parse_captures_parallel

        all_packets, per_file_stats = parse_captures_parallel(captures)
        if on_progress:
            for s in per_file_stats:
                if s["error"]:
                    on_progress(f"  [{s['label']}] ECHEC sur {s['path']} : {s['error']}")
                else:
                    on_progress(
                        f"  [{s['label']}] {s['count']} paquets chargés depuis {s['path']} ({s['seconds']:.2f}s)"
                    )
        return all_packets

    sequential: list = []
    for label, path in captures:
        if on_progress:
            on_progress(f"Lecture de {os.path.basename(path)} ({label})...")
        packets = parse_capture(label, path)
        sequential.extend(packets)
        if on_progress:
            on_progress(f"  -> {len(packets)} paquets chargés")
    return sequential


def run_analysis_pipeline(
    captures: Sequence[tuple[str, str]],
    options: AnalysisOptions,
    on_progress: Callable[[str], None] | None = None,
) -> AnalysisResult:
    """Pipeline d'analyse complet, extrait de MainWindow._run_analysis_thread.

    Étapes :
    1. Chargement des paquets
    2. Détection des doublons inter-captures (optionnel)
    3. Anonymisation des adresses (optionnel)
    4. Corrélation des flux
    5. Analyse (pertes, latence, TTL, QoS, etc.)
    6. Signaux d'expertise tshark
    7. Métadonnées de capture (commentaires, infos)
    8. Mise en forme du rapport texte
    9. Triage des segments (optionnel)
    10. Diagnostic TLS (optionnel)
    11. Diagnostic QUIC (optionnel)

    Parameters
    ----------
    captures : liste de (label, chemin)
    options : AnalysisOptions
    on_progress : callback appelé à chaque étape (remplace GLib.idle_add)

    Returns
    -------
    AnalysisResult
    """

    def _log(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    points_order = None if options.auto_topology else [label for label, _ in captures]

    # 1. Chargement
    all_packets = load_packets(captures, options.parallel, on_progress)

    # 2. Doublons
    duplicate_counts = None
    if options.detect_duplicates:
        _log(f"Détection des doublons inter-captures (seuil {options.duplicate_threshold_ms:.1f} ms)...")
        from netcross_core.forensic import detect_cross_capture_duplicates

        duplicate_counts = detect_cross_capture_duplicates(all_packets, options.duplicate_threshold_ms)
        duplicate_total = sum(duplicate_counts.values())
        _log(f"  -> {duplicate_total} paquet(s) dupliqué(s) détecté(s)")

    # 3. Anonymisation
    if options.redact:
        _log("Anonymisation des adresses IP/MAC (--redact)...")
        from netcross_core.redact import redact_packets

        redactor = redact_packets(all_packets)
        _log(f"  -> {len(redactor)} adresse(s) anonymisée(s)")

    # 4. Corrélation
    _log("Correlation des flux entre points de capture...")
    flows = correlate(all_packets, options.nat_tolerant, 200, options.exclude_duplicates)
    _log(f"  -> {len(flows)} flux identifiés")

    # 5. Analyse
    _log("Analyse (pertes, latence, TTL, QoS, fragmentation, débit, TCP, VLAN, RTP, DHCP, SIP...)...")
    from netcross_core.analysis import analyse

    report = analyse(
        flows,
        points_order,
        all_packets,
        options.bucket_ms / 1000.0,
        options.nat_tolerant,
        options.rtp_rate,
        options.topn,
        exclude_duplicates=options.exclude_duplicates,
        duplicate_counts=duplicate_counts,
    )

    # 6. Expertise tshark
    _log("Expertise tshark (signaux bruts)...")
    wireshark_expert_events = build_wireshark_expert_events(all_packets)
    _log(f"  -> {len(wireshark_expert_events)} signal(aux) d'expertise")

    # 7. Métadonnées de capture
    if captures:
        from netcross_core.parsing import read_capture_comments, read_capture_infos

        report.capture_comments = read_capture_comments(captures)
        report.capture_infos = read_capture_infos(captures)

    # 8. Rapport texte
    _log("Mise en forme du rapport...")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        print_report(report)

    # 9. Triage
    findings = None
    if options.triage:
        _log("Triage des segments...")
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
            print("TRIAGE -- PAR OU COMMENCER")
            print("=" * 70)
            print_triage(ranked, options.triage_topn)
            print(format_health_line(health_score(ranked)))

    # 10. TLS
    tls_findings = None
    if options.tls:
        _log("Diagnostic TLS (relecture des captures via tshark)...")
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

    # 11. QUIC
    quic_findings = None
    if options.quic:
        _log("Diagnostic QUIC (relecture des captures via tshark)...")
        try:
            from netcross_core.quic_diagnostics import (
                diagnose_quic,
                parse_quic_capture,
                print_quic_diagnostics,
            )
        except ImportError:
            logger.debug("dépendance optionnelle absente: ImportError")
            with contextlib.redirect_stdout(buf):
                print("\n--quic nécessite cryptography : pip install cryptography")
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

    if options.security:
        # Issue #357 (#385) : analyse de securite, portee depuis
        # MainWindow._run_analysis_thread lors de l'extraction du pipeline.
        _log(
            "Analyse de securite (beaconing, exfiltration, DGA, fast flux, mouvements lateraux, "
            "flow_stats, DNS tunnel, TLS audit, CVE)..."
        )
        from netcross_core.security.findings import apply_security_findings, scan_capture_exploits

        detections = []
        for label, path in captures:
            detections.extend(scan_capture_exploits(label, path))
        apply_security_findings(report, all_packets, detections=detections)
        _log(f"  -> {len(report.security_findings)} constat(s) de securite")
        with contextlib.redirect_stdout(buf):
            print("\n" + "=" * 70)
            print("SECURITE")
            print("=" * 70)
            for f in report.security_findings:
                print(f"  [{f.get('severity', '?')}] ({f.get('category', '?')}) {f.get('detail', '?')}")
            if not report.security_findings:
                print("  Aucun constat de securite.")
            if report.asset_inventory:
                print(f"\n  Inventaire d'actifs : {len(report.asset_inventory)} hote(s)")
            if report.lateral_movement_events:
                print(f"  Mouvements lateraux : {len(report.lateral_movement_events)} evenement(s)")
            if report.dga_alerts:
                print(f"  DGA : {len(report.dga_alerts)} alerte(s)")
            if report.fast_flux_alerts:
                print(f"  Fast flux : {len(report.fast_flux_alerts)} alerte(s)")

    text = buf.getvalue()
    _log("Analyse terminée.")

    return AnalysisResult(
        mode="single",
        report=report,
        flows=flows,
        findings=findings,
        text=text,
        tls_findings=tls_findings,
        quic_findings=quic_findings,
        wireshark_expert_events=wireshark_expert_events,
    )
