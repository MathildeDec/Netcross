"""netcross_gtk4.app_helpers -- fonctions de logique pure extraites de app.py.

Issue #285, lot 7 : ces fonctions ne dépendent ni de GTK ni de GLib et sont
donc testables directement. ``app.py`` les appelle après avoir lu l'état
de ses widgets.

Chaque fonction documente la méthode ``MainWindow`` dont elle est issue.
"""

from __future__ import annotations

from typing import Any, Callable

from netcross_gtk4.stats_view import (
    group_options,
    sort_options,
)


def flow_by_key(flows: list, key: Any) -> Any | None:
    """Recherche un flux par sa clé.

    Extrait de ``MainWindow._flow_by_key``.
    """
    for f in flows or []:
        if f.key == key:
            return f
    return None


def dashboard_events(
    findings: list | None,
    tls_findings: list | None,
    quic_findings: list | None,
    wireshark_expert_events: list | None,
) -> list:
    """Liste fusionnée des événements (findings + TLS/QUIC + signaux tshark).

    Extrait de ``MainWindow._dashboard_events``.
    Même ordre que ``build_dashboard_snapshot``.
    """
    events = list(findings or [])
    events.extend(tls_findings or [])
    events.extend(quic_findings or [])
    events.extend(wireshark_expert_events or [])
    return events


def stats_group_value(selected_idx: int) -> str:
    """Lit la valeur de group_by sélectionnée dans le DropDown.

    Extrait de ``MainWindow._stats_group_value``.
    """
    opts = group_options()
    if 0 <= selected_idx < len(opts):
        return opts[selected_idx][0]
    return "endpoint"


def stats_sort_value(selected_idx: int) -> str:
    """Lit la valeur de sort_by sélectionnée dans le DropDown.

    Extrait de ``MainWindow._stats_sort_value``.
    """
    opts = sort_options()
    if 0 <= selected_idx < len(opts):
        return opts[selected_idx][0]
    return "bytes"


def build_session_objects_for_gui(
    report: Any,
    findings: Any | None,
    flows: list | None,
    wireshark_expert_events: list | None,
) -> Any:
    """Objets enrichis du dernier run single (issue #14).

    Extrait de ``MainWindow._session_objects``.
    """
    from netcross_report import build_findings, build_session_objects

    if findings is None:
        findings = build_findings(report)
    return build_session_objects(
        report,
        findings,
        flows=flows,
        wireshark_expert_events=wireshark_expert_events,
    )


def generate_pdf(
    mode: str,
    path: str,
    report: Any = None,
    findings: Any = None,
    tls_findings: Any = None,
    quic_findings: Any = None,
    session_objects: Any = None,
    diff_findings: Any = None,
    baseline_report: Any = None,
    current_report: Any = None,
    tls_findings_baseline: Any = None,
    tls_findings_current: Any = None,
    quic_findings_baseline: Any = None,
    quic_findings_current: Any = None,
) -> None:
    """Génère le PDF du dernier run, en mode single ou diff.

    Extrait de ``MainWindow._generate_pdf_thread``.
    Lève :class:`ImportError` si reportlab/matplotlib/networkx sont absents.
    """
    if mode == "single":
        from netcross_report import generate_pdf as _generate_pdf

        if _generate_pdf is None:
            raise ImportError(
                "reportlab/matplotlib/networkx requis pour l'export PDF"
            )
        _generate_pdf(
            report,
            path,
            findings=findings,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            session_objects=session_objects,
        )
    else:
        from netcross_report import generate_diff_pdf

        if generate_diff_pdf is None:
            raise ImportError(
                "reportlab/matplotlib/networkx requis pour l'export PDF"
            )
        generate_diff_pdf(
            diff_findings,
            baseline_report,
            current_report,
            path,
            tls_findings_baseline=tls_findings_baseline,
            tls_findings_current=tls_findings_current,
            quic_findings_baseline=quic_findings_baseline,
            quic_findings_current=quic_findings_current,
        )


def generate_json(
    mode: str,
    path: str,
    report: Any = None,
    findings: Any = None,
    tls_findings: Any = None,
    quic_findings: Any = None,
    session_objects: Any = None,
    diff_findings: Any = None,
    baseline_report: Any = None,
    current_report: Any = None,
    tls_findings_baseline: Any = None,
    tls_findings_current: Any = None,
    quic_findings_baseline: Any = None,
    quic_findings_current: Any = None,
) -> None:
    """Génère le JSON du dernier run, en mode single ou diff.

    Extrait de ``MainWindow._generate_json_thread``.
    """
    if mode == "single":
        from netcross_report import generate_json_report

        generate_json_report(
            report,
            path,
            findings=findings,
            tls_findings=tls_findings,
            quic_findings=quic_findings,
            **session_objects.json_kwargs(),
        )
    else:
        from netcross_report import generate_json_diff

        generate_json_diff(
            diff_findings,
            baseline_report,
            current_report,
            path,
            tls_findings_baseline=tls_findings_baseline,
            tls_findings_current=tls_findings_current,
            quic_findings_baseline=quic_findings_baseline,
            quic_findings_current=quic_findings_current,
        )
