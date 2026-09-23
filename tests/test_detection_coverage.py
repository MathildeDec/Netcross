"""Regression test: every detection/anomaly type must appear in at least one
report render (Issue #329).

Ce test garantit qu'aucune detection n'est "perdue" entre l'analyse et le
rendu. Pour chaque type de detection, on verifie qu'il est reference dans au
moins un module de rapport (JSON, PDF, HTML, SIEM, STIX, texte, etc.).
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Tous les types de detection produits par le moteur d'analyse.
# Chaque entree est (nom_detection, liste_de_modules_attendus).
DETECTION_TYPES = [
    "beaconing",
    "dga",
    "dns_tunnel",
    "exfiltration",
    "fast_flux",
    "flow_stats",
    "port_scan",
    "host_scan",
    "brute_force",
    "lateral_movement",
    "protocol_mismatch",
    "tls_audit",
    "cross_capture_duplicate",
    "sequence_gap",
    "expert_correlation",
    "cpe_match",
    "cve",
    "plugin",
]

# Modules de rapport a verifier
REPORT_MODULES = [
    SRC / "netcross_report" / "json_report.py",
    SRC / "netcross_report" / "pdf.py",
    SRC / "netcross_report" / "security_html.py",
    SRC / "netcross_report" / "security_report.py",
    SRC / "netcross_report" / "siem_export.py",
    SRC / "netcross_report" / "stix_export.py",
    SRC / "netcross_report" / "synthesis.py",
    SRC / "netcross_report" / "expert_events.py",
    SRC / "netcross_report" / "triage.py",
    SRC / "netcross_report" / "charts.py",
    SRC / "netcross_report" / "metric_charts.py",
    SRC / "netcross_report" / "path_metrics.py",
    SRC / "netcross_report" / "session_objects.py",
    SRC / "netcross_report" / "rule_engine.py",
    SRC / "netcross_report" / "sequence_view.py",
    SRC / "netcross_report" / "comm_map.py",
    SRC / "netcross_report" / "history.py",
]

# Modules de detection (producteurs)
DETECTION_MODULES = [
    SRC / "netcross_core" / "security" / "beaconing.py",
    SRC / "netcross_core" / "security" / "dga.py",
    SRC / "netcross_core" / "security" / "dns_tunnel.py",
    SRC / "netcross_core" / "security" / "exfiltration.py",
    SRC / "netcross_core" / "security" / "fast_flux.py",
    SRC / "netcross_core" / "security" / "flow_stats.py",
    SRC / "netcross_core" / "security" / "lateral_movement.py",
    SRC / "netcross_core" / "security" / "protocol_mismatch.py",
    SRC / "netcross_core" / "security" / "tls_audit.py",
    SRC / "netcross_core" / "security" / "findings.py",
    SRC / "netcross_core" / "security" / "cpe_match.py",
    SRC / "netcross_core" / "security" / "cve_db.py",
    SRC / "netcross_core" / "forensic.py",
    SRC / "netcross_core" / "expert_model.py",
    SRC / "netcross_core" / "expert_rules.py",
    SRC / "netcross_core" / "plugins" / "runner.py",
]


def _all_report_text() -> str:
    """Concatene le texte de tous les modules de rapport."""
    parts = []
    for path in REPORT_MODULES:
        if path.exists():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def test_chaque_detection_apparait_dans_au_moins_un_rapport():
    """Chaque type de detection doit etre reference dans au moins un module
    de rapport. On verifie la presence du nom de la detection dans le code
    source des modules de rapport."""
    report_text = _all_report_text()
    missing = []
    for det in DETECTION_TYPES:
        if det.lower() not in report_text.lower():
            missing.append(det)
    assert not missing, (
        f"Les detections suivantes n'apparaissent dans AUCUN module de rapport: {missing}. "
        "Chaque detection doit etre referencee dans au moins un rendu (JSON, PDF, HTML, "
        "SIEM, STIX, texte, etc.)."
    )


def test_chaque_detection_a_un_sigid_siem():
    """Le SIEM export doit avoir un Signature ID pour chaque type de detection."""
    siem_path = SRC / "netcross_report" / "siem_export.py"
    siem_text = siem_path.read_text(encoding="utf-8")
    missing = []
    for det in DETECTION_TYPES:
        if det not in siem_text:
            missing.append(det)
    assert not missing, (
        f"Les detections suivantes n'ont pas de Signature ID dans siem_export.py: {missing}."
    )


def test_modules_detection_existes():
    """Tous les modules de detection declares existent sur disque."""
    missing = [str(p) for p in DETECTION_MODULES if not p.exists()]
    assert not missing, f"Modules de detection manquants: {missing}"


def test_findings_agrège_toutes_les_detections():
    """Le module findings.py doit appeler chaque fonction de detection."""
    findings_path = SRC / "netcross_core" / "security" / "findings.py"
    findings_text = findings_path.read_text(encoding="utf-8")

    expected_imports = [
        "detect_beaconing",
        "detect_dga",
        "detect_dns_tunneling",
        "detect_exfiltration",
        "detect_fast_flux",
        "analyze_flow_stats",
        "detect_lateral_movement",
        "detect_protocol_mismatches",
        "audit_tls_certificates",
    ]
    missing = [name for name in expected_imports if name not in findings_text]
    assert not missing, (
        f"Les fonctions de detection suivantes ne sont pas importees dans findings.py: {missing}"
    )
