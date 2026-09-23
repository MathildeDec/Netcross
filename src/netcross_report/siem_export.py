"""
netcross_report.siem_export -- export des constats de sécurité au format CEF
(Common Event Format) pour intégration SIEM (issue #170).

CEF est un format texte standardisé utilisé par Splunk, ArcSight, et
d'autres SIEM. Chaque ligne représente un événement :

    CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

Le module lit ``Report.security_findings`` (list[dict] avec clés
``severity``, ``category``, ``detail``, ``point``) et produit une liste
de lignes CEF prêtes à ingérer par un SIEM.

Usage :

    from netcross_report.siem_export import export_cef, write_cef
    from netcross_core.models import Report

    lines = export_cef(report)          # list[str]
    write_cef(report, "output.cef")    # écrit le fichier
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from netcross_core.models import Report


from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
# Constantes CEF
_DEVICE_VENDOR = "Netcross"
_DEVICE_PRODUCT = "Netcross"
_DEVICE_VERSION = "1.0"

# Mapping sévérité Netcross → sévérité CEF (entier 0-10)
_SEVERITY_MAP = {
    "critique": 10,
    "elevee": 8,
    "haute": 8,
    "moyenne": 6,
    "modere": 6,
    "faible": 3,
    "info": 1,
    "informationnel": 1,
}

# Catégories Netcross → Signature ID CEF (arbitraire, stable)
_SIGID_MAP = {
    "exploit": 100,
    "anomalie": 200,
    "dns_tunnel": 201,
    "beaconing": 202,
    "protocol_mismatch": 203,
    "cve": 300,
    "lateral_movement": 204,
    "dga": 205,
    "fast_flux": 206,
}


def _cef_severity(severity: str) -> int:
    """Convertit une sévérité texte en entier CEF (0-10)."""
    return _SEVERITY_MAP.get(severity.lower(), 5)


def _cef_sigid(category: str) -> int:
    """Convertit une catégorie en Signature ID CEF."""
    return _SIGID_MAP.get(category, 999)


def _escape_cef_field(value: str) -> str:
    """Échappe les caractères spéciaux CEF (pipe, backslash)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _format_extension(point: str | None) -> str:
    """Formate la partie extension CEF."""
    ext_parts: list[str] = []
    if point:
        ext_parts.append(f"shost={_escape_cef_field(point)}")
    ext_parts.append(f"rt={int(_dt.datetime.now().timestamp() * 1000)}")
    return " ".join(ext_parts)


def export_cef(report: Report) -> list[str]:
    """Exporte les constats de sécurité d'un Report en lignes CEF.

    Retourne une liste de chaînes, une par constat. Le résultat peut
    être écrit ligne par ligne dans un fichier ``.cef`` ou envoyé
    directement à un SIEM via syslog.
    """
    lines: list[str] = []
    for finding in report.security_findings:
        severity = finding.get("severity", "faible")
        category = finding.get("category", "anomalie")
        detail = finding.get("detail", "")
        point = finding.get("point")

        sigid = _cef_sigid(category)
        cef_sev = _cef_severity(severity)
        name = _escape_cef_field(f"{category}: {detail}"[:255])
        extension = _format_extension(point)

        line = f"CEF:0|{_DEVICE_VENDOR}|{_DEVICE_PRODUCT}|{_DEVICE_VERSION}|{sigid}|{name}|{cef_sev}|{extension}"
        lines.append(line)

    return lines


def write_cef(report: Report, output_path: str | Path) -> str:
    """Écrit les constats de sécurité au format CEF dans un fichier.

    Retourne le chemin absolu du fichier écrit.
    """
    lines = export_cef(report)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return str(path.resolve())
