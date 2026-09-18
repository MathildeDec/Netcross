"""netcross_report -- synthese, triage, et generation de rapports (PDF,
JSON) a partir d'un Report netcross_core.

synthesis, triage et json_report sont du pur Python (aucune dependance
externe) : toujours disponibles. generate_pdf a besoin de reportlab/
matplotlib/networkx -- si ces paquets ne sont pas installes, generate_pdf
vaut None plutot que de faire planter l'import de tout le package (un
appelant qui ne veut que le triage ou le JSON n'a pas a installer
reportlab)."""

from netcross_report.expert_events import build_diagnoses, build_expert_events
from netcross_report.history import HistoryEntry, list_history, print_history, record_diff_run, record_run
from netcross_report.json_report import generate_json_diff, generate_json_report
from netcross_report.synthesis import Finding, build_findings
from netcross_report.triage import (
    DEFAULT_SEVERITY_WEIGHTS,
    HEALTH_LABELS,
    SegmentScore,
    format_health_line,
    health_label,
    health_score,
    print_triage,
    rank_segments,
)

try:
    from netcross_report.pdf import generate_diff_pdf, generate_pdf
except ImportError:
    generate_pdf = None
    generate_diff_pdf = None

__all__ = [
    "DEFAULT_SEVERITY_WEIGHTS",
    "HEALTH_LABELS",
    "Finding",
    "HistoryEntry",
    "SegmentScore",
    "build_diagnoses",
    "build_expert_events",
    "build_findings",
    "format_health_line",
    "generate_diff_pdf",
    "generate_json_diff",
    "generate_json_report",
    "generate_pdf",
    "health_label",
    "health_score",
    "list_history",
    "print_history",
    "print_triage",
    "rank_segments",
    "record_diff_run",
    "record_run",
]
