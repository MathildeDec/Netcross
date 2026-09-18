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
from netcross_report.path_metrics import (
    SegmentMetrics,
    build_path_metrics,
    degradation_summary,
    rank_path_segments,
)
from netcross_report.rule_engine import available_rule_ids, evaluate
from netcross_report.session_objects import (
    SessionObjects,
    build_session_objects,
    format_session_objects,
    print_session_objects,
)
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
    "SegmentMetrics",
    "SegmentScore",
    "SessionObjects",
    "available_rule_ids",
    "build_diagnoses",
    "build_expert_events",
    "build_findings",
    "build_path_metrics",
    "build_session_objects",
    "degradation_summary",
    "evaluate",
    "format_health_line",
    "format_session_objects",
    "generate_diff_pdf",
    "generate_json_diff",
    "generate_json_report",
    "generate_pdf",
    "health_label",
    "health_score",
    "list_history",
    "print_history",
    "print_session_objects",
    "print_triage",
    "rank_path_segments",
    "rank_segments",
    "record_diff_run",
    "record_run",
]
