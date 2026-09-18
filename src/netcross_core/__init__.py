"""
netcross_core -- moteur d'analyse croisee de captures Wireshark
multi-points, sans dependance a une interface (CLI, GTK4, PDF...).

Utilisation typique :

    from netcross_core import parse_capture, correlate, analyse, print_report

    packets = []
    for label, path in [("LAN", "lan.pcapng"), ("WAN", "wan.pcapng")]:
        packets.extend(parse_capture(label, path))

    flows = correlate(packets)
    report = analyse(flows, points_order=["LAN", "WAN"], all_packets=packets)
    print_report(report)
"""

from netcross_core.analysis import analyse
from netcross_core.baseline_diff import DiffFinding, diff_reports, print_diff_report, write_diff_csv
from netcross_core.client_diff import (
    ClientComparisonResult,
    ClientReport,
    compare_clients,
    print_client_comparison,
    write_client_diff_csv,
)
from netcross_core.compliance import DEFAULT_REFERENCES, evaluate_compliance
from netcross_core.correlate import (
    build_conversations,
    build_flows,
    compute_throughput,
    compute_topn_series,
    correlate,
    flow_key,
)
from netcross_core.models import Pkt, Report
from netcross_core.parsing import (
    compute_mos,
    detect_encapsulation,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    parse_rtp,
    parse_sip,
)
from netcross_core.redact import AddressRedactor, redact_packets, write_redaction_map_csv
from netcross_core.report_text import print_report, write_detail_csv
from netcross_core.voip import Call, build_calls
from netcross_core.wireshark_expert import build_wireshark_expert_events

__all__ = [
    "DEFAULT_REFERENCES",
    "AddressRedactor",
    "ClientComparisonResult",
    "ClientReport",
    "DiffFinding",
    "Pkt",
    "Report",
    "analyse",
    "build_conversations",
    "build_flows",
    "build_wireshark_expert_events",
    "Call",
    "build_calls",
    "compare_clients",
    "compute_mos",
    "compute_throughput",
    "compute_topn_series",
    "correlate",
    "detect_encapsulation",
    "diff_reports",
    "evaluate_compliance",
    "flow_key",
    "parse_capture",
    "parse_captures_parallel",
    "parse_live",
    "parse_rtp",
    "parse_sip",
    "print_client_comparison",
    "print_diff_report",
    "print_report",
    "redact_packets",
    "write_client_diff_csv",
    "write_detail_csv",
    "write_diff_csv",
    "write_redaction_map_csv",
]
