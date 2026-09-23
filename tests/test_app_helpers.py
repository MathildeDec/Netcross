"""Tests pour netcross_gtk4.app_helpers (issue #285, lot 7).

Valide les fonctions de logique pure extraites de app.py.
Aucune dépendance GTK.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from conftest import make_pkt

from netcross_gtk4.app_helpers import (
    flow_by_key,
    dashboard_events,
    stats_group_value,
    stats_sort_value,
    build_session_objects_for_gui,
    generate_pdf,
    generate_json,
)


class TestFlowByKey:
    def test_found(self):
        f = MagicMock()
        f.key = "flow1"
        assert flow_by_key([f], "flow1") is f

    def test_not_found(self):
        f = MagicMock()
        f.key = "flow1"
        assert flow_by_key([f], "flow2") is None

    def test_empty_flows(self):
        assert flow_by_key([], "key") is None

    def test_none_flows(self):
        assert flow_by_key(None, "key") is None


class TestDashboardEvents:
    def test_merge_all_sources(self):
        findings = ["f1"]
        tls = ["t1"]
        quic = ["q1"]
        expert = ["e1"]
        events = dashboard_events(findings, tls, quic, expert)
        assert events == ["f1", "t1", "q1", "e1"]

    def test_none_sources(self):
        events = dashboard_events(None, None, None, None)
        assert events == []

    def test_partial_none(self):
        events = dashboard_events(["f1"], None, ["q1"], None)
        assert events == ["f1", "q1"]

    def test_does_not_mutate_input(self):
        findings = ["f1"]
        dashboard_events(findings, ["t1"], None, None)
        assert findings == ["f1"]


class TestStatsGroupValue:
    def test_valid_index(self):
        # group_options() returns a list of tuples; we just check the dispatch
        result = stats_group_value(0)
        assert isinstance(result, str)

    def test_negative_index(self):
        assert stats_group_value(-1) == "endpoint"

    def test_out_of_range(self):
        assert stats_group_value(999) == "endpoint"


class TestStatsSortValue:
    def test_valid_index(self):
        result = stats_sort_value(0)
        assert isinstance(result, str)

    def test_negative_index(self):
        assert stats_sort_value(-1) == "bytes"

    def test_out_of_range(self):
        assert stats_sort_value(999) == "bytes"


class TestBuildSessionObjectsForGui:
    def test_with_existing_findings(self):
        """build_session_objects_for_gui ne recalcule pas les findings si fournis."""
        mock_report = MagicMock()
        mock_findings = ["finding1"]
        with patch("netcross_report.build_session_objects") as mock_build:
            mock_build.return_value = MagicMock()
            build_session_objects_for_gui(
                mock_report, mock_findings, [], []
            )
            mock_build.assert_called_once_with(
                mock_report, mock_findings, flows=[], wireshark_expert_events=[]
            )

    def test_recalculates_findings_when_none(self):
        """findings=None → build_findings est appelé."""
        mock_report = MagicMock()
        with patch("netcross_report.build_findings") as mock_build_f:
            mock_build_f.return_value = ["recalculated"]
            with patch("netcross_report.build_session_objects") as mock_build:
                mock_build.return_value = MagicMock()
                build_session_objects_for_gui(
                    mock_report, None, [], []
                )
                mock_build_f.assert_called_once_with(mock_report)
                mock_build.assert_called_once_with(
                    mock_report, ["recalculated"], flows=[], wireshark_expert_events=[]
                )


class TestGeneratePdf:
    def test_single_mode_calls_generate_pdf(self):
        with patch("netcross_report.generate_pdf") as mock_gen:
            mock_gen.__bool__ = lambda self: True  # not None
            generate_pdf(
                mode="single", path="/tmp/test.pdf",
                report=MagicMock(), findings=[], session_objects=MagicMock(),
            )
            mock_gen.assert_called_once()

    def test_diff_mode_calls_generate_diff_pdf(self):
        with patch("netcross_report.generate_diff_pdf") as mock_gen:
            mock_gen.__bool__ = lambda self: True
            generate_pdf(
                mode="diff", path="/tmp/test.pdf",
                diff_findings=[], baseline_report=MagicMock(),
                current_report=MagicMock(),
            )
            mock_gen.assert_called_once()


class TestGenerateJson:
    def test_single_mode_calls_generate_json_report(self):
        mock_session = MagicMock()
        mock_session.json_kwargs.return_value = {"key": "value"}
        with patch("netcross_report.generate_json_report") as mock_gen:
            generate_json(
                mode="single", path="/tmp/test.json",
                report=MagicMock(), session_objects=mock_session,
            )
            mock_gen.assert_called_once()

    def test_diff_mode_calls_generate_json_diff(self):
        with patch("netcross_report.generate_json_diff") as mock_gen:
            generate_json(
                mode="diff", path="/tmp/test.json",
                diff_findings=[], baseline_report=MagicMock(),
                current_report=MagicMock(),
            )
            mock_gen.assert_called_once()
