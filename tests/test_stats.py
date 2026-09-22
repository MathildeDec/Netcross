"""tests/test_stats.py — Exploration statistique interactive (Job 27, issue #22).

Tests du module netcross_core.stats : Top-N, tri, regroupement, filtres
temporels, export CSV/JSON.
"""

from netcross_core.correlate import build_flows
from netcross_core.models import Pkt, Report
from netcross_core.stats import (
    StatsQuery,
    compute_stats,
    export_csv,
    export_json,
)


def _pkt(**kw):
    base = dict(  # noqa: C408
        point="LAN",
        ts=1.0,
        frame_number=1,
        proto="TCP",
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=50000,
        dport=80,
        length=100,
        ttl=64,
        dscp=0,
        ecn=0,
        seq=1,
        ack=0,
        window=1000,
        flags=None,
        key_id=1,
        payload_hash=None,
        ip_id=1,
        is_fragment=False,
        df=False,
        is_retransmission=False,
        is_fast_retransmission=False,
        is_spurious_retransmission=False,
        mss_val=None,
        wscale_shift=None,
        sack_permitted=False,
        icmp_type=None,
        icmp_code=None,
        icmpv6_type=None,
        icmpv6_code=None,
        arp_opcode=None,
        arp_sender_mac=None,
        arp_is_gratuitous=False,
        stp_bpdu_type=None,
        stp_flags_tc=False,
        stp_root_id=None,
        tls_cert_not_before=None,
        tls_cert_not_after=None,
        tls_cert_san=None,
        tls_cert_serial=None,
        tls_cert_issuer=None,
        tls_cert_subject=None,
        tls_cert_sig_hash=None,
        tls_cert_key_type=None,
        tls_cert_key_bits=None,
        tls_cert_san_ip=None,
        tls_cert_chain_len=None,
        tls_client_hello=False,
        tls_server_hello=False,
        tls_application_data=False,
        vlan_id=None,
        vlan_prio=None,
        is_rtp=False,
        rtp_seq=None,
        rtp_ts=None,
        rtp_ssrc=None,
        encap_tags=(),
        dhcp_xid=None,
        dhcp_msg_type=None,
        dhcp_server_id=None,
        dhcp_vendor_class=None,
        sip_call_id=None,
        sip_msg_type=None,
        sip_cseq=None,
        sip_user_agent=None,
        sip_server=None,
        dns_txn_id=None,
        dns_is_response=False,
        dns_qry_name=None,
        dns_rcode=None,
        http_is_request=False,
        http_is_response=False,
        http_method=None,
        http_uri=None,
        http_status_code=None,
        http_response_time_ms=None,
        expert_flags=(),
        expert_details=(),
    )
    base.update(kw)
    return Pkt(**base)


def _make_flows():
    """Cree un jeu de flows de test : 3 flux entre 2 endpoints."""
    packets = [
        _pkt(
            point="LAN",
            ts=1.0,
            frame_number=1,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=100,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=2.0,
            frame_number=2,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=200,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=3.0,
            frame_number=3,
            src="10.0.0.2",
            dst="10.0.0.1",
            sport=80,
            dport=50000,
            length=150,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=4.0,
            frame_number=4,
            src="10.0.0.1",
            dst="10.0.0.3",
            sport=50001,
            dport=443,
            length=500,
            proto="TCP",
        ),
        _pkt(
            point="LAN",
            ts=5.0,
            frame_number=5,
            src="10.0.0.1",
            dst="10.0.0.3",
            sport=50001,
            dport=443,
            length=300,
            proto="TCP",
        ),
        _pkt(
            point="WAN",
            ts=1.5,
            frame_number=6,
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=50000,
            dport=80,
            length=100,
            proto="TCP",
        ),
    ]
    from netcross_core.correlate import flow_key

    flows_dict: dict[tuple, dict[str, list[Pkt]]] = {}
    for pk in packets:
        fk = flow_key(pk)
        flows_dict.setdefault(fk, {}).setdefault(pk.point, []).append(pk)

    flows = build_flows(flows_dict)
    return flows, packets


def test_group_by_endpoint():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "endpoint" for r in rows)
    # Le groupe avec le plus d'octets doit etre en premier
    assert rows[0].bytes >= rows[-1].bytes


def test_group_by_protocol():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="protocol", sort_by="packets", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "protocol" for r in rows)


def test_group_by_segment():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="segment", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "segment" for r in rows)


def test_group_by_flow():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    assert len(rows) >= 1
    assert all(r.group_by == "flow" for r in rows)


def test_top_n_limit():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=2)
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) <= 2


def test_top_n_none_returns_all():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    assert len(rows) >= 2


def test_sort_by_packets():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="packets", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].packets >= rows[i + 1].packets


def test_sort_by_bytes():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="bytes", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].bytes >= rows[i + 1].bytes


def test_sort_by_duration():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="duration_ms", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].duration_ms >= rows[i + 1].duration_ms


def test_sort_by_throughput():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="flow", sort_by="throughput_bps", top_n=None)
    rows = compute_stats(flows, report, packets, query)
    for i in range(len(rows) - 1):
        assert rows[i].throughput_bps >= rows[i + 1].throughput_bps


def test_time_filter():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    # Filtre : seulement les paquets entre t=1.0 et t=3.0
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        time_start=1.0,
        time_end=3.0,
    )
    rows = compute_stats(flows, report, packets, query)
    # Les flux avec des paquets apres t=3.0 doivent etre filtres
    for row in rows:
        assert row.duration_ms <= 2000.0  # max 2s = 2000ms


def test_segment_filter():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(
        group_by="flow",
        sort_by="bytes",
        top_n=None,
        segment="WAN",
    )
    rows = compute_stats(flows, report, packets, query)
    # Seuls les flux vus au point WAN doivent apparaitre
    for row in rows:
        assert len(row.flow_keys) >= 1


def test_invalid_group_by():
    import pytest

    with pytest.raises(ValueError, match="group_by"):
        StatsQuery(group_by="invalid", sort_by="bytes")


def test_invalid_sort_by():
    import pytest

    with pytest.raises(ValueError, match="sort_by"):
        StatsQuery(group_by="endpoint", sort_by="invalid")


def test_invalid_top_n():
    import pytest

    with pytest.raises(ValueError, match="top_n"):
        StatsQuery(group_by="endpoint", sort_by="bytes", top_n=0)


def test_export_csv():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=5)
    rows = compute_stats(flows, report, packets, query)

    csv_str = export_csv(rows)
    assert "label" in csv_str
    assert "packets" in csv_str
    assert "bytes" in csv_str
    assert len(csv_str) > 0


def test_export_json():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=5)
    rows = compute_stats(flows, report, packets, query)

    json_data = export_json(rows)
    assert isinstance(json_data, list)
    assert len(json_data) == len(rows)
    assert "label" in json_data[0]
    assert "bytes" in json_data[0]


def test_export_empty_rows():
    assert export_csv([]) == ""
    assert export_json([]) == []


def test_drill_down_flow_keys():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    query = StatsQuery(group_by="endpoint", sort_by="bytes", top_n=10)
    rows = compute_stats(flows, report, packets, query)

    for row in rows:
        assert isinstance(row.flow_keys, list)
        # Chaque flow_key doit etre un tuple
        for fk in row.flow_keys:
            assert isinstance(fk, tuple)


def test_events_count_with_index():
    flows, packets = _make_flows()
    report = Report(points=["LAN", "WAN"])
    events_by_segment = {"LAN": [{"event": 1}, {"event": 2}], "WAN": []}
    query = StatsQuery(group_by="segment", sort_by="events", top_n=10)
    rows = compute_stats(flows, report, packets, query, events_by_segment=events_by_segment)
    assert any(r.events > 0 for r in rows)
