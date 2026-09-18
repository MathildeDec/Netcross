import pytest

from netcross_core.analysis import analyse
from netcross_core.models import Pkt


def _pkt(point, ts, **kw):
    d = dict(
        point=point, ts=ts, frame_number=None, proto="UDP",
        src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=5000,
        length=200, ttl=64, dscp=0, ecn=0, seq=None, ack=None,
        window=None, flags=None, key_id=None, payload_hash=None,
        ip_id=None, is_fragment=False, df=False,
        is_retransmission=False, is_fast_retransmission=False,
        is_spurious_retransmission=False, mss_val=None, wscale_shift=None,
        sack_permitted=False, icmp_type=None, icmp_code=None,
        icmpv6_type=None, icmpv6_code=None, arp_opcode=None,
        arp_sender_mac=None, arp_is_gratuitous=False, stp_bpdu_type=None,
        stp_flags_tc=False, stp_root_id=None, tls_cert_not_before=None,
        tls_cert_not_after=None, tls_cert_san=None, tls_cert_serial=None,
        tls_client_hello=False, tls_server_hello=False,
        tls_application_data=False, vlan_id=None, vlan_prio=None,
        is_rtp=False, rtp_seq=None, rtp_ts=None, rtp_ssrc=None,
        encap_tags=(), dhcp_xid=None, dhcp_msg_type=None,
        dhcp_server_id=None, dhcp_vendor_class=None, sip_call_id=None,
        sip_msg_type=None, sip_cseq=None, sip_user_agent=None,
        sip_server=None, dns_txn_id=None, dns_is_response=False,
        dns_qry_name=None, dns_rcode=None, http_is_request=False,
        http_is_response=False, http_method=None, http_uri=None,
        http_status_code=None, http_response_time_ms=None,
        expert_flags=(), expert_details=(),
    )
    d.update(kw)
    return Pkt(**d)


def _sip(point, ts, msg, cseq, call_id="call-1"):
    return _pkt(
        point, ts, proto="UDP", src="10.0.0.10", dst="10.0.0.20",
        sport=5060, dport=5060, sip_call_id=call_id,
        sip_msg_type=msg, sip_cseq=cseq,
    )


def _rtp(point, ts, seq, ssrc=42):
    return _pkt(
        point, ts, src="10.0.0.10", dst="10.0.0.20",
        is_rtp=True, rtp_seq=seq, rtp_ts=seq * 160, rtp_ssrc=ssrc,
    )


def test_voip_call_fusionne_signalisation_et_media():
    packets = [
        _sip("A", 1.000, "INVITE", "1 INVITE"),
        _sip("B", 1.020, "INVITE", "1 INVITE"),
        _sip("A", 1.100, "200 OK", "1 INVITE"),
        _sip("B", 1.120, "200 OK", "1 INVITE"),
        _rtp("A", 1.200, 1),
        _rtp("B", 1.250, 1),
        _rtp("B", 1.270, 2),
        _sip("B", 3.000, "BYE", "2 BYE"),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert len(r.voip_calls) == 1
    call = r.voip_calls[0]
    assert call["call_id"] == "call-1"
    assert call["participants"] == ["10.0.0.10", "10.0.0.20"]
    assert call["setup_duration_ms"] == pytest.approx(100.0)
    assert call["duration_ms"] == 2000.0
    assert len(call["rtp_streams"]) == 1
    assert any(e["type"] == "media" for e in call["events"])


def test_voip_timeline_conserve_echec_sip_et_distribution():
    packets = [
        _sip("A", 10.0, "INVITE", "3 INVITE", "failed"),
        _sip("A", 10.2, "486 Busy Here", "3 INVITE", "failed"),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert r.voip_calls[0]["quality"] == "unknown"
    assert r.voip_calls[0]["events"][-1]["type"] == "failure"
    assert r.voip_quality_distribution == {"unknown": 1}


def test_voip_flux_hors_fenetre_non_associe():
    packets = [
        _sip("A", 1.0, "INVITE", "1 INVITE", "call-a"),
        _sip("A", 1.1, "200 OK", "1 INVITE", "call-a"),
        _rtp("A", 1000.0, 1),
    ]
    r = analyse({}, ["A", "B"], packets)
    assert r.voip_calls[0]["rtp_streams"] == []
