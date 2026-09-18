from netcross_core.voip import RtpStream, SignalingEvent, correlate_call, quality_distribution


def test_correlates_signaling_and_rtp_into_call():
    call = correlate_call(
        "abc",
        [SignalingEvent(2.0, "200_ok"), SignalingEvent(5.0, "bye"), SignalingEvent(1.0, "invite")],
        [RtpStream("audio-a", "send", 2.2, 4.8, packets=90, lost_packets=10, jitter_ms=4, mos=4.1)],
        participants=["alice", "bob"],
    )
    assert call.established_at == 2.0
    assert call.duration == 3.0
    assert call.participants == ("alice", "bob")
    assert call.quality["loss_rate"] == 0.1


def test_timeline_is_sorted_and_contains_media_boundaries():
    call = correlate_call(
        "abc",
        [SignalingEvent(3.0, "bye"), SignalingEvent(1.0, "invite")],
        [RtpStream("audio", start=1.5, end=2.5)],
    )
    assert [item["kind"] for item in call.timeline()] == ["invite", "rtp-start", "rtp-end", "bye"]


def test_quality_distribution_ignores_missing_metrics():
    calls = [
        correlate_call("a", [], [RtpStream("a", packets=9, lost_packets=1, jitter_ms=2, mos=4)]),
        correlate_call("b", [], [RtpStream("b", packets=10, lost_packets=0, jitter_ms=3)]),
    ]
    distribution = quality_distribution(calls)
    assert distribution["loss_rate"] == [0.1, 0.0]
    assert distribution["jitter_ms"] == [2, 3]
    assert distribution["mos"] == [4]
