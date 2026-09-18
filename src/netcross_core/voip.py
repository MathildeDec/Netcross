"""Call-oriented SIP/RTP correlation primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any, Iterable


@dataclass(frozen=True, order=True)
class SignalingEvent:
    timestamp: float
    kind: str
    details: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class RtpStream:
    stream_id: str
    direction: str | None = None
    start: float | None = None
    end: float | None = None
    packets: int = 0
    lost_packets: int = 0
    jitter_ms: float | None = None
    mos: float | None = None

    @property
    def duration(self) -> float | None:
        if self.start is None or self.end is None:
            return None
        return max(0.0, self.end - self.start)

    @property
    def loss_rate(self) -> float | None:
        total = self.packets + self.lost_packets
        return self.lost_packets / total if total else None


@dataclass
class Call:
    call_id: str
    signaling: list[SignalingEvent] = field(default_factory=list)
    streams: list[RtpStream] = field(default_factory=list)
    participants: tuple[str, ...] = ()
    established_at: float | None = None
    ended_at: float | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration(self) -> float | None:
        if self.established_at is None or self.ended_at is None:
            return None
        return max(0.0, self.ended_at - self.established_at)

    @property
    def quality(self) -> dict[str, float | None]:
        streams = self.streams
        losses = [s.loss_rate for s in streams if s.loss_rate is not None]
        jitters = [s.jitter_ms for s in streams if s.jitter_ms is not None]
        mos = [s.mos for s in streams if s.mos is not None]
        return {
            "loss_rate": mean(losses) if losses else None,
            "jitter_ms": mean(jitters) if jitters else None,
            "mos": mean(mos) if mos else None,
        }

    def timeline(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = [
            {"timestamp": e.timestamp, "kind": e.kind, "details": dict(e.details)}
            for e in self.signaling
        ]
        for stream in self.streams:
            if stream.start is not None:
                items.append({"timestamp": stream.start, "kind": "rtp-start", "stream_id": stream.stream_id})
            if stream.end is not None:
                items.append({"timestamp": stream.end, "kind": "rtp-end", "stream_id": stream.stream_id})
        return sorted(items, key=lambda item: item["timestamp"])


def correlate_call(
    call_id: str,
    signaling: Iterable[SignalingEvent],
    streams: Iterable[RtpStream],
    *,
    participants: Iterable[str] = (),
    events: Iterable[dict[str, Any]] = (),
) -> Call:
    signaling_list = sorted(signaling)
    stream_list = list(streams)
    established = next((e.timestamp for e in signaling_list if e.kind.lower() in {"established", "200_ok", "connected"}), None)
    ended = next((e.timestamp for e in reversed(signaling_list) if e.kind.lower() in {"bye", "ended", "terminated"}), None)
    return Call(
        call_id=call_id,
        signaling=signaling_list,
        streams=stream_list,
        participants=tuple(participants),
        established_at=established,
        ended_at=ended,
        events=list(events),
    )


def quality_distribution(calls: Iterable[Call]) -> dict[str, list[float]]:
    result: dict[str, list[float]] = {"loss_rate": [], "jitter_ms": [], "mos": []}
    for call in calls:
        for key, value in call.quality.items():
            if value is not None:
                result[key].append(value)
    return result
