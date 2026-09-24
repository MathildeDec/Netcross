"""Issue #278 : extraction des contenus (audio, video, documents),
analyse qualitative et rappel de l'usage raisonne. Sans tshark : les
datagrammes sont fabriques, tshark --export-objects est simule."""

from __future__ import annotations

import json
import stat
import struct
import sys
import wave
from types import SimpleNamespace

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core.extract.contents import (
    USAGE_REMINDER,
    export_documents,
    format_extraction,
    parse_kinds,
    prepare_out_dir,
    run_extraction,
)
from netcross_core.extract.media import (
    analyse_stream,
    collect_streams,
    decode_g711,
    depacketize_h264,
    export_stream,
    parse_rtp_header,
    parse_sdp,
    verdict,
)

A, B = "10.0.0.1", "10.0.0.2"


def rtp(seq, ts, *, pt=0, ssrc=0x1234, marker=False, payload=b"\xff" * 160, csrc=0, ext=b"", pad=0):
    b0 = 0x80 | csrc | (0x10 if ext else 0) | (0x20 if pad else 0)
    head = struct.pack("!BBHII", b0, (0x80 if marker else 0) | pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    head += b"\x00\x00\x00\x01" * csrc
    if ext:
        head += struct.pack("!HH", 0xBEDE, len(ext) // 4) + ext
    tail = (b"\x00" * (pad - 1) + bytes([pad])) if pad else b""
    return head + payload + tail


def audio_stream(n=50, *, drop=(), pt=0, jitter=None, seq0=100, payload=b"\xff" * 160):
    out = []
    for i in range(n):
        if i in drop:
            continue
        arrival = 1.0 + i * 0.02 + (jitter(i) if jitter else 0.0)
        out.append(("LAN", arrival, A, 40000, B, 50000, rtp(seq0 + i, i * 160, pt=pt, payload=payload)))
    return out


SDP_H264 = (
    b"INVITE sip:b@x SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n"
    b"v=0\r\nc=IN IP4 10.0.0.2\r\nm=audio 50000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    b"m=video 50002 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
)


# -- en-tete RTP / SDP -------------------------------------------------------


def test_en_tete_rtp_csrc_extension_bourrage():
    pt, seq, ts, ssrc, marker, body = parse_rtp_header(
        rtp(7, 99, pt=8, marker=True, payload=b"abc", csrc=2, ext=b"\x01\x02\x03\x04", pad=4)
    )
    assert (pt, seq, ts, ssrc, marker, body) == (8, 7, 99, 0x1234, True, b"abc")


@pytest.mark.parametrize(
    "data",
    [b"\x80\x00", b"\x40" + b"\x00" * 20, bytes([0x80, 200]) + b"\x00" * 30],  # court, v1, RTCP SR
)
def test_pas_du_rtp(data):
    assert parse_rtp_header(data) is None


def test_sdp_par_adresse_et_repli_srtp():
    table = parse_sdp(SDP_H264)
    assert table[("10.0.0.2", 50002)][96] == ("H264", 90000, "video", False)
    assert table[(None, None)][96][0] == "H264"
    srtp = parse_sdp(b"c=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/SAVP 96\r\na=rtpmap:96 opus/48000/2\r\n")
    assert srtp[("1.2.3.4", 4000)][96] == ("OPUS", 48000, "audio", True)
    assert parse_sdp(b"GET / HTTP/1.1\r\n") == {}


def test_faux_rtp_ecarte():
    few = audio_stream(5)
    noisy = [("LAN", i, A, 5353, B, 53, rtp(i * 7919, 0)) for i in range(40)]
    assert collect_streams(few + noisy) == []


# -- analyse qualitative -------------------------------------------------------


def test_flux_intact_degradation_imperceptible():
    (st,) = collect_streams(audio_stream())
    q = analyse_stream(st)
    assert (st.codec, st.kind, q.lost, q.duplicates, q.reordered) == ("PCMU", "audio", 0, 0, 0)
    assert q.degradation is not None and q.degradation < 5 and q.verdict == "imperceptible"
    assert q.mos is not None and q.mos > 4.0
    assert "non mesure" in (q.note or "")


def test_pertes_en_rafale_degradation_severe():
    (st,) = collect_streams(audio_stream(100, drop=set(range(40, 55))))
    q = analyse_stream(st)
    assert (q.expected, q.lost, q.max_burst) == (100, 15, 15)
    assert q.loss_pct == 15.0
    assert q.verdict == "severe" and q.mos is not None and q.mos < 3.0


def test_bouclage_des_numeros_de_sequence():
    (st,) = collect_streams(audio_stream(40, seq0=65520))
    q = analyse_stream(st)
    assert (q.expected, q.lost) == (40, 0)


def test_doublons_desordre_et_gigue():
    data = audio_stream(30, jitter=lambda i: 0.015 if i % 3 == 0 else 0.0)
    data.insert(5, data[5])  # doublon
    data[10], data[11] = data[11], data[10]  # desordre
    (st,) = collect_streams(data)
    q = analyse_stream(st)
    assert q.duplicates == 1 and q.reordered == 1 and q.lost == 0
    assert q.jitter_ms is not None and q.jitter_ms > 1.0


@pytest.mark.parametrize(
    ("score", "label"), [(None, "non evaluee"), (0, "imperceptible"), (10, "legere"), (20, "genante"), (80, "severe")]
)
def test_verdicts(score, label):
    assert verdict(score) == label


def _video(drop=()):
    out = [("LAN", 0.5, A, 5060, B, 5060, SDP_H264)]
    seq = 0
    for frame in range(10):
        for part in range(3):  # 3 paquets par image, FU-A
            fu = (0x80 if part == 0 else 0) | (0x40 if part == 2 else 0) | 5
            if seq not in drop:
                payload = bytes([0x7C, fu]) + bytes([frame]) * 10
                out.append(("LAN", 1 + seq * 0.01, A, 40002, B, 50002, rtp(seq, frame * 3000, pt=96, payload=payload)))
            seq += 1
    return out


def test_video_images_endommagees():
    (st,) = collect_streams(_video(drop={4, 16}))
    q = analyse_stream(st)
    assert (st.codec, st.kind) == ("H264", "video")
    assert (q.frames, q.damaged_frames, q.degradation) == (10, 2, 20)
    assert q.verdict == "genante"


def test_codec_inconnu_statistiques_seules():
    (st,) = collect_streams(audio_stream(pt=111))
    q = analyse_stream(st)
    assert q.degradation is None and "PT 111" in (q.note or "")


# -- decodage / extraction -----------------------------------------------------


def test_decodage_g711():
    assert struct.unpack("<4h", decode_g711("PCMU", b"\xff\x00\x7f\x80")) == (0, -32124, 0, 32124)
    assert struct.unpack("<2h", decode_g711("PCMA", b"\xd5\x55")) == (8, -8)


def test_wav_silence_a_la_place_des_pertes(tmp_path):
    (st,) = collect_streams(audio_stream(20, drop={5, 6}, payload=b"\x00" * 160))
    path = export_stream(st, tmp_path)
    with wave.open(str(path)) as w:
        assert (w.getframerate(), w.getnchannels(), w.getnframes()) == (8000, 1, 20 * 160)
        frames = w.readframes(20 * 160)
    samples = struct.unpack(f"<{20 * 160}h", frames)
    assert set(samples[5 * 160 : 7 * 160]) == {0}  # silence
    assert set(samples[:160]) == {-32124}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_depaquetage_h264():
    single = b"\x67\x42\x00"
    stap = b"\x18" + struct.pack("!H", 2) + b"\x68\xaa" + struct.pack("!H", 2) + b"\x06\xbb"
    fu = [b"\x7c\x85AA", b"\x7c\x05BB", b"\x7c\x45CC"]  # IDR (type 5) en 3 fragments
    out = depacketize_h264(enumerate([single, stap, *fu]))
    start = b"\x00\x00\x00\x01"
    assert out == start + single + start + b"\x68\xaa" + start + b"\x06\xbb" + start + b"\x65AABBCC"
    # fragment du milieu perdu : NAL ecarte entier
    assert depacketize_h264([(0, fu[0]), (2, fu[2])]) == b""


def test_srtp_non_exporte(tmp_path):
    sdp = b"c=IN IP4 10.0.0.2\r\nm=audio 50000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    (st,) = collect_streams([("LAN", 0.1, B, 5060, A, 5060, sdp), *audio_stream()])
    assert st.encrypted
    assert "SRTP" in (analyse_stream(st).note or "")
    with pytest.raises(ValueError, match="SRTP"):
        export_stream(st, tmp_path)


# -- orchestration, manifeste, rappel d'usage --------------------------------------


def _raw(datagrams):
    return [
        SimpleNamespace(proto="UDP", ts=ts, src=s, sport=sp, dst=d, dport=dp, payload=p)
        for _pt, ts, s, sp, d, dp, p in datagrams
    ]


def test_extraction_manifeste_permissions_et_rappel(tmp_path):
    out = tmp_path / "extraction"
    captures = [("LAN", "lan.pcap")]
    res = run_extraction(
        captures, out_dir=str(out), kinds=("audio", "video"), read_capture=lambda _p: _raw(audio_stream() + _video())
    )
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["usage_reminder"] == USAGE_REMINDER
    assert [m["kind"] for m in manifest["media"]] == ["audio", "video"]
    assert all(m["exported"] for m in manifest["media"])
    assert (out / "video").is_dir() and list((out / "video").glob("*.h264"))
    assert "226-15" in (out / "LISEZ-MOI.txt").read_text(encoding="utf-8")
    text = "\n".join(format_extraction(res))
    assert "degradation" in text and "Manifeste" in text


def test_extraction_restreinte_a_l_audio(tmp_path):
    out = tmp_path / "x"
    run_extraction(
        [("LAN", "f")], out_dir=str(out), kinds=("audio",), read_capture=lambda _p: _raw(audio_stream() + _video())
    )
    assert not (out / "video").exists() and list((out / "audio").glob("*.wav"))


def test_analyse_qualitative_n_ecrit_rien(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = run_extraction([("LAN", "f")], out_dir=None, kinds=(), read_capture=lambda _p: _raw(audio_stream()))
    assert len(res.media) == 1 and res.media[0].exported is None
    assert list(tmp_path.iterdir()) == []


def test_repertoire_non_vide_refuse(tmp_path):
    (tmp_path / "deja").mkdir()
    (tmp_path / "deja" / "f").write_text("x")
    with pytest.raises(ValueError, match="repertoire vide"):
        prepare_out_dir(str(tmp_path / "deja"))


def test_types_d_extraction():
    assert parse_kinds(None) == ("audio", "video", "documents")
    assert parse_kinds("documents, audio,audio") == ("documents", "audio")
    with pytest.raises(ValueError, match="texte"):
        parse_kinds("audio,texte")


def _fake_tshark(tmp_path):
    script = tmp_path / "tshark"
    script.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in http,*) d="${a#http,}"; printf "%%PDF-1.4 x" > "$d/rapport.pdf";;\n'
        'smb,*) echo "tshark: unknown protocol" >&2; exit 2;; esac; done\n'
    )
    script.chmod(0o755)
    return str(script)


def test_documents_via_export_objects(tmp_path):
    out = prepare_out_dir(str(tmp_path / "out"))
    docs, errors = export_documents(
        [("LAN", "c.pcap")], out, protocols=("http", "smb", "tftp"), tshark_bin=_fake_tshark(tmp_path)
    )
    (doc,) = docs
    assert (doc.protocol, doc.detected_type, doc.size) == ("http", "pdf", 10)
    assert len(doc.sha256) == 64
    assert errors == ["documents [LAN] smb : tshark: unknown protocol"]
    assert not (out / "documents" / "LAN" / "tftp").exists()  # repertoires vides retires


def test_documents_sans_tshark(tmp_path):
    _docs, errors = export_documents([("LAN", "c")], tmp_path, tshark_bin=str(tmp_path / "absent"))
    assert errors == ["documents : tshark introuvable, aucun document extrait"]


# -- validations CLI -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--extract-kinds", "audio"], "--extract-kinds necessite --extract-contents"),
        (["--extract-contents", "OUT", "--redact"], "ne peut pas etre anonymise"),
        (["--extract-contents", "OUT", "--extract-kinds", "texte"], "type(s) inconnu(s)"),
        (["--extract-contents", "PLEIN"], "n'est pas un repertoire vide"),
    ],
)
def test_validations_cli(monkeypatch, capsys, tmp_path, extra, message):
    (tmp_path / "PLEIN").mkdir()
    (tmp_path / "PLEIN" / "f").write_text("x")
    extra = [str(tmp_path / e) if e in ("OUT", "PLEIN") else e for e in extra]
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cli", "--capture", f"LAN={capture}", *extra])
    with pytest.raises(SystemExit):
        cli.main()
    assert message in capsys.readouterr().err


def test_live_refuse(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cli", "--live", "LAN=eth0", "--media-quality"])
    with pytest.raises(SystemExit):
        cli.main()
    assert "indisponibles avec --live" in capsys.readouterr().err
