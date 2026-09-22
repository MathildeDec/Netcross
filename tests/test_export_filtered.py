"""
Tests de pcap_parser.capture.export_filtered (Job 36, issue #156) et de la
CLI --export-pcap.

Meme convention que test_split_capture.py : par defaut tshark est SIMULE
(monkeypatch de shutil.which + subprocess.run) et on verifie la ligne de
commande construite. Les tests de la derniere section lancent le VRAI
tshark et sont sautes s'il est absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from pcap_builders import (
    ip_tcp_frame,
    ip_udp_frame,
    read_pcap,
    synthetic_packets,
    write_pcap,
)

requires_tshark = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark non installe",
)


# -- _build_display_filter --------------------------------------------------


def test_build_display_filter_aucun_critere_donne_none():
    from pcap_parser.capture import _build_display_filter

    assert _build_display_filter() is None


def test_build_display_filter_bpf_filter_seul():
    """Malgre son nom, bpf_filter est repli tel quel dans le filtre
    d'affichage (issue #261) -- pas une traduction BPF -> display filter."""
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(bpf_filter="tcp.port == 80")
    assert f == "(tcp.port == 80)"


def test_build_display_filter_time_start_seul():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=10.0)
    assert "frame.time_relative >= 10" in f
    assert "frame.time_relative <= " not in f


def test_build_display_filter_time_end_seul():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_end=60.0)
    assert "frame.time_relative <= 60" in f


def test_build_display_filter_plage_complete():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=10.0, time_end=60.0)
    assert "frame.time_relative >= 10" in f
    assert "frame.time_relative <= 60" in f
    assert "&&" in f


def test_build_display_filter_endpoints():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(endpoints=["192.168.1.1", "10.0.0.1"])
    assert "ip.addr == 192.168.1.1" in f
    assert "ip.addr == 10.0.0.1" in f
    assert "||" in f


def test_build_display_filter_combine_tout():
    from pcap_parser.capture import _build_display_filter

    f = _build_display_filter(time_start=5.0, time_end=30.0, endpoints=["192.168.1.1"], bpf_filter="tcp.port == 443")
    assert "frame.time_relative >= 5" in f
    assert "frame.time_relative <= 30" in f
    assert "ip.addr == 192.168.1.1" in f
    assert "(tcp.port == 443)" in f
    assert f.count("&&") == 3  # les 4 criteres sont bien en ET logique


# -- export_filtered : validation des arguments -----------------------------


def test_export_filtered_capture_inexistante(tmp_path):
    from pcap_parser.capture import export_filtered

    with pytest.raises(FileNotFoundError):
        export_filtered(str(tmp_path / "absent.pcap"), str(tmp_path / "out.pcap"))


def test_export_filtered_endpoints_vides_leve_valueerror(tmp_path):
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    with pytest.raises(ValueError, match="endpoints ne peut pas"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), endpoints=[])


def test_export_filtered_time_start_superieur_time_end(tmp_path):
    from pcap_parser.capture import export_filtered

    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    with pytest.raises(ValueError, match=r"time_start.*>.*time_end"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), time_start=60.0, time_end=10.0)


# -- export_filtered : construction de la ligne de commande tshark ----------


def _fake_tshark(monkeypatch, returncode=0, stderr=""):
    """Monkeypatch shutil.which pour tshark et subprocess.run pour
    verifier la ligne de commande construite sans lancer tshark."""

    def fake_which(name):
        if name == "tshark":
            return "/usr/bin/tshark"
        return shutil.which(name)

    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=returncode, stdout="", stderr=stderr)

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_export_filtered_sans_filtre_recopie_tout(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))
    out = str(tmp_path / "out.pcap")

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), out)
    assert len(calls) == 1
    args = calls[0]
    assert "-r" in args
    assert "-w" in args
    assert str(src) in args
    assert out in args
    # Aucun critere : pas de -Y. -f n'est JAMAIS utilise par export_filtered
    # (issue #261 : incompatible avec -r, "Only read filters, not capture
    # filters, can be specified when reading a capture file").
    assert "-f" not in args
    assert "-Y" not in args


def test_export_filtered_format_pcap_ajoute_f_pcap(monkeypatch, tmp_path):
    """-F explicite, indispensable : sans lui tshark ecrit toujours du
    pcapng, quelle que soit l'extension de path_out (issue #261)."""
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"))
    args = calls[0]
    assert "-F" in args
    assert args[args.index("-F") + 1] == "pcap"


def test_export_filtered_format_pcapng_ajoute_f_pcapng(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcapng"))
    args = calls[0]
    assert "-F" in args
    assert args[args.index("-F") + 1] == "pcapng"


def test_export_filtered_avec_bpf_filter_ajoute_y_pas_f(monkeypatch, tmp_path):
    """bpf_filter, malgre son nom, part dans -Y (filtre d'affichage), jamais
    dans -f (filtre de capture, refuse par tshark en lecture de fichier) --
    issue #261."""
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), bpf_filter="tcp.port == 80")
    args = calls[0]
    assert "-f" not in args
    assert "-Y" in args
    assert "tcp.port == 80" in args[args.index("-Y") + 1]


def test_export_filtered_avec_plage_temporelle_ajoute_y(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), time_start=10.0, time_end=60.0)
    args = calls[0]
    assert "-Y" in args
    y_idx = args.index("-Y")
    display_filter = args[y_idx + 1]
    assert "frame.time_relative >= 10" in display_filter
    assert "frame.time_relative <= 60" in display_filter


def test_export_filtered_avec_endpoints_ajoute_y(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(str(src), str(tmp_path / "out.pcap"), endpoints=["192.168.1.1", "10.0.0.1"])
    args = calls[0]
    assert "-Y" in args
    y_idx = args.index("-Y")
    display_filter = args[y_idx + 1]
    assert "ip.addr == 192.168.1.1" in display_filter
    assert "ip.addr == 10.0.0.1" in display_filter
    assert "||" in display_filter


def test_export_filtered_combine_bpf_et_display_filter(monkeypatch, tmp_path):
    calls = _fake_tshark(monkeypatch)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered

    export_filtered(
        str(src),
        str(tmp_path / "out.pcap"),
        bpf_filter="tcp",
        time_start=5.0,
        endpoints=["10.0.0.1"],
    )
    args = calls[0]
    assert "-f" not in args
    assert "-Y" in args
    display_filter = args[args.index("-Y") + 1]
    assert "(tcp)" in display_filter
    assert "frame.time_relative >= 5" in display_filter
    assert "ip.addr == 10.0.0.1" in display_filter


def test_export_filtered_tshark_absent_leve_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered
    from pcap_parser.ek_source import TsharkNotFoundError

    with pytest.raises(TsharkNotFoundError):
        export_filtered(str(src), str(tmp_path / "out.pcap"))


def test_export_filtered_tshark_echoue_leve_tshark_error(monkeypatch, tmp_path):
    _fake_tshark(monkeypatch, returncode=1, stderr="bad filter")
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    from pcap_parser.capture import export_filtered
    from pcap_parser.ek_source import TsharkError

    with pytest.raises(TsharkError, match="echoue"):
        export_filtered(str(src), str(tmp_path / "out.pcap"), bpf_filter="invalid filter")


# -- Tests reels (tshark installe) -----------------------------------------


@requires_tshark
def test_reel_export_100_paquets_d_un_pcap_de_1000(tmp_path):
    """Exporte 100 paquets d'un PCAP de 1000 (par count via BPF impossiblesur
    des paquets synthetiques sans IP -- on filtre par plage temporelle)."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))

    from pcap_parser.capture import export_filtered

    # synthetic_packets : 1 paquet / 100ms, duree 100s pour 1000 paquets
    # Plage [0, 10s] = ~100 paquets
    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, time_start=0.0, time_end=10.0)

    assert os.path.isfile(out)
    _, packets = read_pcap(out)
    assert 90 <= len(packets) <= 110  # tolerance pour les bornes


@requires_tshark
def test_reel_export_plage_temporelle_verifie_timestamps(tmp_path):
    """Filtre par plage temporelle et verifie que tous les paquets
    exportes sont dans la plage."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, time_start=20.0, time_end=40.0)

    _, packets = read_pcap(out)
    # Les paquets synthetiques sont a 0, 0.1, 0.2, ... secondes
    # Plage [20, 40] -> paquets 200 a 400 (environ)
    assert len(packets) > 0
    # Verifie que tous les indices de paquets sont dans la plage attendue
    from pcap_builders import frame_index

    indices = [frame_index(d) for _sec, _frac, d in packets]
    assert min(indices) >= 190  # tolerance
    assert max(indices) <= 410  # tolerance


@requires_tshark
def test_reel_export_sans_filtre_recopie_tout(tmp_path):
    """Sans aucun filtre, la capture entiere est recopiee."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(100))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out)

    _, packets = read_pcap(out)
    assert len(packets) == 100


@requires_tshark
def test_reel_export_format_pcapng(tmp_path):
    """Le format de sortie depend de l'extension (issue #261 : sans le -F
    explicite ajoute par le correctif, tshark ecrit TOUJOURS du pcapng,
    y compris quand path_out se termine par .pcap -- voir le test suivant)."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(10))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcapng")
    export_filtered(str(src), out)

    assert os.path.isfile(out)
    # Verifier que c'est un pcapng (magic number 0x0A0D0D0A)
    with open(out, "rb") as f:
        magic = f.read(4)
    assert magic == b"\x0a\x0d\x0d\x0a"


@requires_tshark
def test_reel_export_format_pcap_n_est_pas_ecrit_en_pcapng(tmp_path):
    """Regression issue #261 : une sortie .pcap doit reellement etre du
    pcap classique (magic 0xA1B2C3D4/0xD4C3B2A1), pas du pcapng maquille
    sous une extension .pcap."""
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(10))

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out)

    with open(out, "rb") as f:
        magic = f.read(4)
    assert magic != b"\x0a\x0d\x0d\x0a", "sortie .pcap ecrite en pcapng (issue #261)"
    assert magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    # Et bien relisible avec le lecteur pcap classique (sinon read_pcap leverait)
    _, packets = read_pcap(out)
    assert len(packets) == 10


@requires_tshark
def test_reel_export_bpf_filter_sur_de_vraies_trames_ip(tmp_path):
    """Regression issue #261 : bpf_filter ne doit PLUS lever TsharkError
    ("Only read filters, not capture filters..."), et doit reellement
    filtrer -- ici via une syntaxe de filtre d'AFFICHAGE (ip.addr), pas BPF."""
    src = tmp_path / "cap.pcap"
    packets = []
    ts = 1_700_000_000_000_000
    for i in range(20):
        frame_bytes = (
            ip_udp_frame("10.0.0.1", "10.0.0.9", 5000 + i, 53)
            if i % 2 == 0
            else ip_tcp_frame("10.0.0.2", "10.0.0.9", 6000 + i, 80)
        )
        packets.append((ts + i * 100_000, frame_bytes))
    write_pcap(src, packets)

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, bpf_filter="ip.addr == 10.0.0.1")  # ne leve pas

    _, result = read_pcap(out)
    assert len(result) == 10  # les 10 paquets UDP depuis 10.0.0.1, aucun des TCP


@requires_tshark
def test_reel_export_bpf_filter_combine_avec_endpoints(tmp_path):
    """bpf_filter et endpoints sont bien en ET logique une fois combines
    dans le meme filtre d'affichage."""
    src = tmp_path / "cap.pcap"
    ts = 1_700_000_000_000_000
    packets = [
        (ts + i * 100_000, ip_udp_frame("10.0.0.1", "10.0.0.9", 5000 + i, 53 if i < 5 else 80)) for i in range(10)
    ]
    write_pcap(src, packets)

    from pcap_parser.capture import export_filtered

    out = str(tmp_path / "out.pcap")
    export_filtered(str(src), out, bpf_filter="udp.port == 53", endpoints=["10.0.0.1"])

    _, result = read_pcap(out)
    assert len(result) == 5
