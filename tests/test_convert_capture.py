"""
pcap_parser.capture.convert_capture / export_csv / export_json
(Job 49, issue #169) -- conversion de formats et export structure.
Meme discipline que test_replay.py : on monkeypatch shutil.which et
subprocess.run, jamais un vrai binaire tshark.
"""

import pytest

import pcap_parser.capture as capture_mod
from pcap_parser.capture import convert_capture, export_csv, export_json
from pcap_parser.ek_source import TsharkError, TsharkNotFoundError


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


@pytest.fixture
def pcap_file(tmp_path):
    p = tmp_path / "capture.pcapng"
    p.write_bytes(b"\x00")
    return str(p)


# -- validation des parametres (avant tout appel a tshark) ---------------------


def test_convert_capture_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        convert_capture(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.pcap"))


def test_convert_capture_format_non_supporte(pcap_file, tmp_path):
    with pytest.raises(ValueError, match="format non supporte"):
        convert_capture(pcap_file, str(tmp_path / "out.txt"), fmt="txt")


def test_convert_capture_format_insensible_casse(pcap_file, tmp_path, monkeypatch):
    """PCAPNG, Pcapng, pcapng doivent tous etre acceptes."""
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    convert_capture(pcap_file, str(tmp_path / "out.pcap"), fmt="PCAPNG")
    convert_capture(pcap_file, str(tmp_path / "out2.pcap"), fmt="Pcap")
    assert len(calls) == 2


# -- tshark absent du PATH ----------------------------------------------------


def test_convert_capture_tshark_absent(pcap_file, tmp_path, monkeypatch):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        convert_capture(pcap_file, str(tmp_path / "out.pcap"))


# -- conversion reussie (mock subprocess) -------------------------------------


def test_convert_capture_pcap_vers_pcapng(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "converted.pcapng")
    convert_capture(pcap_file, out, fmt="pcapng")

    assert len(calls) == 1
    args = calls[0]
    assert "-r" in args
    assert pcap_file in args
    assert "-F" in args
    assert "pcapng" in args
    assert "-w" in args
    assert out in args


def test_convert_capture_erf(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess()

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "converted.erf")
    convert_capture(pcap_file, out, fmt="erf")

    args = calls[0]
    assert "erf" in args


def test_convert_capture_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="unknown format")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="conversion"):
        convert_capture(pcap_file, str(tmp_path / "out.pcap"))


# -- export CSV ---------------------------------------------------------------


def test_export_csv_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_csv(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.csv"))


def test_export_csv_reussi(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess(stdout="frame.time_epoch,ip.src,ip.dst\n")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "export.csv")
    export_csv(pcap_file, out)

    assert len(calls) == 1
    args = calls[0]
    assert "-T" in args
    assert "fields" in args
    assert "-e" in args
    assert "frame.time_epoch" in args
    assert "ip.src" in args
    assert "ip.dst" in args
    assert "frame.len" in args


def test_export_csv_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="cannot read")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="export CSV"):
        export_csv(pcap_file, str(tmp_path / "out.csv"))


# -- export JSON --------------------------------------------------------------


def test_export_json_fichier_introuvable(tmp_path):
    with pytest.raises(FileNotFoundError):
        export_json(str(tmp_path / "absent.pcapng"), str(tmp_path / "out.json"))


def test_export_json_reussi(pcap_file, tmp_path, monkeypatch):
    calls = []

    def _fake_run(args, **kwargs):
        calls.append(args)
        return _FakeCompletedProcess(stdout='[{"_index": "packets"}]')

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    out = str(tmp_path / "export.json")
    export_json(pcap_file, out)

    assert len(calls) == 1
    args = calls[0]
    assert "-T" in args
    assert "json" in args


def test_export_json_echec_tshark(pcap_file, tmp_path, monkeypatch):
    def _fake_run(args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stderr="cannot read")

    monkeypatch.setattr(capture_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: "/usr/bin/" + name)

    with pytest.raises(TsharkError, match="export JSON"):
        export_json(pcap_file, str(tmp_path / "out.json"))
