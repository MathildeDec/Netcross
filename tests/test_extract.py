"""
tests.test_extract -- module netcross_core.extract (issue #150,
SCENARIO-4) : extraction/reconstruction de fichiers transferes dans les
flux reseau (HTTP, email, SMB, FTP) et carving generique par magic
bytes.

Deux familles de tests, meme discipline que test_merge_captures.py /
test_security_report_pcap.py :
  - unitaires, sans tshark : logique pure (carving par signatures,
    hashing, ecriture securisee des fichiers, orchestration
    extract_all()) et cablage des sous-modules (smb.py/ftp.py) verifie
    par subprocess simule ;
  - integration, avec un vrai tshark sur des captures synthetisees
    octet par octet (Ethernet/IPv4/TCP, sans scapy -- voir
    eth_ip_tcp_builders.py) : HTTP, email (piece jointe base64) et
    carving generique. Sautees si tshark est absent du PATH.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from eth_ip_tcp_builders import TcpStreamBuilder
from pcap_builders import write_pcap

import cross_capture_analyzer_cli as cli
from netcross_core import extract
from netcross_core.extract import carver
from netcross_core.extract._common import (
    TsharkError,
    detect_type,
    file_hashes,
    write_extracted,
)

TSHARK_ABSENT = shutil.which("tshark") is None
requires_tshark = pytest.mark.skipif(TSHARK_ABSENT, reason="tshark absent du PATH")

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


# -- fabriques de captures synthetiques --------------------------------------------


def _write_http_capture(path: Path) -> bytes:
    """Un GET/200 avec un corps PDF factice. Retourne le corps attendu."""
    body = b"%PDF-1.4 contenu de test pour extraction HTTP%%EOF"
    b = TcpStreamBuilder(CLIENT, SERVER, 51000, 80)
    b.handshake()
    b.send_client(b"GET /file.pdf HTTP/1.1\r\nHost: example.com\r\n\r\n")
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    b.send_server(response)
    b.close()
    write_pcap(path, b.packets)
    return body


def _write_email_capture(path: Path) -> bytes:
    """Une session SMTP avec une piece jointe encodee en base64. Retourne
    le contenu attendu de la piece jointe."""
    attachment = b"contenu-secret-de-la-piece-jointe-0123456789"
    b64 = base64.b64encode(attachment).decode()
    boundary = "BOUND-NETCROSS"
    smtp_data = (
        "From: alice@example.com\r\n"
        "To: bob@example.com\r\n"
        "Subject: test\r\n"
        "MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n'
        "\r\n"
        f"--{boundary}\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Bonjour\r\n"
        f"--{boundary}\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="secret.bin"\r\n\r\n'
        + "\r\n".join(b64[i : i + 76] for i in range(0, len(b64), 76))
        + "\r\n"
        f"--{boundary}--\r\n"
        ".\r\n"
    ).encode()

    b = TcpStreamBuilder(CLIENT, SERVER, 52000, 25)
    b.handshake()
    b.send_client(b"EHLO client.example.com\r\n")
    b.send_server(b"250 OK\r\n")
    b.send_client(b"MAIL FROM:<alice@example.com>\r\n")
    b.send_server(b"250 OK\r\n")
    b.send_client(b"RCPT TO:<bob@example.com>\r\n")
    b.send_server(b"250 OK\r\n")
    b.send_client(b"DATA\r\n")
    b.send_server(b"354 Start mail input\r\n")
    b.send_client(smtp_data)
    b.send_server(b"250 Message accepted\r\n")
    b.close()
    write_pcap(path, b.packets)
    return attachment


def _write_generic_zip_capture(path: Path) -> bytes:
    """Un ZIP minimal (magic bytes + EOCD) transfere sur un port non
    standard (4444), pour verifier le carving generique."""
    zip_bytes = b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"A" * 40 + b"PK\x05\x06" + b"\x00" * 18
    b = TcpStreamBuilder(CLIENT, SERVER, 51000, 4444)
    b.handshake()
    b.send_server(zip_bytes)
    b.close()
    write_pcap(path, b.packets)
    return zip_bytes


# -- unitaires : _common ------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"PK\x03\x04reste", "ZIP"),
        (b"%PDF-1.4 ...", "PDF"),
        (b"\x89PNG\r\n\x1a\nreste", "PNG"),
        (b"GIF89a...", "GIF"),
        (b"\xff\xd8\xffreste", "JPEG"),
        (b"MZ\x90\x00...", "EXE"),
        (b"random bytes here", "unknown"),
    ],
)
def test_detect_type(data, expected):
    assert detect_type(data) == expected


def test_file_hashes():
    md5, sha256 = file_hashes(b"hello")
    assert md5 == "5d41402abc4b2a76b9719d911017c592"
    assert sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_write_extracted_desambiguise_les_collisions(tmp_path):
    p1 = write_extracted(str(tmp_path), "rapport.pdf", b"un")
    p2 = write_extracted(str(tmp_path), "rapport.pdf", b"deux")
    assert p1 != p2
    assert Path(p1).read_bytes() == b"un"
    assert Path(p2).read_bytes() == b"deux"


def test_write_extracted_neutralise_un_chemin_traversant(tmp_path):
    out = write_extracted(str(tmp_path), "../../etc/passwd", b"x")
    assert Path(out).parent == tmp_path
    assert Path(out).name == "passwd"


# -- unitaires : carving (logique pure, sans tshark) ---------------------------------


def test_carve_zip_s_arrete_a_l_eocd():
    zip_bytes = b"PK\x03\x04" + b"A" * 40 + b"PK\x05\x06" + b"\x00" * 18
    trailer = b"garbage-after"
    matches = carver._carve(zip_bytes + trailer)
    assert matches == [("ZIP", 0, len(zip_bytes))]


def test_carve_pdf_s_arrete_a_eof():
    pdf_bytes = b"%PDF-1.4 contenu %%EOF"
    trailer = b"pas du pdf"
    matches = carver._carve(pdf_bytes + trailer)
    assert matches == [("PDF", 0, len(pdf_bytes))]


def test_carve_png_s_arrete_a_iend():
    png_bytes = b"\x89PNG\r\n\x1a\ndonnees" + b"IEND\xae\x42\x60\x82"
    trailer = b"pas du png"
    matches = carver._carve(png_bytes + trailer)
    assert matches == [("PNG", 0, len(png_bytes))]


def test_carve_type_sans_marqueur_de_fin_prend_le_reste_du_flux():
    data = b"prefixe" + b"MZ" + b"reste-du-binaire"
    matches = carver._carve(data)
    assert matches == [("EXE", 7, len(data))]


def test_carve_plusieurs_fichiers_sans_chevauchement():
    pdf_bytes = b"%PDF-1.4 x %%EOF"
    zip_bytes = b"PK\x03\x04" + b"B" * 10 + b"PK\x05\x06" + b"\x00" * 18
    data = b"avant" + pdf_bytes + b"entre" + zip_bytes + b"apres"
    matches = carver._carve(data)
    types = [m[0] for m in matches]
    assert types == ["PDF", "ZIP"]


def test_carve_aucune_signature():
    assert carver._carve(b"rien d'interessant ici") == []


# -- unitaires : orchestrateur extract_all -------------------------------------------


def test_extract_all_protocole_inconnu_leve_value_error(tmp_path):
    with pytest.raises(ValueError, match="inconnu"):
        extract.extract_all("capture.pcap", str(tmp_path), protocols=["telepathie"])


def test_extract_all_un_protocole_en_echec_n_empeche_pas_les_autres(tmp_path, monkeypatch):
    from netcross_core.extract.models import ExtractedFile

    ok_file = ExtractedFile(
        protocol="HTTP",
        point="",
        frame_number=1,
        ts=0.0,
        src=None,
        dst=None,
        filename="x.pdf",
        content_type=None,
        detected_type="PDF",
        size_bytes=1,
        md5="a",
        sha256="b",
        output_path="x",
    )

    def failing(*a, **k):
        raise TsharkError("boom", returncode=1, stderr="boom")

    def working(*a, **k):
        return [ok_file]

    monkeypatch.setattr(extract, "_EXTRACTORS", {"http": working, "email": failing})
    results = extract.extract_all("capture.pcap", str(tmp_path), protocols=["http", "email"])
    assert results == [ok_file]


def test_extract_all_protocols_none_utilise_tout(monkeypatch, tmp_path):
    called = []

    def make(name):
        def _f(pcap_path, dest_dir, *, point=""):
            called.append(name)
            return []

        return _f

    monkeypatch.setattr(
        extract,
        "_EXTRACTORS",
        {name: make(name) for name in extract.ALL_PROTOCOLS},
    )
    extract.extract_all("capture.pcap", str(tmp_path))
    assert set(called) == set(extract.ALL_PROTOCOLS)


# -- unitaires : smb.py/ftp.py (cablage tshark simule) ---------------------------------


def test_extract_smb_files_appelle_export_objects_smb(tmp_path, monkeypatch):
    from netcross_core.extract import smb

    seen_args = []

    def fake_run(args, **kwargs):
        seen_args.append(args)
        if "--export-objects" in args:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("netcross_core.extract._common.shutil.which", lambda name: "/usr/bin/tshark")
    smb.extract_smb_files("capture.pcap", str(tmp_path))
    export_call = next(a for a in seen_args if "--export-objects" in a)
    assert "smb," in export_call[export_call.index("--export-objects") + 1]


def test_extract_ftp_files_appelle_export_objects_ftp_data(tmp_path, monkeypatch):
    from netcross_core.extract import ftp

    seen_args = []

    def fake_run(args, **kwargs):
        seen_args.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("netcross_core.extract._common.shutil.which", lambda name: "/usr/bin/tshark")
    ftp.extract_ftp_files("capture.pcap", str(tmp_path))
    export_call = next(a for a in seen_args if "--export-objects" in a)
    assert "ftp-data," in export_call[export_call.index("--export-objects") + 1]


def test_tshark_absent_leve_tshark_not_found_error(tmp_path, monkeypatch):
    from netcross_core.extract import http
    from netcross_core.extract._common import TsharkNotFoundError

    monkeypatch.setattr("netcross_core.extract._common.shutil.which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        http.extract_http_files("capture.pcap", str(tmp_path))


# -- integration : vrai tshark ------------------------------------------------------


@requires_tshark
def test_http_integration(tmp_path):
    pcap = tmp_path / "http.pcap"
    expected_body = _write_http_capture(pcap)
    dest = tmp_path / "out"

    files = extract.extract_http_files(str(pcap), str(dest), point="LAN")
    assert len(files) == 1
    f = files[0]
    assert f.protocol == "HTTP"
    assert f.point == "LAN"
    assert f.content_type == "application/pdf"
    assert f.detected_type == "PDF"
    assert f.size_bytes == len(expected_body)
    assert Path(f.output_path).read_bytes() == expected_body
    md5, sha256 = file_hashes(expected_body)
    assert f.md5 == md5
    assert f.sha256 == sha256
    assert f.frame_number is not None
    assert f.ts is not None


@requires_tshark
def test_email_integration(tmp_path):
    pcap = tmp_path / "email.pcap"
    expected_attachment = _write_email_capture(pcap)
    dest = tmp_path / "out"

    files = extract.extract_email_attachments(str(pcap), str(dest))
    assert len(files) == 1
    f = files[0]
    assert f.protocol == "email"
    assert f.filename == "secret.bin"
    assert Path(f.output_path).read_bytes() == expected_attachment
    assert f.size_bytes == len(expected_attachment)


@requires_tshark
def test_carving_generique_integration(tmp_path):
    pcap = tmp_path / "generic.pcap"
    expected_zip = _write_generic_zip_capture(pcap)
    dest = tmp_path / "out"

    files = extract.carve_generic(str(pcap), str(dest))
    assert len(files) == 1
    f = files[0]
    assert f.protocol == "carving"
    assert f.detected_type == "ZIP"
    assert Path(f.output_path).read_bytes() == expected_zip


@requires_tshark
def test_extract_all_combine_les_protocoles(tmp_path):
    pcap = tmp_path / "http.pcap"
    _write_http_capture(pcap)
    dest = tmp_path / "out"

    files = extract.extract_all(str(pcap), str(dest), protocols=["http", "carving"])
    protocols = {f.protocol for f in files}
    assert "HTTP" in protocols


# -- integration CLI : --extract-dir --------------------------------------------------


@requires_tshark
def test_cli_extract_dir_peuple_le_rapport(monkeypatch, capsys, tmp_path):
    pcap = tmp_path / "http.pcap"
    expected_body = _write_http_capture(pcap)
    dest = tmp_path / "extraits"

    argv = [
        "cross_capture_analyzer_cli.py",
        "--capture",
        f"LAN={pcap}",
        "--extract-dir",
        str(dest),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()

    out = capsys.readouterr().out
    # --extract-dir lance TOUS les protocoles par defaut (voir extract_all) :
    # le carving generique retrouve legitimement le meme corps PDF que
    # l'extracteur HTTP applicatif (les deux passent sur la meme donnee, par
    # des chemins independants) -- au moins un fichier ecrit, dont le
    # contenu correspond exactement au corps attendu.
    assert "fichier(s) extrait(s)" in out
    assert "-- Fichiers extraits (" in out
    written = list(dest.iterdir())
    assert written
    assert any(p.read_bytes() == expected_body for p in written)


def test_cli_extract_dir_incompatible_avec_live(monkeypatch, capsys):
    argv = ["cross_capture_analyzer_cli.py", "--live", "eth0", "--extract-dir", "/tmp/out"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        cli.main()
    assert "--extract-dir" in capsys.readouterr().err


def test_cli_extract_dir_incompatible_avec_merge(monkeypatch, capsys, tmp_path):
    pcap = tmp_path / "a.pcap"
    write_pcap(pcap, [])
    argv = [
        "cross_capture_analyzer_cli.py",
        "--capture",
        f"LAN={pcap}",
        "--merge",
        str(tmp_path / "out.pcap"),
        "--extract-dir",
        str(tmp_path / "extraits"),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        cli.main()
    assert "--extract-dir" in capsys.readouterr().err
