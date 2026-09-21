"""
Conversion de formats de capture (Job 49, issue #169) :
pcap_parser.convert.convert_capture et le flag --convert de
cross_capture_analyzer_cli.py.

Trois familles de tests, comme le reste de la suite pour tshark :
  - unitaires, SANS outil Wireshark : mergecap et le flux EK sont simules,
    on verifie arguments, validations, gestion d'erreur, nettoyage et le
    contenu des lignes CSV / objets JSON ;
  - d'integration, avec les VRAIS mergecap/tshark/capinfos, sautes (skipif)
    s'ils ne sont pas dans le PATH : formats de sortie verifies par capinfos,
    nombre de lignes CSV == nombre de paquets ;
  - CLI : cablage de --convert / --convert-format (convert_capture simule).
"""

import csv
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from pcap_builders import epb, idb, shb, write_bytes

import cross_capture_analyzer_cli as analyzer_cli
import pcap_parser
import pcap_parser.convert as convert_mod
from pcap_parser.convert import CONVERT_FORMATS, CSV_DEFAULT_FIELDS, CSV_FIELDS, convert_capture
from pcap_parser.ek_source import EkRecord, TsharkError, TsharkNotFoundError

requires_tshark = pytest.mark.skipif(
    any(shutil.which(tool) is None for tool in ("tshark", "mergecap", "capinfos")),
    reason="tshark/mergecap/capinfos absents du PATH (paquet tshark)",
)

# ---------------------------------------------------------------------
# Fabriques (sans dependance a tshark)
# ---------------------------------------------------------------------


def _udp_frame(payload: bytes, ident: int = 1) -> bytes:
    """Trame Ethernet/IPv4/UDP 10.0.0.1:1000 -> 10.0.0.2:2000."""
    udp = struct.pack("!HHHH", 1000, 2000, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    )
    return bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00" + ip + udp


# Requete ARP « qui a 192.168.0.2 ? » : pas d'en-tete IP (build_packet la traite,
# mais un export « une ligne par paquet » doit aussi couvrir LLDP, STP, etc.).
_ARP_FRAME = bytes.fromhex("ffffffffffff11223344556608060001080006040001112233445566c0a80001000000000000c0a80002")

_PACKETS = [(1700000000.0, _udp_frame(b"a", 1)), (1700000000.5, _ARP_FRAME), (1700000001.25, _udp_frame(b"bb", 2))]


def _write_pcap(path: Path, packets=_PACKETS) -> str:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, round((ts - sec) * 1e6), len(data), len(data)))
            f.write(data)
    return str(path)


def _write_erf(path: Path, packets=_PACKETS) -> str:
    """ERF (Endace) ecrit a la main : en-tete 16 octets (timestamp 32.32 petit-
    boutiste, type 2 = Ethernet, rlen, lctr, wlen) + 2 octets de padding + trame."""
    with open(path, "wb") as f:
        for ts, data in packets:
            sec = int(ts)
            ts64 = (sec << 32) | round((ts - sec) * 2**32)
            payload = b"\x00\x00" + data
            f.write(struct.pack("<Q", ts64) + struct.pack(">BBHHH", 2, 0, 16 + len(payload), 0, len(payload)) + payload)
    return str(path)


def _capinfos(path, option: str) -> str:
    out = subprocess.run(["capinfos", option, str(path)], capture_output=True, text=True, check=True).stdout
    # capinfos ecrit d'abord « File name: <chemin> » : seule la DERNIERE ligne porte la valeur.
    return out.strip().splitlines()[-1].split(":", 1)[1].strip()


def _file_type(path) -> str:
    return _capinfos(path, "-t")


def _frames_with_ip(path) -> list[tuple[str, str]]:
    """(src, dst) des trames IP, lues par tshark -- independant du code teste."""
    out = subprocess.run(
        ["tshark", "-r", str(path), "-Y", "ip", "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [tuple(line.split("\t")) for line in out.splitlines()]


def _read_csv(path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------------
# Unitaires : validations
# ---------------------------------------------------------------------


@pytest.fixture
def entree(tmp_path):
    return _write_pcap(tmp_path / "in.pcap")


def test_api_publique_reexportee():
    assert pcap_parser.convert_capture is convert_capture
    assert "convert_capture" in pcap_parser.__all__
    import netcross_core

    assert netcross_core.convert_capture is convert_capture


def test_formats_supportes():
    assert CONVERT_FORMATS == ("pcap", "pcapng", "erf", "csv", "json")
    assert CSV_DEFAULT_FIELDS == ("timestamp", "src", "dst", "proto", "length")
    assert set(CSV_DEFAULT_FIELDS) <= set(CSV_FIELDS)


def test_format_inconnu(entree, tmp_path):
    with pytest.raises(ValueError, match="format doit valoir"):
        convert_capture(entree, str(tmp_path / "o.xyz"), format="xyz")
    assert not (tmp_path / "o.xyz").exists()


@pytest.mark.parametrize("fmt", ["pcap", "pcapng", "erf", "json"])
def test_fields_refuse_hors_csv(entree, tmp_path, fmt):
    with pytest.raises(ValueError, match="fields n'a de sens que pour format='csv'"):
        convert_capture(entree, str(tmp_path / "o"), format=fmt, fields=["src"])


@pytest.mark.parametrize("fields", [[], "src", ["src", "inconnue"]])
def test_fields_invalides(entree, tmp_path, fields):
    with pytest.raises(ValueError, match=r"fields|colonne"):
        convert_capture(entree, str(tmp_path / "o.csv"), format="csv", fields=fields)


def test_entree_absente(tmp_path):
    with pytest.raises(FileNotFoundError, match="introuvable"):
        convert_capture(str(tmp_path / "absent.pcap"), str(tmp_path / "o.pcapng"))


def test_sortie_identique_a_l_entree(entree):
    with pytest.raises(ValueError, match="fichier d'entree"):
        convert_capture(entree, entree, format="pcapng")
    assert Path(entree).stat().st_size > 0  # entree intacte


def test_repertoire_de_sortie_absent(entree, tmp_path):
    with pytest.raises(FileNotFoundError, match="repertoire de sortie"):
        convert_capture(entree, str(tmp_path / "nulle_part" / "o.pcapng"))


# ---------------------------------------------------------------------
# Unitaires : mergecap simule (formats de capture)
# ---------------------------------------------------------------------


class _FakeRun:
    def __init__(self, returncode: int = 0, stderr: str = "boom"):
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if self.returncode == 0:
            Path(args[args.index("-w") + 1]).write_bytes(b"contenu-converti")
        return subprocess.CompletedProcess(args, self.returncode, "", self.stderr)


@pytest.fixture
def fake_mergecap(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


@pytest.mark.parametrize("fmt", ["pcap", "pcapng", "erf"])
def test_formats_de_capture_appellent_mergecap_sur_un_seul_fichier(fake_mergecap, entree, tmp_path, fmt):
    out = tmp_path / f"o.{fmt}"
    convert_capture(entree, str(out), format=fmt)
    [call] = fake_mergecap.calls
    assert call[0] == "/usr/bin/mergecap"
    assert call[1:3] == ["-F", fmt]
    assert call[3] == "-w"
    assert call[5:] == [entree]  # UN seul fichier d'entree
    assert out.read_bytes() == b"contenu-converti"
    assert list(tmp_path.glob(".netcross-convert-*")) == []


def test_format_par_defaut_pcapng(fake_mergecap, entree, tmp_path):
    convert_capture(entree, str(tmp_path / "o"))
    assert fake_mergecap.calls[0][1:3] == ["-F", "pcapng"]


def test_intermediaire_dans_le_repertoire_de_sortie(fake_mergecap, entree, tmp_path):
    sortie = tmp_path / "sous"
    sortie.mkdir()
    convert_capture(entree, str(sortie / "o.pcapng"))
    tmp_arg = Path(fake_mergecap.calls[0][4])
    assert tmp_arg.parent.parent == sortie.resolve()  # meme FS que la sortie : os.replace atomique


def test_mergecap_absent(monkeypatch, entree, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(TsharkNotFoundError, match="mergecap"):
        convert_capture(entree, str(tmp_path / "o.pcapng"))
    assert not (tmp_path / "o.pcapng").exists()


def test_echec_mergecap_laisse_la_sortie_preexistante_intacte(monkeypatch, entree, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    fake = _FakeRun(returncode=2, stderr="not writable")
    monkeypatch.setattr(subprocess, "run", fake)
    out = tmp_path / "o.pcap"
    out.write_bytes(b"ancien")
    with pytest.raises(TsharkError, match="not writable") as exc_info:
        convert_capture(entree, str(out), format="pcap")
    assert exc_info.value.returncode == 2
    assert out.read_bytes() == b"ancien"
    assert list(tmp_path.glob(".netcross-convert-*")) == []


# ---------------------------------------------------------------------
# Unitaires : export CSV / JSON (flux EK simule)
# ---------------------------------------------------------------------


def _ek(number: int, iso: str, ts: float, protocols: str, length: int, **layers) -> EkRecord:
    frame = {
        "frame_frame_number": str(number),
        "frame_frame_time_epoch": iso,
        "frame_frame_protocols": protocols,
        "frame_frame_len": str(length),
    }
    return EkRecord(ts=ts, layers={"frame": frame, **layers})


_TCP = _ek(
    1,
    "2023-11-14T22:13:20.123456789Z",
    1700000000.123456789,
    "eth:ethertype:ip:tcp:tls",
    120,
    eth={"eth_eth_src": "aa:aa:aa:aa:aa:aa", "eth_eth_dst": "bb:bb:bb:bb:bb:bb"},
    ip={"ip_ip_src": "10.0.0.1", "ip_ip_dst": "10.0.0.2"},
    tcp={"tcp_tcp_srcport": "51000", "tcp_tcp_dstport": "443"},
)
_V6_UDP = _ek(
    2,
    "2023-11-14T22:13:21.000000000Z",
    1700000001.0,
    "eth:ethertype:ipv6:udp:data",
    90,
    eth={"eth_eth_src": "aa:aa:aa:aa:aa:aa", "eth_eth_dst": "bb:bb:bb:bb:bb:bb"},
    ipv6={"ipv6_ipv6_src": "fe80::1", "ipv6_ipv6_dst": "fe80::2"},
    udp={"udp_udp_srcport": "5353", "udp_udp_dstport": "5353"},
)
_ARP = _ek(
    3,
    "2023-11-14T22:13:22.500000000Z",
    1700000002.5,
    "eth:ethertype:arp",
    42,
    eth={"eth_eth_src": "11:22:33:44:55:66", "eth_eth_dst": "ff:ff:ff:ff:ff:ff"},
    arp={"arp_arp_opcode": "1"},
)
_SANS_FRAME = EkRecord(ts=1700000003.25, layers={})


@pytest.fixture
def ek_records(monkeypatch):
    """Remplace le flux tshark : convert_capture ne lance alors aucun outil."""
    records = [_TCP, _V6_UDP, _ARP]
    monkeypatch.setattr(convert_mod, "iter_ek_records", lambda **kwargs: iter(records))
    return records


def test_csv_par_defaut_une_ligne_par_paquet_et_colonnes_de_l_issue(ek_records, entree, tmp_path):
    out = tmp_path / "o.csv"
    convert_capture(entree, str(out), format="csv")
    assert out.read_text(encoding="utf-8").splitlines()[0] == "timestamp,src,dst,proto,length"
    rows = _read_csv(out)
    assert len(rows) == len(ek_records)  # paquet non IP (ARP) compris
    assert rows[0] == {
        "timestamp": "1700000000.123456789",  # 9 decimales exactes, pas de derive flottante
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "proto": "tls",
        "length": "120",
    }
    assert (rows[1]["src"], rows[1]["dst"]) == ("fe80::1", "fe80::2")
    assert rows[1]["proto"] == "udp"  # « data » (charge non disseque) ecarte
    assert rows[2] == {
        "timestamp": "1700000002.500000000",
        "src": "11:22:33:44:55:66",  # pas d'IP : repli sur la MAC
        "dst": "ff:ff:ff:ff:ff:ff",
        "proto": "arp",
        "length": "42",
    }


def test_csv_champs_choisis_dans_l_ordre_demande(ek_records, entree, tmp_path):
    out = tmp_path / "o.csv"
    convert_capture(entree, str(out), format="csv", fields=["length", "frame_number", "sport", "dport", "src"])
    assert out.read_text(encoding="utf-8").splitlines()[0] == "length,frame_number,sport,dport,src"
    rows = _read_csv(out)
    assert rows[0] == {"length": "120", "frame_number": "1", "sport": "51000", "dport": "443", "src": "10.0.0.1"}
    assert rows[1]["sport"] == "5353"  # UDP
    assert (rows[2]["sport"], rows[2]["dport"]) == ("", "")  # ARP : pas de port


def test_csv_paquet_sans_couche_frame_ne_plante_pas(monkeypatch, entree, tmp_path):
    monkeypatch.setattr(convert_mod, "iter_ek_records", lambda **kwargs: iter([_SANS_FRAME]))
    out = tmp_path / "o.csv"
    convert_capture(entree, str(out), format="csv", fields=list(CSV_FIELDS))
    [row] = _read_csv(out)
    assert row["timestamp"] == "1700000003.250000"  # repli sur EkRecord.ts
    assert (row["src"], row["dst"], row["proto"], row["length"]) == ("", "", "", "")


def test_csv_capture_vide_ne_contient_que_l_en_tete(monkeypatch, entree, tmp_path):
    monkeypatch.setattr(convert_mod, "iter_ek_records", lambda **kwargs: iter([]))
    out = tmp_path / "o.csv"
    convert_capture(entree, str(out), format="csv")
    assert out.read_text(encoding="utf-8") == "timestamp,src,dst,proto,length\n"


def test_json_un_objet_par_paquet_avec_tous_les_champs_ek(ek_records, entree, tmp_path):
    out = tmp_path / "o.json"
    convert_capture(entree, str(out), format="json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == len(ek_records)
    assert [p["frame_number"] for p in data] == [1, 2, 3]
    assert data[0]["timestamp"] == "1700000000.123456789"
    assert data[0]["layers"] == _TCP.layers  # champs EK repris tels quels
    assert data[2]["layers"]["arp"] == {"arp_arp_opcode": "1"}


def test_json_capture_vide_reste_un_json_valide(monkeypatch, entree, tmp_path):
    monkeypatch.setattr(convert_mod, "iter_ek_records", lambda **kwargs: iter([]))
    out = tmp_path / "o.json"
    convert_capture(entree, str(out), format="json")
    assert json.loads(out.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("fmt", ["csv", "json"])
def test_export_structure_echec_tshark_laisse_la_sortie_intacte(monkeypatch, entree, tmp_path, fmt):
    def echoue(**kwargs):
        yield _TCP  # un premier paquet est deja ecrit dans l'intermediaire...
        raise TsharkError("tshark a echoue", returncode=2)

    monkeypatch.setattr(convert_mod, "iter_ek_records", echoue)
    out = tmp_path / f"o.{fmt}"
    out.write_text("ancien", encoding="utf-8")
    with pytest.raises(TsharkError):
        convert_capture(entree, str(out), format=fmt)
    assert out.read_text(encoding="utf-8") == "ancien"  # ...mais la sortie n'est jamais partielle
    assert list(tmp_path.glob(".netcross-convert-*")) == []


def test_export_structure_tshark_absent(entree, tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        convert_capture(entree, str(tmp_path / "o.csv"), format="csv")
    assert not (tmp_path / "o.csv").exists()


# ---------------------------------------------------------------------
# Integration : vrais outils Wireshark
# ---------------------------------------------------------------------


@requires_tshark
def test_pcap_vers_pcapng_format_verifie_par_capinfos(tmp_path):
    src = _write_pcap(tmp_path / "in.pcap")
    out = tmp_path / "out.pcapng"
    convert_capture(src, str(out), format="pcapng")
    assert "pcapng" in _file_type(out)
    assert _capinfos(out, "-c") == "3"
    assert _frames_with_ip(out) == [("10.0.0.1", "10.0.0.2")] * 2  # paquets et ordre conserves


@requires_tshark
def test_pcapng_vers_pcap(tmp_path):
    pcapng = tmp_path / "mid.pcapng"
    convert_capture(_write_pcap(tmp_path / "in.pcap"), str(pcapng), format="pcapng")
    out = tmp_path / "out.pcap"
    convert_capture(str(pcapng), str(out), format="pcap")
    assert _file_type(out).endswith("pcap") and "pcapng" not in _file_type(out)
    assert _capinfos(out, "-c") == "3"


@requires_tshark
def test_pcap_vers_erf(tmp_path):
    out = tmp_path / "out.erf"
    convert_capture(_write_pcap(tmp_path / "in.pcap"), str(out), format="erf")
    assert "ERF" in _file_type(out)
    assert _frames_with_ip(out) == [("10.0.0.1", "10.0.0.2")] * 2


@requires_tshark
@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_erf_en_entree(tmp_path, fmt):
    src = _write_erf(tmp_path / "in.erf")
    out = tmp_path / f"out.{fmt}"
    convert_capture(src, str(out), format=fmt)
    assert _capinfos(out, "-c") == "3"
    assert _frames_with_ip(out) == [("10.0.0.1", "10.0.0.2")] * 2


@requires_tshark
def test_conversion_impossible_pour_wireshark_erreur_propre_et_aucune_sortie(tmp_path):
    """pcapng a deux types de liaison -> pcap : refuse par Wireshark lui-meme."""
    src = tmp_path / "multi.pcapng"
    write_bytes(
        src, shb(), idb(1), idb(101), epb(_udp_frame(b"a"), 1_000_000, 0), epb(_udp_frame(b"a")[14:], 2_000_000, 1)
    )
    out = tmp_path / "out.pcap"
    out.write_bytes(b"ancien")
    with pytest.raises(TsharkError, match="mergecap a echoue"):
        convert_capture(str(src), str(out), format="pcap")
    assert out.read_bytes() == b"ancien"
    assert list(tmp_path.glob(".netcross-convert-*")) == []


@requires_tshark
def test_entree_illisible_pour_wireshark(tmp_path):
    src = tmp_path / "corrompu.pcap"
    src.write_bytes(b"ceci n'est pas une capture")
    out = tmp_path / "out.pcapng"
    with pytest.raises(TsharkError):
        convert_capture(str(src), str(out), format="pcapng")
    assert not out.exists()


@requires_tshark
def test_csv_nombre_de_lignes_egal_nombre_de_paquets(tmp_path):
    src = _write_pcap(tmp_path / "in.pcap")
    out = tmp_path / "out.csv"
    convert_capture(src, str(out), format="csv")
    rows = _read_csv(out)
    assert len(rows) == int(_capinfos(src, "-c"))  # 3, ARP compris
    assert [r["proto"] for r in rows] == ["udp", "arp", "udp"]
    assert [r["length"] for r in rows] == [str(len(d)) for _ts, d in _PACKETS]
    assert [r["timestamp"] for r in rows] == ["1700000000.000000000", "1700000000.500000000", "1700000001.250000000"]
    assert (rows[0]["src"], rows[0]["dst"]) == ("10.0.0.1", "10.0.0.2")
    assert (rows[1]["src"], rows[1]["dst"]) == ("11:22:33:44:55:66", "ff:ff:ff:ff:ff:ff")


@requires_tshark
def test_json_nombre_d_objets_egal_nombre_de_paquets(tmp_path):
    src = _write_pcap(tmp_path / "in.pcap")
    out = tmp_path / "out.json"
    convert_capture(src, str(out), format="json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [p["frame_number"] for p in data] == [1, 2, 3]
    assert data[0]["layers"]["ip"]["ip_ip_src"] == "10.0.0.1"
    assert data[1]["layers"]["arp"]["arp_arp_opcode"] == "1"


@requires_tshark
def test_csv_depuis_erf(tmp_path):
    out = tmp_path / "out.csv"
    convert_capture(_write_erf(tmp_path / "in.erf"), str(out), format="csv")
    assert len(_read_csv(out)) == 3


# ---------------------------------------------------------------------
# CLI : cross_capture_analyzer_cli.py --convert
# ---------------------------------------------------------------------


def _run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *args])
    analyzer_cli.main()


@pytest.fixture
def convert_spy(monkeypatch):
    calls = []
    monkeypatch.setattr(
        analyzer_cli, "convert_capture", lambda src, out, format="pcapng": calls.append((src, out, format))
    )

    def analyse_interdite(*_a, **_k):
        raise AssertionError("--convert ne doit lancer AUCUNE analyse")

    monkeypatch.setattr(analyzer_cli, "parse_capture", analyse_interdite)
    monkeypatch.setattr(analyzer_cli, "parse_captures_parallel", analyse_interdite)
    return calls


@pytest.mark.parametrize(
    ("sortie", "attendu"),
    [
        ("o.pcap", "pcap"),
        ("o.PCAPNG", "pcapng"),
        ("o.erf", "erf"),
        ("o.csv", "csv"),
        ("o.json", "json"),
        ("o.bin", "pcapng"),  # inconnu -> pcapng, comme --merge
        ("sans_extension", "pcapng"),
    ],
)
def test_cli_format_deduit_de_l_extension(monkeypatch, capsys, convert_spy, sortie, attendu):
    _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--convert", sortie)
    assert convert_spy == [("a.pcap", sortie, attendu)]
    assert f"a.pcap converti en {attendu} dans {sortie}." in capsys.readouterr().out


def test_cli_convert_format_prime_sur_l_extension(monkeypatch, convert_spy):
    _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--convert", "paquets.txt", "--convert-format", "csv")
    assert convert_spy == [("a.pcap", "paquets.txt", "csv")]


@pytest.mark.parametrize(
    ("args", "fragment"),
    [
        (["--capture", "LAN=a.pcap", "--convert-format", "csv"], "--convert-format necessite --convert"),
        (["--live", "LAN:eth0", "--convert", "o.pcap"], "--convert necessite --capture"),
        (["--capture", "LAN=a.pcap,b.pcap", "--convert", "o.pcap"], "exactement un fichier de capture (recu 2"),
        (["--capture", "LAN=a.pcap", "--capture", "WAN=b.pcap", "--convert", "o.pcap"], "exactement un fichier"),
        (["--capture", "LAN=a.pcap", "--convert", "o.pcap", "--merge", "m.pcap"], "--convert est exclusif"),
        (["--capture", "LAN=a.pcap", "--convert", "o.pcap", "--split", "count:10"], "--convert est exclusif"),
        (["--capture", "LAN=a.pcap", "--convert", "o.pcap", "--replay", "eth0"], "--convert est exclusif"),
        (
            ["--capture", "LAN=a.pcap", "--convert", "o.pcap", "--pdf-report", "r.pdf", "--triage"],
            "incompatible avec --pdf-report, --triage",
        ),
        (["--capture", "LAN=a.pcap", "--convert", "o.pcap", "--parallel"], "incompatible avec --parallel"),
    ],
)
def test_cli_convert_arguments_invalides(monkeypatch, capsys, convert_spy, args, fragment):
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, *args)
    assert exc_info.value.code == 1
    assert fragment in capsys.readouterr().err
    assert convert_spy == []


def test_cli_convert_format_hors_liste_refuse_par_argparse(monkeypatch, capsys, convert_spy):
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--convert", "o.x", "--convert-format", "pdf")
    assert exc_info.value.code == 2  # erreur d'usage argparse
    assert "invalid choice" in capsys.readouterr().err
    assert convert_spy == []


@pytest.mark.parametrize(
    "erreur",
    [
        FileNotFoundError("capture absente"),
        ValueError("sortie == entree"),
        TsharkNotFoundError("mergecap absent"),
        TsharkError("echec"),
    ],
)
def test_cli_convert_erreur_de_conversion_sortie_propre(monkeypatch, capsys, erreur):
    def echoue(src, out, format="pcapng"):
        raise erreur

    monkeypatch.setattr(analyzer_cli, "convert_capture", echoue)
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "--capture", "LAN=a.pcap", "--convert", "o.pcapng")
    assert exc_info.value.code == 1
    assert f"--convert : {erreur}" in capsys.readouterr().err


@requires_tshark
def test_cli_convert_bout_en_bout_avec_les_vrais_outils(monkeypatch, capsys, tmp_path):
    src = _write_pcap(tmp_path / "in.pcap")
    _run_cli(monkeypatch, "--capture", f"LAN={src}", "--convert", str(tmp_path / "out.pcapng"))
    assert "pcapng" in _file_type(tmp_path / "out.pcapng")
    _run_cli(monkeypatch, "--capture", f"LAN={src}", "--convert", str(tmp_path / "out.csv"))
    assert len(_read_csv(tmp_path / "out.csv")) == 3
    assert "converti en csv" in capsys.readouterr().out
