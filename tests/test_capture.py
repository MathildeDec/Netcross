"""
pcap_parser.capture -- couche d'orchestration. On monkeypatch
iter_ek_records (jamais tshark lui-meme, cf. les autres fichiers de
test) pour verifier le cablage : gestion d'erreur, arret propre en
live, restauration de l'ordre d'entree en parallele.
"""

import pcap_parser.capture as capture_mod
from pcap_parser.ek_source import EkRecord, TsharkError, TsharkNotFoundError


def _record(ts=1.0, src="1.1.1.1", dst="2.2.2.2"):
    return EkRecord(
        ts=ts,
        layers={
            "ip": {"ip_ip_src": src, "ip_ip_dst": dst},
            "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2", "tcp_tcp_seq_raw": "0"},
        },
    )


# -- parse_capture ------------------------------------------------------------


def test_parse_capture_construit_les_raw_packets(monkeypatch):
    monkeypatch.setattr(capture_mod, "iter_ek_records", lambda path: iter([_record(), _record(ts=2.0)]))
    pkts = capture_mod.parse_capture("fichier.pcapng")
    assert len(pkts) == 2
    assert pkts[0].ts == 1.0 and pkts[1].ts == 2.0


def test_parse_capture_avale_erreur_par_defaut(monkeypatch, capsys):
    def boom(path):
        raise TsharkNotFoundError("absent")
        yield  # pragma: no cover -- fait de boom un generateur

    monkeypatch.setattr(capture_mod, "iter_ek_records", boom)
    result = capture_mod.parse_capture("fichier.pcapng")
    assert result == []
    assert "fichier.pcapng" in capsys.readouterr().err


def test_parse_capture_relaie_si_raise_on_error(monkeypatch):
    import pytest

    def boom(path):
        raise TsharkError("echec")
        yield  # pragma: no cover

    monkeypatch.setattr(capture_mod, "iter_ek_records", boom)
    with pytest.raises(TsharkError):
        capture_mod.parse_capture("fichier.pcapng", raise_on_error=True)


def test_parse_capture_ignore_les_paquets_non_decodables(monkeypatch):
    # une couche EK ni IP, ni ARP, ni STP -> build_packet renvoie None
    # (LLDP, CDP...). ARP (Session 24) et STP (Session 25), eux, sont
    # desormais decodes -- voir test_parsing_adapter.py/test_packet.py
    # pour la couverture ARP/STP dediee.
    monkeypatch.setattr(capture_mod, "iter_ek_records", lambda path: iter([EkRecord(ts=1.0, layers={"lldp": {}})]))
    assert capture_mod.parse_capture("fichier.pcapng") == []


# -- iter_live -----------------------------------------------------------------


def test_iter_live_yield_au_fil_de_l_eau(monkeypatch):
    monkeypatch.setattr(
        capture_mod,
        "iter_ek_records",
        lambda interface, bpf_filter=None, stop_event=None: iter([_record(), _record(ts=2.0)]),
    )
    pkts = list(capture_mod.iter_live("eth0"))
    assert len(pkts) == 2


def test_iter_live_transmet_interface_et_filtre(monkeypatch):
    captured_args = {}

    def fake_iter(interface, bpf_filter=None, stop_event=None):
        captured_args["interface"] = interface
        captured_args["bpf_filter"] = bpf_filter
        captured_args["stop_event"] = stop_event
        return iter([])

    monkeypatch.setattr(capture_mod, "iter_ek_records", fake_iter)
    sentinel = object()
    list(capture_mod.iter_live("eth0", bpf_filter="tcp", stop_event=sentinel))
    assert captured_args == {"interface": "eth0", "bpf_filter": "tcp", "stop_event": sentinel}


def test_iter_live_s_arrete_proprement_si_l_appelant_casse_la_boucle(monkeypatch):
    def fake_iter(interface, bpf_filter=None, stop_event=None):
        yield _record(ts=1.0)
        yield _record(ts=2.0)
        raise AssertionError("ne doit pas etre consomme apres le break")

    monkeypatch.setattr(capture_mod, "iter_ek_records", fake_iter)
    gen = capture_mod.iter_live("eth0")
    first = next(gen)
    assert first.ts == 1.0
    gen.close()  # simule l'arret du generateur cote appelant


# -- parse_captures_parallel : ordre restaure + stats toujours presentes ------
# _parse_capture_timed doit rester une fonction de MODULE (picklable pour
# ProcessPoolExecutor) : on la remplace par une fonction top-level, elle
# aussi picklable, plutot qu'une closure/lambda.


def _fake_parse_capture_timed(label, path):
    if path == "echoue.pcapng":
        raise ValueError("pcap corrompu")
    return [object()] * len(path), 0.01


def test_parse_captures_parallel_restaure_l_ordre_et_gere_les_echecs(monkeypatch):
    monkeypatch.setattr(capture_mod, "_parse_capture_timed", _fake_parse_capture_timed)
    captures = [("C", "c.pcapng"), ("A", "a.pcapng"), ("B", "echoue.pcapng")]
    _all_packets, stats = capture_mod.parse_captures_parallel(captures, max_workers=2)

    # l'ordre des stats doit correspondre a l'ordre d'entree, pas a l'ordre
    # d'achevement des taches paralleles
    assert [s["label"] for s in stats] == ["C", "A", "B"]
    assert stats[2]["error"] is not None and "ValueError" in stats[2]["error"]
    assert stats[2]["count"] == 0
    assert stats[0]["count"] == len("c.pcapng")
