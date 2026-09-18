"""
pcap_parser.ek_source -- couche 1 (subprocess tshark). tshark n'etant
disponible dans aucun des environnements ou ce projet a ete developpe
jusqu'ici (voir claude.md, Sessions 1/3/4/5, "tshark non disponible dans
cet environnement" repete a chaque session), on teste ici uniquement les
fonctions pures qui ne lancent pas de sous-processus : parsing du
timestamp nanoseconde, filtrage du flux NDJSON, et construction des
arguments de la ligne de commande (avec tshark simule via monkeypatch).
"""

import io

import pytest

from pcap_parser.ek_source import (
    TsharkNotFoundError,
    _build_args,
    _iter_ndjson_records,
    _parse_frame_time_epoch,
)

# -- _parse_frame_time_epoch -------------------------------------------


def test_parse_frame_time_epoch_nanoseconde():
    # verification independante via calendar.timegm plutot qu'un epoch
    # code en dur (fragile face aux erreurs de calcul manuel) :
    import calendar
    import datetime

    ts = _parse_frame_time_epoch("2026-08-20T20:19:51.632525000Z")
    expected_int = calendar.timegm(datetime.datetime(2026, 8, 20, 20, 19, 51, tzinfo=datetime.timezone.utc).timetuple())
    assert ts == pytest.approx(expected_int + 0.632525, abs=1e-6)


def test_parse_frame_time_epoch_sans_z_final():
    assert _parse_frame_time_epoch("2026-08-20T20:19:51.000000000") is not None


def test_parse_frame_time_epoch_none_ou_vide():
    assert _parse_frame_time_epoch(None) is None
    assert _parse_frame_time_epoch("") is None


def test_parse_frame_time_epoch_format_invalide():
    assert _parse_frame_time_epoch("pas-une-date") is None


def test_parse_frame_time_epoch_fraction_courte_completee_a_droite():
    # "123" nanosecondes -> 123 000 000 ns, pas 000 000 123 ns
    ts_court = _parse_frame_time_epoch("2026-01-01T00:00:00.123Z")
    ts_long = _parse_frame_time_epoch("2026-01-01T00:00:00.123000000Z")
    assert ts_court == ts_long


# -- _iter_ndjson_records -------------------------------------------------


def test_iter_ndjson_records_filtre_les_lignes_index():
    stream = io.StringIO(
        '{"index": {}}\n'
        '{"layers": {"ip": {}}, "timestamp": "1"}\n'
        '{"index": {}}\n'
        '{"layers": {"tcp": {}}, "timestamp": "2"}\n'
    )
    records = list(_iter_ndjson_records(stream))
    assert len(records) == 2
    assert records[0]["layers"] == {"ip": {}}
    assert records[1]["layers"] == {"tcp": {}}


def test_iter_ndjson_records_ignore_les_lignes_vides():
    stream = io.StringIO('\n\n{"layers": {}}\n\n')
    records = list(_iter_ndjson_records(stream))
    assert len(records) == 1


def test_iter_ndjson_records_ligne_corrompue_ne_casse_pas_le_flux():
    stream = io.StringIO('{"layers": {"a": 1}}\n{ceci n\'est pas du json\n{"layers": {"a": 2}}\n')
    records = list(_iter_ndjson_records(stream))
    assert [r["layers"]["a"] for r in records] == [1, 2]


# -- _build_args ------------------------------------------------------------


def test_build_args_exige_path_ou_interface_pas_les_deux():
    with pytest.raises(ValueError):
        _build_args()
    with pytest.raises(ValueError):
        _build_args(path="a.pcapng", interface="eth0")


def test_build_args_leve_si_tshark_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        _build_args(path="a.pcapng")


def test_build_args_mode_fichier(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(path="a.pcapng")
    assert args[0] == "/usr/bin/tshark"
    assert "-r" in args and args[args.index("-r") + 1] == "a.pcapng"
    assert "-T" in args and args[args.index("-T") + 1] == "ek"
    # rtp.heuristic_rtp:TRUE doit toujours etre active par defaut
    assert "rtp.heuristic_rtp:TRUE" in args


def test_build_args_mode_live_avec_filtre_bpf(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(interface="eth0", bpf_filter="tcp port 443")
    assert "-i" in args and args[args.index("-i") + 1] == "eth0"
    assert "-f" in args and args[args.index("-f") + 1] == "tcp port 443"
    assert "-l" in args  # flush ligne par ligne, indispensable en live
