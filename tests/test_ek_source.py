"""
pcap_parser.ek_source -- couche 1 (subprocess tshark). tshark n'etant
disponible dans aucun des environnements ou ce projet a ete developpe
jusqu'ici (voir claude.md, Sessions 1/3/4/5, "tshark non disponible dans
cet environnement" repete a chaque session), on teste ici uniquement les
fonctions pures qui ne lancent pas de sous-processus : parsing du
timestamp nanoseconde, filtrage du flux NDJSON, et construction des
arguments de la ligne de commande (avec tshark simule via monkeypatch).

_resolve_live_source (Job 46, issue #166) fait exception : les noms de
preference exacts pour sshdump (extcap.sshdump.remotehost, etc., voir
son docstring) ont ete verifies empiriquement contre un vrai tshark
4.2.2 -- les tests marques _tshark_reel ci-dessous rejouent cette
verification (arguments acceptes, pas d'erreur "unrecognized option"/
"unknown preference") et sont sautes si tshark est absent.
"""

import io
import shutil

import pytest

from pcap_parser.ek_source import (
    InvalidCaptureSourceError,
    TsharkNotFoundError,
    _build_args,
    _iter_ndjson_records,
    _parse_frame_time_epoch,
    _resolve_live_source,
)

_tshark_reel = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent de cet environnement")

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


# -- _resolve_live_source (Job 46, issue #166) -------------------------------


def test_resolve_live_source_interface_locale_inchangee():
    # comportement historique (avant #166) : une interface locale ("eth0",
    # "any"...) passe telle quelle, sans pref -o supplementaire.
    assert _resolve_live_source("eth0") == ("eth0", [])
    assert _resolve_live_source("any") == ("any", [])


@pytest.mark.parametrize("pipe_source", ["-", "pipe://", "pipe"])
def test_resolve_live_source_pipe(pipe_source):
    assert _resolve_live_source(pipe_source) == ("-", [])


def test_resolve_live_source_rpcap_transmise_telle_quelle():
    # rpcap:// est nativement compris par tshark/dumpcap -- on ne le
    # reconstruit pas, on le VALIDE puis le transmet tel quel.
    source = "rpcap://192.168.1.10:2002/eth0"
    assert _resolve_live_source(source) == (source, [])


@pytest.mark.parametrize(
    "source",
    [
        "rpcap://:2002/eth0",  # hote manquant
        "rpcap://192.168.1.10/eth0",  # port manquant
        "rpcap://192.168.1.10:2002/",  # interface distante manquante
        "rpcap://192.168.1.10:2002",  # idem (pas de / du tout)
        "rpcap://192.168.1.10:70000/eth0",  # port hors plage
        "rpcap://192.168.1.10:0/eth0",  # port hors plage (0 exclu)
    ],
)
def test_resolve_live_source_rpcap_invalide(source):
    with pytest.raises(InvalidCaptureSourceError):
        _resolve_live_source(source)


def test_resolve_live_source_ssh_complet():
    interface, prefs = _resolve_live_source("ssh://admin:s3cr%40t@192.168.1.20:2222/eth1")
    assert interface == "sshdump"
    assert prefs == [
        "extcap.sshdump.remotehost:192.168.1.20",
        "extcap.sshdump.remoteport:2222",
        "extcap.sshdump.remoteusername:admin",
        # le mot de passe est url-decode : "%40" -> "@"
        "extcap.sshdump.remotepassword:s3cr@t",
        "extcap.sshdump.remoteinterface:eth1",
    ]


def test_resolve_live_source_ssh_minimal_hote_et_interface_seuls():
    # sans utilisateur/mot de passe (agent SSH / cle par defaut) ni port
    # explicite (defaut 22, comme le -o extcap.sshdump.remoteport de
    # sshdump lui-meme).
    interface, prefs = _resolve_live_source("ssh://192.168.1.20/eth1")
    assert interface == "sshdump"
    assert prefs == [
        "extcap.sshdump.remotehost:192.168.1.20",
        "extcap.sshdump.remoteport:22",
        "extcap.sshdump.remoteinterface:eth1",
    ]
    assert not any("username" in p or "password" in p for p in prefs)


def test_resolve_live_source_ssh_sans_interface_distante():
    # l'interface distante est optionnelle cote parsing (sshdump utilise
    # sa propre interface par defaut si absente) -- seuls hote et port
    # sont obligatoires.
    interface, prefs = _resolve_live_source("ssh://192.168.1.20")
    assert interface == "sshdump"
    assert prefs == ["extcap.sshdump.remotehost:192.168.1.20", "extcap.sshdump.remoteport:22"]


@pytest.mark.parametrize(
    "source",
    [
        "ssh://:2222/eth1",  # hote manquant
        "ssh://192.168.1.20:70000/eth1",  # port hors plage
        "ssh://192.168.1.20:abc/eth1",  # port non numerique
    ],
)
def test_resolve_live_source_ssh_invalide(source):
    with pytest.raises(InvalidCaptureSourceError):
        _resolve_live_source(source)


def test_build_args_mode_live_source_rpcap(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(interface="rpcap://192.168.1.10:2002/eth0")
    assert args[args.index("-i") + 1] == "rpcap://192.168.1.10:2002/eth0"
    # aucune pref extcap.sshdump.* -- rpcap n'en a pas besoin
    assert not any("extcap.sshdump" in a for a in args)


def test_build_args_mode_live_source_ssh(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(interface="ssh://admin:secret@10.0.0.5/eth0", bpf_filter="tcp port 22")
    # sshdump est l'interface EXTCAP -- pas l'URL ssh:// telle quelle
    assert args[args.index("-i") + 1] == "sshdump"
    assert "extcap.sshdump.remotehost:10.0.0.5" in args
    assert "extcap.sshdump.remoteusername:admin" in args
    assert "extcap.sshdump.remotepassword:secret" in args
    assert "extcap.sshdump.remoteinterface:eth0" in args
    # le filtre bpf standard reste applique normalement (independant du
    # remote-filter propre a sshdump, non gere par ce module)
    assert args[args.index("-f") + 1] == "tcp port 22"


def test_build_args_mode_live_source_pipe(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    args = _build_args(interface="-")
    assert args[args.index("-i") + 1] == "-"


def test_build_args_source_invalide_leve_avant_tout_subprocess(monkeypatch):
    # la validation doit echouer AVANT meme la resolution du chemin
    # tshark -- on le verifie en s'assurant qu'aucun appel a shutil.which
    # n'a besoin de reussir pour que l'erreur soit levee (ordre des
    # operations dans _build_args : _tshark_path() est appele en premier,
    # donc on garde shutil.which fonctionnel ici et on verifie juste le
    # type d'exception, InvalidCaptureSourceError etant une ValueError).
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    with pytest.raises(InvalidCaptureSourceError):
        _build_args(interface="rpcap://host-sans-port/eth0")


# -- _resolve_live_source / _build_args, tshark reel (Job 46, #166) ----------
#
# Verifient contre le VRAI binaire (installe pour cette session, cf.
# docstring de fichier) que les arguments construits sont *acceptes* par
# tshark 4.2.2 : aucun "unrecognized option" ni "unknown preference" sur
# stderr. On ne verifie pas la capture elle-meme (pas de serveur
# rpcap/SSH reel disponible ici) -- seulement que tshark reconnait la
# forme des arguments, ce qui est justement le point le plus fragile
# (cf. l'ecart constate entre la syntaxe suggeree par l'issue et celle
# reellement acceptee, documente dans _resolve_ssh_source).


@_tshark_reel
def test_tshark_reel_accepte_les_prefs_sshdump():
    import subprocess

    args = _build_args(interface="ssh://admin:secret@203.0.113.5/eth0")
    args += ["-w", "/tmp/test_resolve_live_source_sshdump.pcap"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=2)
        stderr = proc.stderr
    except subprocess.TimeoutExpired as e:
        # attendu : 203.0.113.5 (TEST-NET-3, RFC 5737) ne repond jamais --
        # le timeout confirme que tshark a depasse la phase de parsing des
        # arguments et tente reellement la connexion SSH.
        stderr = (e.stderr or "") if isinstance(e.stderr, str) else (e.stderr or b"").decode(errors="replace")
    assert "unrecognized option" not in stderr
    assert "unknown preference" not in stderr
    assert "Invalid -o flag" not in stderr


@_tshark_reel
def test_tshark_reel_accepte_rpcap():
    import subprocess

    args = _build_args(interface="rpcap://203.0.113.5:2002/eth0")
    proc = subprocess.run(args, capture_output=True, text=True, timeout=5)
    # pas de serveur rpcapd reel : tshark doit echouer sur le DEVICE
    # ("no device named"), jamais sur la SYNTAXE de l'argument -i.
    assert "unrecognized option" not in proc.stderr
    assert proc.returncode != 0
    assert "no device named" in proc.stderr.lower() or "no such device" in proc.stderr.lower()


@_tshark_reel
def test_tshark_reel_accepte_pipe():
    import subprocess

    args = _build_args(interface="-")
    proc = subprocess.run(args, input="", capture_output=True, text=True, timeout=5)
    assert "unrecognized option" not in proc.stderr
    assert proc.returncode != 0  # pas de flux pcap valide sur stdin vide
