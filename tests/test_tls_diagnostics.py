"""
netcross_core.tls_diagnostics -- parsing bas niveau de messages TLS
construits a la main (memes principes que la validation manuelle
decrite dans claude.md Session 3 : "ClientHello TLS minimal... injecte")
et logique de diagnostic multi-points (build_handshake_status/diagnose_tls).
"""

import struct

from netcross_core.tls_diagnostics import (
    HandshakeStatus,
    TlsEvent,
    build_handshake_status,
    diagnose_tls,
    parse_alert,
    parse_client_hello,
    parse_server_hello,
)


def _u16(v):
    return struct.pack("!H", v)


def _client_hello(sni: str | None = "example.com", version=(3, 3)) -> bytes:
    body = bytes(version)  # client_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id_len = 0
    body += _u16(2) + b"\x13\x01"  # cipher_suites (len=2, 1 suite)
    body += b"\x01\x00"  # compression_methods (len=1, null)

    extensions = b""
    if sni is not None:
        name = sni.encode()
        server_name_entry = b"\x00" + _u16(len(name)) + name  # type=host_name(0)
        ext_body = _u16(len(server_name_entry)) + server_name_entry
        extensions += _u16(0) + _u16(len(ext_body)) + ext_body  # extension type 0 = server_name

    body += _u16(len(extensions)) + extensions
    return body


def _server_hello(version=(3, 3), cipher=0x1301) -> bytes:
    body = bytes(version)
    body += b"\x00" * 32
    body += b"\x00"  # session_id_len
    body += _u16(cipher)
    return body


# -- parse_client_hello -----------------------------------------------------


def test_parse_client_hello_extrait_sni_et_version():
    result = parse_client_hello(_client_hello(sni="example.com"))
    assert result["tls_version"] == "TLS 1.2"
    assert result["sni"] == "example.com"


def test_parse_client_hello_sans_sni():
    result = parse_client_hello(_client_hello(sni=None))
    assert result["sni"] is None


def test_parse_client_hello_trop_court_renvoie_dict_vide():
    assert parse_client_hello(b"\x03\x03") == {}


def test_parse_client_hello_tls13_version_str():
    result = parse_client_hello(_client_hello(sni=None, version=(3, 4)))
    assert result["tls_version"] == "TLS 1.3"


# -- parse_server_hello -------------------------------------------------------


def test_parse_server_hello_cipher_et_version():
    result = parse_server_hello(_server_hello(cipher=0x1301))
    assert result["tls_version"] == "TLS 1.2"
    assert result["cipher"] == "0x1301"


def test_parse_server_hello_trop_court():
    assert parse_server_hello(b"\x03\x03") == {}


# -- parse_alert --------------------------------------------------------------


def test_parse_alert_fatal_handshake_failure():
    result = parse_alert(bytes([2, 40]))
    assert result == {"level": "fatal", "description": "handshake_failure"}


def test_parse_alert_warning_close_notify():
    result = parse_alert(bytes([1, 0]))
    assert result == {"level": "warning", "description": "close_notify"}


def test_parse_alert_code_inconnu():
    result = parse_alert(bytes([1, 250]))
    assert result["description"] == "unknown(250)"


def test_parse_alert_trop_court():
    assert parse_alert(b"\x01") == {}


# -- build_handshake_status ----------------------------------------------------


def _ev(**overrides) -> TlsEvent:
    defaults = {
        "point": "A",
        "ts": 0.0,
        "src": "10.0.0.1",
        "sport": 50000,
        "dst": "10.0.0.2",
        "dport": 443,
        "record_type": "handshake",
    }
    defaults.update(overrides)
    return TlsEvent(**defaults)


def test_handshake_status_verdict_no_handshake_seen_par_defaut():
    st = HandshakeStatus(point="A", flow_id="x")
    assert st.verdict == "no_handshake_seen"


def test_handshake_status_verdict_progresse_client_hello_puis_complete():
    events = [
        _ev(ts=0.0, handshake_type="client_hello", sni="example.com"),
        _ev(ts=0.1, handshake_type="server_hello", tls_version="TLS 1.2"),
        _ev(ts=0.2, record_type="application_data"),
    ]
    status = build_handshake_status(events)
    st = status["A"][next(iter(status["A"]))]
    assert st.verdict == "complete"
    assert st.sni == "example.com"


def test_handshake_status_client_hello_no_reply():
    events = [_ev(ts=0.0, handshake_type="client_hello", sni="example.com")]
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.verdict == "client_hello_no_reply"


def test_handshake_status_alert_fatal_prioritaire_sur_application_data():
    events = [
        _ev(ts=0.0, handshake_type="client_hello"),
        _ev(ts=0.1, handshake_type="server_hello"),
        _ev(ts=0.2, record_type="alert", alert_level="fatal", alert_description="bad_certificate"),
    ]
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.verdict == "alert_fatal:bad_certificate"


def test_handshake_status_flux_bidirectionnel_meme_flow_id():
    # meme flux vu dans les deux sens (client->serveur, serveur->client)
    # doit produire UN SEUL HandshakeStatus (voir _flow_id, tri src/dst)
    events = [
        _ev(ts=0.0, src="10.0.0.1", sport=50000, dst="10.0.0.2", dport=443, handshake_type="client_hello"),
        _ev(ts=0.1, src="10.0.0.2", sport=443, dst="10.0.0.1", dport=50000, handshake_type="server_hello"),
    ]
    status = build_handshake_status(events)
    assert len(status["A"]) == 1


# -- diagnose_tls ---------------------------------------------------------------


def test_diagnose_tls_alerte_fatale_signalee_par_point():
    status = {"A": {"flow1": HandshakeStatus(point="A", flow_id="flow1", fatal_alert="bad_certificate", sni="x.com")}}
    findings = diagnose_tls(status, points_order=["A"])
    anomalies = [f for f in findings if f.severity == "anomalie"]
    assert any("alert fatal" in f.message for f in anomalies)


def test_diagnose_tls_degradation_entre_points_consecutifs():
    complete_a = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
        sni="x.com",
    )
    broken_b = HandshakeStatus(
        point="B",
        flow_id="f1",
        client_hello_seen=True,
        fatal_alert=None,
    )
    status = {"A": {"f1": complete_a}, "B": {"f1": broken_b}}
    findings = diagnose_tls(status, points_order=["A", "B"])
    degradation = [f for f in findings if f.segment == "A -> B"]
    assert len(degradation) == 1
    assert degradation[0].severity == "anomalie"
    assert "x.com" in degradation[0].message


def test_diagnose_tls_pas_de_degradation_si_toujours_complete():
    complete = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    status = {"A": {"f1": complete}, "B": {"f1": complete}}
    findings = diagnose_tls(status, points_order=["A", "B"])
    assert not [f for f in findings if f.segment == "A -> B"]


def test_diagnose_tls_info_ratio_handshakes_aboutis():
    complete = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    status = {"A": {"f1": complete}}
    findings = diagnose_tls(status, points_order=["A"])
    info = [f for f in findings if f.severity == "info"]
    assert any("1/1" in f.message for f in info)


def test_diagnose_tls_ordre_par_defaut_alphabetique_sans_points_order():
    status = {"Z": {}, "A": {}}
    # ne doit pas lever meme sans points_order
    findings = diagnose_tls(status)
    assert isinstance(findings, list)
