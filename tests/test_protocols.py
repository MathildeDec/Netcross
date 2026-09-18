"""
pcap_parser.protocols -- lit d'abord ce que tshark a nativement
dissecte (RTP/DHCP/SIP), retombe sur une heuristique par octets sinon.
On teste les deux chemins separement : le repli heuristique est ce qui
est reellement exerce des qu'aucun `tshark` n'est disponible (voir
claude.md, Sessions 3/4/5 : jamais teste avec un vrai tshark faute
d'environnement) -- c'est donc le chemin le plus important a couvrir
ici.
"""

import struct

import pytest

from pcap_parser.protocols import (
    compute_mos,
    extract_dhcp,
    extract_dns,
    extract_http,
    extract_rtp,
    extract_sip,
    extract_tls_certificate,
)


def _rtp_packet(seq=1, ts=1000, ssrc=0xDEADBEEF, pt=0, csrc_count=0) -> bytes:
    b0 = (2 << 6) | csrc_count  # version=2
    b1 = pt & 0x7F
    header = struct.pack("!BBHII", b0, b1, seq, ts, ssrc)
    return header + b"\x00" * 20  # un peu de "voix"


# -- RTP : tshark a deja dissecte --------------------------------------


def test_extract_rtp_lit_la_dissection_tshark():
    layers = {
        "rtp": {
            "rtp_rtp_seq": "42",
            "rtp_rtp_timestamp": "12345",
            "rtp_rtp_ssrc": "0xdeadbeef",
            "rtp_rtp_p_type": "0",
        }
    }
    result = extract_rtp(layers, b"")
    assert result == {"pt": 0, "seq": 42, "ts": 12345, "ssrc": 0xDEADBEEF}


def test_extract_rtp_dissection_incomplete_retombe_sur_heuristique():
    # tshark a bien une couche rtp mais sans seq exploitable -> repli
    layers = {"rtp": {"rtp_rtp_ssrc": "1"}}
    payload = _rtp_packet(seq=7, ts=100, ssrc=99)
    result = extract_rtp(layers, payload)
    assert result == {"pt": 0, "seq": 7, "ts": 100, "ssrc": 99}


# -- RTP : repli heuristique (chemin exerce sans tshark) ----------------


def test_extract_rtp_heuristique_reconnait_un_vrai_paquet():
    payload = _rtp_packet(seq=1000, ts=90000, ssrc=0x12345678, pt=8)
    result = extract_rtp({}, payload)
    assert result == {"pt": 8, "seq": 1000, "ts": 90000, "ssrc": 0x12345678}


def test_extract_rtp_heuristique_rejette_version_incorrecte():
    b0 = 1 << 6  # version=1, pas RTP
    payload = struct.pack("!BBHII", b0, 0, 1, 1, 1) + b"\x00" * 20
    assert extract_rtp({}, payload) is None


def test_extract_rtp_heuristique_rejette_payload_trop_court():
    assert extract_rtp({}, b"\x80\x00") is None


def test_extract_rtp_heuristique_gere_les_csrc():
    payload = _rtp_packet(seq=5, ts=5, ssrc=5, csrc_count=2) + b"\x00" * 8
    result = extract_rtp({}, payload)
    assert result == {"pt": 0, "seq": 5, "ts": 5, "ssrc": 5}


# -- DHCP -----------------------------------------------------------------


def test_extract_dhcp_offer_complet():
    layers = {
        "dhcp": {
            "dhcp_dhcp_type": "2",
            "dhcp_dhcp_id": "0x1a2b3c4d",
            "dhcp_dhcp_option_dhcp_server_id": "10.0.0.1",
            "dhcp_dhcp_option_vendor_class_id": "MSFT 5.0",
        }
    }
    result = extract_dhcp(layers)
    assert result == {
        "xid": 0x1A2B3C4D,
        "msg_type": "offer",
        "server_id": "10.0.0.1",
        "vendor_class": "MSFT 5.0",
    }


def test_extract_dhcp_code_inconnu_renvoie_le_code_en_chaine():
    layers = {"dhcp": {"dhcp_dhcp_type": "99"}}
    result = extract_dhcp(layers)
    assert result["msg_type"] == "99"


def test_extract_dhcp_absent_renvoie_none():
    assert extract_dhcp({}) is None
    assert extract_dhcp({"dhcp": {}}) is None  # pas de dhcp.type -> pas du DHCP


# -- SIP : dissection tshark ------------------------------------------------


def test_extract_sip_lit_la_dissection_tshark():
    layers = {
        "sip": {
            "sip_sip_Method": "INVITE",
            "sip_sip_Call-ID": "abc123@host",
            "sip_sip_CSeq": "1 INVITE",
            "sip_sip_User-Agent": "MonSoftphone/1.0",
        }
    }
    result = extract_sip(layers, b"")
    assert result["msg_type"] == "INVITE"
    assert result["call_id"] == "abc123@host"


# -- SIP : repli heuristique (port non standard, sans dissection tshark) ---


def test_extract_sip_heuristique_invite():
    payload = (
        b"INVITE sip:bob@example.com SIP/2.0\r\n"
        b"Call-ID: abc123@host\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"User-Agent: MonSoftphone/1.0\r\n"
        b"\r\n"
    )
    result = extract_sip({}, payload)
    assert result == {
        "msg_type": "INVITE",
        "call_id": "abc123@host",
        "cseq": "1 INVITE",
        "user_agent": "MonSoftphone/1.0",
        "server": None,
    }


def test_extract_sip_heuristique_reponse_status_line():
    payload = b"SIP/2.0 200 OK\r\nCall-ID: abc123@host\r\n\r\n"
    result = extract_sip({}, payload)
    assert result["msg_type"] == "200 OK"


def test_extract_sip_heuristique_methode_inconnue_renvoie_none():
    payload = b"GET / HTTP/1.1\r\n\r\n"
    assert extract_sip({}, payload) is None


def test_extract_sip_heuristique_payload_vide():
    assert extract_sip({}, b"") is None


# -- DNS : dissection tshark -------------------------------------------------


def test_extract_dns_requete():
    layers = {
        "dns": {
            "dns_dns_id": "0xabcd",
            "dns_dns_flags_response": False,
            "dns_dns_qry_name": "example.com",
            "dns_dns_flags_rcode": "0",
        }
    }
    result = extract_dns(layers)
    assert result == {
        "txn_id": 0xABCD,
        "is_response": False,
        "qry_name": "example.com",
        "rcode": 0,
    }


def test_extract_dns_reponse_nxdomain():
    layers = {
        "dns": {
            "dns_dns_id": "0xabcd",
            "dns_dns_flags_response": True,
            "dns_dns_qry_name": "inexistant.example",
            "dns_dns_flags_rcode": "3",
        }
    }
    result = extract_dns(layers)
    assert result["is_response"] is True
    assert result["rcode"] == 3


def test_extract_dns_qry_name_en_liste_prend_la_premiere():
    layers = {
        "dns": {
            "dns_dns_id": "0x1",
            "dns_dns_flags_response": False,
            "dns_dns_qry_name": ["a.example.com", "b.example.com"],
        }
    }
    result = extract_dns(layers)
    assert result["qry_name"] == "a.example.com"


def test_extract_dns_flags_response_en_chaine_est_tolere():
    # as_bool() (Session 9) tolere une representation en chaine par
    # prudence, meme si tshark rend ces champs en booleen JSON natif.
    layers = {"dns": {"dns_dns_id": "0x1", "dns_dns_flags_response": "1"}}
    result = extract_dns(layers)
    assert result["is_response"] is True


def test_extract_dns_absent_renvoie_none():
    assert extract_dns({}) is None
    assert extract_dns({"dns": {}}) is None  # pas de dns.id -> pas du DNS


# -- HTTP : dissection tshark (valeurs reelles tshark 4.2.2, capture ------
# HTTP/1.1 sur loopback -- serveur+client locaux, voir claude.md Session 17)


def test_extract_http_requete():
    layers = {
        "http": {
            "http_http_request": True,
            "http_http_request_method": "GET",
            "http_http_request_uri": "/",
            "http_http_request_full_uri": "http://127.0.0.1:8080/",
        }
    }
    result = extract_http(layers)
    assert result == {
        "is_request": True,
        "is_response": False,
        "method": "GET",
        "uri": "http://127.0.0.1:8080/",
        "status_code": None,
        "response_time_ms": None,
        "content_type": None,
        "content_length": None,
    }


def test_extract_http_requete_repli_sur_uri_sans_full_uri():
    # http.request.full.uri peut manquer (ex: HTTP/1.0 sans en-tete Host) --
    # repli sur le chemin seul.
    layers = {
        "http": {
            "http_http_request": True,
            "http_http_request_method": "GET",
            "http_http_request_uri": "/notfound",
        }
    }
    result = extract_http(layers)
    assert result["uri"] == "/notfound"


def test_extract_http_reponse():
    # http.time : calcule NATIVEMENT par tshark (ecart requete->reponse),
    # chaine flottante de secondes -- voir as_float. http.response.for.uri
    # (pas http.request.uri) porte l'URI cote reponse : la reponse ne
    # porte pas la methode.
    layers = {
        "http": {
            "http_http_response": True,
            "http_http_response_code": "404",
            "http_http_response_for_uri": "http://127.0.0.1:8080/notfound",
            "http_http_time": "0.000203587",
        }
    }
    result = extract_http(layers)
    assert result == {
        "is_request": False,
        "is_response": True,
        "method": None,
        "uri": "http://127.0.0.1:8080/notfound",
        "status_code": 404,
        "response_time_ms": pytest.approx(0.203587),
        "content_type": None,
        "content_length": None,
    }


def test_extract_http_reponse_sans_http_time():
    # tshark n'a pas toujours pu apparier la transaction dans ce fichier
    # (requete hors capture, pipelining...) -- http.time est alors absent,
    # pas un cas d'erreur.
    layers = {
        "http": {
            "http_http_response": True,
            "http_http_response_code": "200",
            "http_http_response_for_uri": "http://127.0.0.1:8080/",
        }
    }
    result = extract_http(layers)
    assert result["response_time_ms"] is None


def test_extract_http_request_et_response_en_chaine_est_tolere():
    # as_bool() (Session 9) tolere une representation en chaine par
    # prudence, meme si tshark rend http.request/http.response en
    # booleen JSON natif (verifie empiriquement, voir claude.md Session 17).
    layers = {"http": {"http_http_request": "1", "http_http_request_method": "POST"}}
    result = extract_http(layers)
    assert result["is_request"] is True


def test_extract_http_absent_renvoie_none():
    assert extract_http({}) is None
    # couche http presente mais ni requete ni reponse -- ne devrait pas
    # arriver en pratique (le dissecteur tshark pose toujours l'un des
    # deux), gere par prudence comme le reste de ce module.
    assert extract_http({"http": {}}) is None


# -- TLS certificat : dissection X.509 native (valeurs reelles tshark ----
# 4.2.2, capture TLS 1.2 sur loopback -- serveur+client locaux openssl,
# voir claude.md Session 26)


def test_extract_tls_certificate_champs_reels():
    layers = {
        "tls": {
            "x509af_x509af_utcTime": ["2026-08-31 18:46:38 (UTC)", "2027-08-31 18:46:38 (UTC)"],
            "x509ce_x509ce_dNSName": ["test.transcende.fr", "alt.transcende.fr"],
            "x509af_x509af_serialNumber": "38:f5:42:4e:fc:8e:44:c1:50:f9:3c:d4:21:ed:90:60:b9:df:5c:f6",
        }
    }
    result = extract_tls_certificate(layers)
    assert result == {
        "not_before": "2026-08-31 18:46:38 (UTC)",
        "not_after": "2027-08-31 18:46:38 (UTC)",
        "san": ("test.transcende.fr", "alt.transcende.fr"),
        "serial": "38:f5:42:4e:fc:8e:44:c1:50:f9:3c:d4:21:ed:90:60:b9:df:5c:f6",
    }


def test_extract_tls_certificate_un_seul_san_pas_en_liste():
    # tshark ne rend un champ EK repete en liste QUE s'il y a plusieurs
    # occurrences -- un seul SAN reste une chaine nue, pas une liste a
    # un element (meme comportement que dns.qry.name, voir extract_dns).
    layers = {
        "tls": {
            "x509af_x509af_utcTime": ["2026-01-01 00:00:00 (UTC)", "2027-01-01 00:00:00 (UTC)"],
            "x509ce_x509ce_dNSName": "seul.example.com",
            "x509af_x509af_serialNumber": "01:02:03",
        }
    }
    result = extract_tls_certificate(layers)
    assert result["san"] == ("seul.example.com",)


def test_extract_tls_certificate_sans_san():
    # SAN absent (certificat sans cette extension, rare mais possible) --
    # tuple vide plutot que None, pour eviter aux appelants de tester
    # deux cas differents (absent vs vide) pour la meme situation.
    layers = {
        "tls": {
            "x509af_x509af_utcTime": ["2026-01-01 00:00:00 (UTC)", "2027-01-01 00:00:00 (UTC)"],
            "x509af_x509af_serialNumber": "01:02:03",
        }
    }
    result = extract_tls_certificate(layers)
    assert result["san"] == ()


def test_extract_tls_certificate_serial_en_liste_prend_le_premier():
    # Chaine de plusieurs certificats -- x509af.serialNumber devient une
    # liste (un numero par certificat). Le premier est TOUJOURS celui du
    # certificat feuille (RFC 5246 SS7.4.2 : "the sender's certificate
    # MUST come first"), voir docstring de extract_tls_certificate.
    layers = {
        "tls": {
            "x509af_x509af_utcTime": [
                "2026-01-01 00:00:00 (UTC)",
                "2027-01-01 00:00:00 (UTC)",
                "2020-01-01 00:00:00 (UTC)",
                "2030-01-01 00:00:00 (UTC)",
            ],
            "x509af_x509af_serialNumber": ["aa:aa", "bb:bb"],
        }
    }
    result = extract_tls_certificate(layers)
    assert result["not_before"] == "2026-01-01 00:00:00 (UTC)"
    assert result["not_after"] == "2027-01-01 00:00:00 (UTC)"
    assert result["serial"] == "aa:aa"


def test_extract_tls_certificate_absent_renvoie_none():
    assert extract_tls_certificate({}) is None
    assert extract_tls_certificate({"tls": {}}) is None  # pas de certificat dans ce paquet TLS
    # ClientHello ou tout autre message TLS sans champ de date de
    # validite -- pas de certificat present, meme resultat.
    assert extract_tls_certificate({"tls": {"tls_tls_handshake_type": "1"}}) is None


def test_extract_tls_certificate_moins_de_deux_dates_renvoie_none():
    # Format inattendu (une seule date au lieu de la paire notBefore/
    # notAfter) -- pas de reconstruction approximative, voir docstring.
    layers = {"tls": {"x509af_x509af_utcTime": "2026-01-01 00:00:00 (UTC)"}}
    assert extract_tls_certificate(layers) is None


# -- MOS --------------------------------------------------------------------


def test_compute_mos_reseau_parfait_proche_du_maximum():
    r, mos = compute_mos(delay_ms=0.0, loss_pct=0.0)
    assert r == pytest.approx(93.2, abs=0.01)
    assert mos == pytest.approx(4.4, abs=0.05)


def test_compute_mos_degrade_avec_latence_et_perte():
    r_bon, mos_bon = compute_mos(delay_ms=20.0, loss_pct=0.0)
    r_mauvais, mos_mauvais = compute_mos(delay_ms=300.0, loss_pct=10.0)
    assert r_mauvais < r_bon
    assert mos_mauvais < mos_bon


def test_compute_mos_borne_toujours_entre_1_et_4_5():
    r, mos = compute_mos(delay_ms=5000.0, loss_pct=100.0)
    assert 1.0 <= mos <= 4.5
    assert 0.0 <= r <= 100.0


def test_compute_mos_delai_negatif_traite_comme_zero():
    r_negatif, mos_negatif = compute_mos(delay_ms=-50.0, loss_pct=0.0)
    r_zero, mos_zero = compute_mos(delay_ms=0.0, loss_pct=0.0)
    assert r_negatif == pytest.approx(r_zero)
    assert mos_negatif == pytest.approx(mos_zero)


def test_extract_http_reponse_expose_type_et_taille():
    layers = {
        "http": {
            "http_http_response": True,
            "http_http_response_code": "200",
            "http_http_response_for_uri": "/file.pdf",
            "http_http_content_type": "application/pdf",
            "http_http_content_length": "12345",
        }
    }
    result = extract_http(layers)
    assert result["content_type"] == "application/pdf"
    assert result["content_length"] == 12345
