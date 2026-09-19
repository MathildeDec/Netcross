"""
netcross_core.report_text -- mise en forme texte/CSV d'un Report. On ne
teste pas la mise en page caractere pres (fragile, sans valeur), mais
que (1) print_report() ne leve jamais sur un Report réaliste ni sur un
Report vide, et (2) write_detail_csv() produit un CSV structurellement
correct et complet.
"""

import csv

from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate
from netcross_core.report_text import print_report, write_detail_csv


def test_print_report_report_vide_ne_leve_pas(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "ANALYSE CROISEE DE CAPTURES" in out


def test_print_report_scenario_realiste_ne_leve_pas(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, flags="S", seq=1),
        make_pkt(point="B", sport=1, ts=0.01, flags="S", seq=1),
        make_pkt(point="A", sport=2, ts=1.0),  # perdu en B
        make_pkt(point="A", sport=3, ts=2.0, window=0),
        make_pkt(
            point="A",
            proto="UDP",
            sport=4,
            is_rtp=True,
            rtp_seq=1,
            rtp_ts=100,
            rtp_ssrc=1,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Paquets/flux identifies par point" in out
    assert "A" in out and "B" in out


def test_print_report_tcp_expert_signaux_affiche_section(capsys):
    # issue #21 : la section signaux d'expertise TCP natifs apparait et
    # distingue hors-ordre (reordonnancement) / segment perdu (perte reelle)
    # / maj de fenetre.
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            sport=10,
            expert_flags=("tcp_tcp_analysis_out_of_order",),
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=11,
            expert_flags=("tcp_tcp_analysis_lost_segment",),
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=12,
            expert_flags=("tcp_tcp_analysis_window_update",),
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Signaux d'expertise TCP natifs" in out
    assert "hors-ordre" in out
    assert "segment(s) perdu(s)" in out
    assert "maj(s) de fenetre" in out


def test_print_report_tcp_expert_signaux_aucun_message_defaut(capsys):
    pkts = [make_pkt(point="A", proto="TCP", sport=1, ts=0.0)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun signal d'expertise TCP supplementaire detecte" in out


def test_print_report_pmtud_blackhole_affiche(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1", df=True, length=1400),
        make_pkt(point="A", sport=1, ts=1.0, payload_hash="h2", df=True, length=1400),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "PMTUD" in out
    assert "A -> B" in out
    assert "noir PMTUD probable" in out


def test_print_report_idle_timeout_affiche(capsys):
    pkts = [
        make_pkt(point="A", sport=1, ts=0.0, payload_hash="h1"),
        make_pkt(point="B", sport=1, ts=0.1, payload_hash="h1"),
        make_pkt(point="A", sport=1, ts=90.0, payload_hash="h2"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "coupure NAT-FW silencieuse" in out
    assert "A -> B" in out
    assert "coupure NAT/pare-feu silencieuse probable" in out


def test_print_report_sans_idle_timeout_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune coupure detectee" in out


def test_print_report_arp_conflict_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:09"),
        make_pkt(point="A", proto="ARP", src="10.0.0.9", arp_sender_mac="aa:aa:aa:aa:aa:99"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Conflits d'adresse IP (ARP)" in out
    assert "conflit d'adresse IP probable" in out
    assert "10.0.0.9" in out


def test_print_report_sans_arp_conflict_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun conflit d'adresse IP detecte" in out


def test_print_report_stp_instability_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="STP", ts=0.0, stp_bpdu_type=0x80, stp_flags_tc=False, stp_root_id=None),
        make_pkt(
            point="A", proto="STP", ts=1.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="32768/aa:aa:aa:aa:aa:01"
        ),
        make_pkt(
            point="A", proto="STP", ts=3.0, stp_bpdu_type=0, stp_flags_tc=False, stp_root_id="4096/aa:aa:aa:aa:aa:02"
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Instabilite STP" in out
    assert "1 changement(s) de topologie, 1 reelection(s) de racine" in out


def test_print_report_sans_stp_instability_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune instabilite STP detectee" in out


def test_print_report_tls_cert_invalid_dates_affiche(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            ts=1924992000.0,  # 2031-01-01, apres notAfter
            tls_cert_not_before="2020-01-01 00:00:00 (UTC)",
            tls_cert_not_after="2030-01-01 00:00:00 (UTC)",
            tls_cert_serial="aa:aa",
        )
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Certificats TLS" in out
    assert "1 certificat(s) hors de leur fenetre de validite" in out


def test_print_report_tls_cert_mismatch_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="aa:aa"),
        make_pkt(point="B", proto="TCP", src="10.0.0.9", sport=443, tls_cert_serial="bb:bb"),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "interception/substitution TLS possible" in out


def test_print_report_sans_tls_cert_anomalie_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune anomalie de certificat detectee" in out


def test_print_report_tls_handshake_no_reply_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True)
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Negociations TLS incompletes" in out
    assert "1 negociation(s) sans reponse" in out


def test_print_report_tls_handshake_incomplete_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", src="10.0.0.1", sport=1234, dst="10.0.0.2", dport=443, tls_client_hello=True),
        make_pkt(point="A", proto="TCP", src="10.0.0.2", sport=443, dst="10.0.0.1", dport=1234, tls_server_hello=True),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "1 negociation(s) interrompue(s)" in out


def test_print_report_sans_negociation_tls_incomplete_message_par_defaut(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucune negociation TLS incomplete detectee" in out


def test_print_report_icmpv6_too_big_affiche(capsys):
    # Session 22 -- pendant IPv6 du test ICMP Fragmentation Needed
    # (deja couvert implicitement par le scenario "realiste" ci-dessus,
    # qui ne contient pas d'ICMP -- ce test-ci verifie explicitement le
    # texte ICMPv6).
    pkts = [make_pkt(point="A", proto="ICMPv6", icmpv6_type=2, icmpv6_code=0, ip_id=None)]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "ICMPv6" in out and "Packet Too Big" in out


def test_print_report_retransmissions_par_cause_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", sport=1, is_fast_retransmission=True),
        make_pkt(point="A", proto="TCP", sport=2, is_retransmission=True),
        make_pkt(point="A", proto="TCP", sport=3, is_spurious_retransmission=True),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Retransmissions TCP par cause" in out
    assert "1 rapide(s)" in out
    assert "1 par timeout/RTO" in out
    assert "1 inutile(s)" in out


def test_print_report_options_tcp_affiche(capsys):
    pkts = [
        make_pkt(point="A", proto="TCP", flags="......S.", sport=1, mss_val=1460, wscale_shift=7),
        make_pkt(point="B", proto="TCP", flags="......S.", sport=1, mss_val=1400, wscale_shift=None),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "Options TCP negociees au handshake" in out
    assert "MSS reduit sur 1 handshake" in out
    assert "Window Scale retire sur 1 handshake" in out


def test_print_report_dns_affiche_compteurs_et_nxdomain(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="UDP",
            sport=1,
            ts=0.0,
            dns_txn_id=1,
            dns_is_response=False,
            dns_qry_name="example.com",
        ),
        make_pkt(
            point="A",
            proto="UDP",
            sport=1,
            ts=0.01,
            dns_txn_id=1,
            dns_is_response=True,
            dns_qry_name="example.com",
            dns_rcode=0,
        ),
        make_pkt(
            point="A",
            proto="UDP",
            sport=2,
            ts=1.0,
            dns_txn_id=2,
            dns_is_response=True,
            dns_qry_name="inexistant.example",
            dns_rcode=3,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "DNS (resolution de noms)" in out
    assert "requete(s)" in out and "reponse(s)" in out
    assert "NXDOMAIN" in out
    assert "duree moyenne de resolution" in out


def test_print_report_dns_absent_affiche_message_dedie(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun trafic DNS detecte dans les captures" in out


def test_print_report_http_affiche_compteurs_et_erreurs(capsys):
    pkts = [
        make_pkt(
            point="A",
            proto="TCP",
            sport=1,
            ts=0.0,
            http_is_request=True,
            http_method="GET",
            http_uri="/",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=1,
            ts=0.01,
            http_is_response=True,
            http_uri="/",
            http_status_code=200,
            http_response_time_ms=10.0,
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=2,
            ts=1.0,
            http_is_request=True,
            http_method="GET",
            http_uri="/panne",
        ),
        make_pkt(
            point="A",
            proto="TCP",
            sport=2,
            ts=1.02,
            http_is_response=True,
            http_uri="/panne",
            http_status_code=500,
            http_response_time_ms=20.0,
        ),
    ]
    flows = correlate(pkts)
    r = analyse(flows, points_order=["A", "B"], all_packets=pkts)
    print_report(r)
    out = capsys.readouterr().out
    assert "HTTP (codes de statut" in out
    assert "requete(s)" in out and "reponse(s)" in out
    assert "GET /panne -> 500" in out
    assert "duree moyenne de reponse" in out


def test_print_report_http_absent_affiche_message_dedie(capsys):
    flows = correlate([])
    r = analyse(flows, points_order=["A", "B"], all_packets=[])
    print_report(r)
    out = capsys.readouterr().out
    assert "aucun trafic HTTP detecte dans les captures" in out


def test_write_detail_csv_structure_et_contenu(tmp_path):
    pkts = [
        make_pkt(point="A", sport=1, dscp=10, ttl=64, ts=0.0),
        make_pkt(point="B", sport=1, dscp=20, ttl=62, ts=0.05),
    ]
    flows = correlate(pkts)
    out_path = tmp_path / "detail.csv"
    write_detail_csv(str(out_path), flows, ["A", "B"])

    with open(out_path, newline="") as f:
        rows = list(csv.reader(f))

    header = rows[0]
    assert header[:6] == ["proto", "src", "sport", "dst", "dport", "key_id"]
    assert "A_ts" in header and "B_dscp" in header and "B_ttl" in header
    assert len(rows) == 2  # en-tete + 1 flux

    row = dict(zip(header, rows[1]))
    assert row["A_dscp"] == "10"
    assert row["B_dscp"] == "20"
    assert row["A_ttl"] == "64"


def test_write_detail_csv_flux_absent_a_un_point_laisse_les_cellules_vides(tmp_path):
    pkts = [make_pkt(point="A", sport=1)]
    flows = correlate(pkts)
    out_path = tmp_path / "detail.csv"
    write_detail_csv(str(out_path), flows, ["A", "B"])
    with open(out_path, newline="") as f:
        rows = list(csv.reader(f))
    _header, row = rows[0], dict(zip(rows[0], rows[1]))
    assert row["B_dscp"] == ""
    assert row["B_ttl"] == ""
