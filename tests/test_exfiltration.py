"""
netcross_core.security.exfiltration -- issue #148 (SCENARIO-2) : detection
d'exfiltration de donnees. Paquets synthetiques (make_pkt) ; le trafic
« legitime » imite une navigation web ordinaire (peu de sortant, beaucoup
de retour) pour verifier le critere « aucun faux positif ».
"""

from datetime import datetime, timezone

from conftest import make_pkt
from netcross_core.models import Report
from netcross_core.security.exfiltration import (
    SIGNAL_DNS_VOLUME,
    SIGNAL_HTTP_CLOUD_UPLOAD,
    SIGNAL_ICMP_PAYLOAD,
    SIGNAL_NEW_DESTINATION,
    SIGNAL_OFF_HOURS,
    SIGNAL_RATIO,
    SIGNAL_VOLUME,
    ExfiltrationThresholds,
    detect_exfiltration,
)
from netcross_core.security.findings import apply_security_findings, exfiltration_findings

INTERNAL = "10.0.0.5"
EXTERNAL = "93.184.216.34"


def _epoch(hour, minute=0, day=1):
    return datetime(2024, 1, day, hour, minute, tzinfo=timezone.utc).timestamp()


_BUSINESS_HOURS_TS = _epoch(14)  # 14h UTC : hors de la plage hors-heures-ouvrees par defaut (20h-8h)


def _out(length=1000, ts=_BUSINESS_HOURS_TS, *, src=INTERNAL, dst=EXTERNAL, proto="TCP", sport=50000, dport=443,
         point="A", frame=None, **kw):
    return make_pkt(
        point=point, ts=ts, proto=proto, src=src, dst=dst, sport=sport, dport=dport, length=length,
        frame_number=frame, **kw,
    )


def _in_(length=1000, ts=_BUSINESS_HOURS_TS, *, src=EXTERNAL, dst=INTERNAL, proto="TCP", sport=443, dport=50000,
         point="A", frame=None, **kw):
    return make_pkt(
        point=point, ts=ts, proto=proto, src=src, dst=dst, sport=sport, dport=dport, length=length,
        frame_number=frame, **kw,
    )


# --- frontiere ---------------------------------------------------------


def test_deux_adresses_internes_ignorees():
    pkts = [_out(dst="10.0.0.9", length=5_000_000)]
    result = detect_exfiltration(pkts)
    assert result.flow_stats == [] and result.suspicions == []


def test_deux_adresses_publiques_ignorees():
    pkts = [_out(src="93.184.216.34", dst="1.1.1.1", length=5_000_000)]
    result = detect_exfiltration(pkts)
    assert result.flow_stats == [] and result.suspicions == []


def test_adresse_multicast_ignoree():
    pkts = [_out(dst="224.0.0.1", length=5_000_000)]
    assert detect_exfiltration(pkts).flow_stats == []


def test_paquet_non_ip_ignore():
    pkts = [_out(src="not-an-ip", length=5_000_000)]
    assert detect_exfiltration(pkts).flow_stats == []


def test_flux_regroupe_ports_ephemeres_internes():
    """Plusieurs connexions ephemeres vers le meme service externe : UN SEUL flux."""
    pkts = [_out(length=500_000, sport=50000 + i) for i in range(3)]
    result = detect_exfiltration(pkts)
    assert len(result.flow_stats) == 1
    assert result.flow_stats[0]["bytes_out"] == 1_500_000


# --- signal fort : ratio -------------------------------------------------


def test_ratio_eleve_sans_retour_leve_une_suspicion():
    pkts = [_out(length=2_000_000)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert s["kind"] == "flow"
    assert s["signals"] == [SIGNAL_RATIO]
    assert s["severity"] == "moyenne"
    assert s["bytes_out"] == 2_000_000 and s["bytes_in"] == 0 and s["ratio"] is None


def test_ratio_eleve_avec_peu_de_retour():
    pkts = [_out(length=2_000_000), _in_(length=50_000)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_RATIO in s["signals"]
    assert s["ratio"] == 40.0


def test_ratio_insuffisant_sous_le_plancher_de_volume():
    """Ratio infini mais volume sortant sous `ratio_min_bytes` : pas de suspicion."""
    pkts = [_out(length=500)]
    assert detect_exfiltration(pkts).suspicions == []
    assert detect_exfiltration(pkts).flow_stats  # le flux est neanmoins visible


def test_ratio_sous_le_seuil_ne_leve_rien():
    pkts = [_out(length=2_000_000), _in_(length=300_000)]  # ratio ~6.7 < 10
    assert detect_exfiltration(pkts).suspicions == []


# --- signal fort : volume -------------------------------------------------


def test_volume_total_superieur_au_seuil_meme_avec_ratio_equilibre():
    volume = 101 * 1024 * 1024
    pkts = [_out(length=volume), _in_(length=volume)]  # ratio 1:1
    (s,) = detect_exfiltration(pkts).suspicions
    assert s["signals"] == [SIGNAL_VOLUME]


def test_volume_sous_le_seuil_ne_leve_rien():
    volume = 50 * 1024 * 1024
    pkts = [_out(length=volume), _in_(length=volume)]
    assert detect_exfiltration(pkts).suspicions == []


# --- signaux faibles : jamais seuls ---------------------------------------


def test_destination_nouvelle_seule_ne_leve_rien():
    pkts = [_out(length=500)]  # sous le plancher de volume
    result = detect_exfiltration(pkts, known_destinations=frozenset({"1.1.1.1"}))
    assert result.suspicions == []


def test_destination_connue_ne_declenche_pas_new_destination():
    pkts = [_out(length=2_000_000)]
    (s,) = detect_exfiltration(pkts, known_destinations=frozenset({EXTERNAL})).suspicions
    assert SIGNAL_NEW_DESTINATION not in s["signals"]
    assert s["severity"] == "moyenne"


def test_destination_inconnue_aggrave_une_suspicion():
    pkts = [_out(length=2_000_000)]
    (s,) = detect_exfiltration(pkts, known_destinations=frozenset({"1.1.1.1"})).suspicions
    assert SIGNAL_NEW_DESTINATION in s["signals"]
    assert s["severity"] == "elevee"


def test_new_destination_desactive_par_defaut():
    """Sans baseline fournie (None) : jamais de faux positif par defaut."""
    pkts = [_out(length=2_000_000)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_NEW_DESTINATION not in s["signals"]


# --- signal faible : off_hours --------------------------------------------


def test_transfert_hors_heures_ouvrees_aggrave_une_suspicion():
    ts = _epoch(hour=2)  # 02h UTC : dans la plage par defaut [20h, 8h[
    pkts = [_out(length=15_000_000, ts=ts)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_OFF_HOURS in s["signals"]
    assert s["severity"] == "elevee"


def test_transfert_en_journee_ne_leve_pas_off_hours():
    ts = _epoch(hour=14)  # 14h UTC : heures ouvrees
    pkts = [_out(length=15_000_000, ts=ts)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_OFF_HOURS not in s["signals"]


def test_off_hours_exige_un_volume_minimal():
    ts = _epoch(hour=2)
    pkts = [_out(length=2_000_000, ts=ts)]  # au-dessus du plancher ratio, en dessous du plancher off_hours
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_OFF_HOURS not in s["signals"]


# --- signal faible : dns_large_volume -------------------------------------


def test_dns_large_volume_aggrave_une_suspicion():
    pkts = [_out(length=2_000_000, proto="UDP", sport=40000, dport=53, dns_txn_id=1, dns_is_response=False)]
    pkts += [
        _in_(length=600, proto="UDP", sport=53, dport=40000, dns_txn_id=100 + i, dns_is_response=True)
        for i in range(5)
    ]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_DNS_VOLUME in s["signals"]
    assert s["severity"] == "elevee"


def test_dns_reponses_sous_le_seuil_de_taille_ne_levent_rien():
    pkts = [_out(length=2_000_000, proto="UDP", sport=40000, dport=53, dns_txn_id=1, dns_is_response=False)]
    pkts += [
        _in_(length=200, proto="UDP", sport=53, dport=40000, dns_txn_id=100 + i, dns_is_response=True)
        for i in range(5)
    ]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_DNS_VOLUME not in s["signals"]


# --- signal faible : icmp_payload -----------------------------------------


def test_icmp_payload_aggrave_une_suspicion():
    pkts = [_out(length=2_000_000, proto="ICMP", sport=None, dport=None)]
    pkts += [_out(length=250, proto="ICMP", sport=None, dport=None, ts=i) for i in range(20)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_ICMP_PAYLOAD in s["signals"]


def test_ping_normal_ne_leve_pas_icmp_payload():
    pkts = [_out(length=2_000_000, proto="ICMP", sport=None, dport=None)]
    pkts += [_out(length=64, proto="ICMP", sport=None, dport=None, ts=i) for i in range(30)]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_ICMP_PAYLOAD not in s["signals"]


# --- signal faible : http_cloud_upload ------------------------------------


def test_post_vers_stockage_cloud_aggrave_une_suspicion():
    pkts = [
        _out(
            length=2_000_000,
            http_is_request=True,
            http_method="POST",
            http_uri="https://mybucket.amazonaws.com/leak.zip",
        )
    ]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_HTTP_CLOUD_UPLOAD in s["signals"]


def test_post_vers_domaine_non_cloud_ne_leve_rien():
    pkts = [
        _out(
            length=2_000_000,
            http_is_request=True,
            http_method="POST",
            http_uri="https://internal-app.example.com/upload",
        )
    ]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_HTTP_CLOUD_UPLOAD not in s["signals"]


def test_get_vers_stockage_cloud_ne_leve_rien():
    pkts = [
        _out(
            length=2_000_000,
            http_is_request=True,
            http_method="GET",
            http_uri="https://mybucket.amazonaws.com/leak.zip",
        )
    ]
    (s,) = detect_exfiltration(pkts).suspicions
    assert SIGNAL_HTTP_CLOUD_UPLOAD not in s["signals"]


# --- score de risque -------------------------------------------------------


def test_score_de_risque_cumule_les_signaux():
    ts = _epoch(hour=2)
    pkts = [_out(length=2_000_000, ts=ts)]
    only_ratio = detect_exfiltration(pkts).suspicions[0]["risk_score"]
    with_offhours = detect_exfiltration([_out(length=15_000_000, ts=ts)]).suspicions[0]["risk_score"]
    assert with_offhours > only_ratio


def test_score_de_risque_plafonne_a_100():
    ts = _epoch(hour=2)
    pkts = [
        _out(
            length=200 * 1024 * 1024,
            ts=ts,
            http_is_request=True,
            http_method="POST",
            http_uri="https://mybucket.amazonaws.com/leak.zip",
        )
    ]
    pkts += [
        _out(length=250, proto="ICMP", sport=None, dport=None, ts=i) for i in range(20)
    ]
    (s,) = detect_exfiltration(pkts, known_destinations=frozenset({"1.1.1.1"})).suspicions
    assert s["risk_score"] <= 100


# --- seuils configurables ---------------------------------------------------


def test_seuils_configurables():
    pkts = [_out(length=2_000_000)]
    strict = ExfiltrationThresholds(ratio_min_bytes=3_000_000)
    assert detect_exfiltration(pkts, strict).suspicions == []
    loose = ExfiltrationThresholds(volume_bytes=1_000_000)
    assert [s["signals"] for s in detect_exfiltration(pkts, loose).suspicions] == [[SIGNAL_RATIO, SIGNAL_VOLUME]]


# --- points de capture -------------------------------------------------------


def test_suspicion_par_point_sans_double_comptage():
    pkts = [_out(length=2_000_000, point="A"), _out(length=3_000_000, point="B")]
    result = detect_exfiltration(pkts)
    assert {(s["point"], s["bytes_out"]) for s in result.suspicions} == {("A", 2_000_000), ("B", 3_000_000)}


# --- aucun faux positif -----------------------------------------------------


def test_navigation_web_normale_ne_leve_rien():
    """Beaucoup de retour (pages, images), peu de sortant (requetes) : jamais de ratio inverse."""
    pkts = []
    for i in range(50):
        pkts.append(_out(length=400, ts=i * 2.0, sport=50000 + i))
        pkts.append(_in_(length=15_000, ts=i * 2.0 + 0.05, sport=443, dport=50000 + i))
    result = detect_exfiltration(pkts)
    assert result.suspicions == []
    assert result.flow_stats  # le flux est neanmoins visible pour l'analyste


def test_sauvegarde_cloud_legitime_avec_accuse_de_reception_ne_leve_rien():
    """Un POST vers un service cloud dont le volume et le ratio restent sous les seuils
    (ratio proche de 1:1, volume modeste) ne doit rien lever, meme vers un domaine
    de stockage cloud connu."""
    pkts = [
        _out(
            length=5_000_000,
            http_is_request=True,
            http_method="POST",
            http_uri="https://mybucket.amazonaws.com/backup.tar",
        ),
        _in_(length=5_000_000),
    ]
    assert detect_exfiltration(pkts).suspicions == []


# --- integration Report / findings de securite ------------------------------


def test_exfiltration_findings_format():
    pkts = [_out(length=2_000_000)]
    (f,) = exfiltration_findings(detect_exfiltration(pkts).suspicions)
    assert f["category"] == "anomalie" and f["severity"] == "moyenne"
    assert EXTERNAL in f["detail"] and "Mo envoyes" in f["detail"]
    assert f["host"] == EXTERNAL


def test_apply_security_findings_inclut_exfiltration():
    report = Report()
    pkts = [_out(length=2_000_000)]
    apply_security_findings(report, iter(pkts))
    assert [f["category"] for f in report.security_findings] == ["anomalie"]
    apply_security_findings(report, pkts)  # remplacement, pas ajout
    assert len(report.security_findings) == 1


def test_apply_security_findings_navigation_normale_reste_vide():
    report = Report()
    pkts = []
    for i in range(20):
        pkts.append(_out(length=400, ts=i * 2.0, sport=50000 + i))
        pkts.append(_in_(length=15_000, ts=i * 2.0 + 0.05, sport=443, dport=50000 + i))
    apply_security_findings(report, pkts)
    assert report.security_findings == []
