"""
netcross_core.security.dga + fast_flux -- tests (issue #152, SCENARIO-6).

Couvre :
- DGA : domaine a haute entropie detecte, domaine legitime non detecte
- Fast flux : rotation d'IPs via corrélation DNS+TCP, ratio NXDOMAIN
- Anti faux positifs : liste blanche, domaines ignores, seuils
"""

from __future__ import annotations

from netcross_core.security.dga import (
    DgaAlert,
    DgaResult,
    DgaThresholds,
    detect_dga,
)
from netcross_core.security.fast_flux import (
    FastFluxAlert,
    FastFluxResult,
    FastFluxThresholds,
    detect_fast_flux,
)
from tests.conftest import make_pkt

# --- DGA tests -------------------------------------------------------------


def test_dga_domaine_haute_entropie_detecte():
    """Un domaine DGA type (xkqjfwbvt.com) doit etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=True, dns_rcode=0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) >= 1
    assert result.alerts[0].domain == "xkqjfwbvt.com"
    assert result.alerts[0].score >= 0.6
    assert result.suspicious


def test_dga_domaine_legitime_non_detecte():
    """google.com ne doit pas etre detecte (liste blanche)."""
    pkts = [
        make_pkt(dns_qry_name="www.google.com", dns_is_response=False),
        make_pkt(dns_qry_name="www.google.com", dns_is_response=True, dns_rcode=0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_cloudflare_non_detecte():
    """cloudflare.com ne doit pas etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="cdn.cloudflare.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_domaine_court_non_detecte():
    """Un sous-domaine court (abc.com) ne doit pas declencher d'alerte."""
    pkts = [
        make_pkt(dns_qry_name="abc.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_domaine_normal_non_detecte():
    """Un domaine normal lisible ne doit pas etre detecte."""
    pkts = [
        make_pkt(dns_qry_name="my-blog.example.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0


def test_dga_nxdomain_eleve_aggrave_score():
    """Un ratio NXDOMAIN eleve doit augmenter le score DGA."""
    dga_domain = "qjwvn3k1n2.com"
    pkts = [
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=0.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=1.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=2.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=3.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=False, ts=4.0),
        make_pkt(dns_qry_name=dga_domain, dns_is_response=True, dns_rcode=3, ts=5.0),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) >= 1
    # Le ratio NXDOMAIN doit etre remonte dans l'alerte
    alert = result.alerts[0]
    assert alert.nxdomain_ratio >= 0.5


def test_dga_score_dans_intervalle_0_1():
    """Tous les scores doivent etre dans [0, 1]."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    for alert in result.alerts:
        assert 0.0 <= alert.score <= 1.0


def test_dga_domain_scores_calcules():
    """domain_scores doit contenir tous les domaines evaluates."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
        make_pkt(dns_qry_name="my-blog.example.com", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    domains = {d["domain"] for d in result.domain_scores}
    assert "xkqjfwbvt.com" in domains
    assert "example.com" in domains


def test_dga_thresholds_configurables():
    """Un seuil plus eleve doit reduire le nombre d'alertes."""
    pkts = [
        make_pkt(dns_qry_name="xkqjfwbvt.com", dns_is_response=False),
    ]
    # Seuil par defaut
    result_default = detect_dga(pkts)
    # Seuil tres eleve
    thresholds = DgaThresholds(score_threshold=0.99)
    result_high = detect_dga(pkts, thresholds)
    assert len(result_default.alerts) >= len(result_high.alerts)


def test_dga_ignored_domains():
    """in-addr.arpa et local doivent etre ignores."""
    pkts = [
        make_pkt(dns_qry_name="1.2.3.4.in-addr.arpa", dns_is_response=False),
        make_pkt(dns_qry_name="host.local", dns_is_response=False),
    ]
    result = detect_dga(pkts)
    assert len(result.alerts) == 0
    assert len(result.domain_scores) == 0


# --- Fast flux tests -------------------------------------------------------


def _make_dns_query(src: str, domain: str, ts: float) -> object:
    return make_pkt(src=src, dns_qry_name=domain, dns_is_response=False, ts=ts, proto="UDP", dport=53)


def _make_dns_response(src: str, domain: str, ts: float, rcode: int = 0) -> object:
    return make_pkt(src=src, dns_qry_name=domain, dns_is_response=True, dns_rcode=rcode, ts=ts, proto="UDP", sport=53)


def _make_tcp_conn(src: str, dst: str, ts: float) -> object:
    return make_pkt(src=src, dst=dst, ts=ts, proto="TCP", flags="S.......")


def test_fast_flux_rotation_ip_detecte():
    """Un domaine menant a 5+ IPs differentes en 10 min -> fast flux."""
    domain = "suspicious.example.com"
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    result = detect_fast_flux(pkts)
    alerts = [a for a in result.alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) >= 1
    assert alerts[0].domain == domain
    assert len(alerts[0].ips) >= 5


def test_fast_flux_peu_d_ips_non_detecte():
    """2 IPs differentes -> sous le seuil de 5."""
    domain = "normal.example.com"
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.append(_make_tcp_conn(src, "203.0.113.1", 1.0))
    pkts.append(_make_tcp_conn(src, "203.0.113.2", 2.0))
    result = detect_fast_flux(pkts)
    alerts = [a for a in result.alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) == 0


def test_fast_flux_hors_fenetre_non_detecte():
    """Connexions hors de la fenetre de 10 min -> pas de fast flux."""
    domain = "test.example.com"
    src = "192.168.1.100"
    thresholds = FastFluxThresholds(window_seconds=60.0)
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", 100.0 + i) for i in range(6))  # > 60s apres
    result = detect_fast_flux(pkts, thresholds)
    alerts = [a for a in result.alerts if a.alert_type == "ip_rotation"]
    assert len(alerts) == 0


def test_fast_flux_domaine_legitime_non_detecte():
    """google.com en liste blanche -> pas d'alerte."""
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, "www.google.com", 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    result = detect_fast_flux(pkts)
    alerts = [a for a in result.alerts if a.domain == "google.com"]
    assert len(alerts) == 0


def test_fast_flux_nxdomain_eleve_detecte():
    """Un domaine avec 70%+ de NXDOMAIN -> alerte high_nxdomain."""
    domain = "dga-suspicious.example.com"
    src = "192.168.1.100"
    pkts = []
    for i in range(10):
        pkts.append(_make_dns_query(src, domain, float(i)))
        pkts.append(_make_dns_response(src, domain, float(i + 0.5), rcode=3))
    result = detect_fast_flux(pkts)
    nxdomain_alerts = [a for a in result.alerts if a.alert_type == "high_nxdomain"]
    assert len(nxdomain_alerts) >= 1
    assert nxdomain_alerts[0].nxdomain_ratio >= 0.7


def test_fast_flux_nxdomain_bas_non_detecte():
    """Un domaine avec peu de NXDOMAIN -> pas d'alerte high_nxdomain."""
    domain = "normal.example.com"
    src = "192.168.1.100"
    pkts = []
    for i in range(10):
        pkts.append(_make_dns_query(src, domain, float(i)))
        pkts.append(_make_dns_response(src, domain, float(i + 0.5), rcode=0))
    result = detect_fast_flux(pkts)
    nxdomain_alerts = [a for a in result.alerts if a.alert_type == "high_nxdomain"]
    assert len(nxdomain_alerts) == 0


def test_fast_flux_score_dans_intervalle_0_1():
    """Tous les scores doivent etre dans [0, 1]."""
    domain = "suspicious.example.com"
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    result = detect_fast_flux(pkts)
    for alert in result.alerts:
        assert 0.0 <= alert.score <= 1.0


def test_fast_flux_ignored_domains():
    """in-addr.arpa et local doivent etre ignores."""
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, "1.2.3.4.in-addr.arpa", 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    result = detect_fast_flux(pkts)
    assert len(result.alerts) == 0


def test_fast_flux_thresholds_configurables():
    """Un min_ips plus eleve doit reduire les alertes."""
    domain = "test.example.com"
    src = "192.168.1.100"
    pkts = [_make_dns_query(src, domain, 0.0)]
    pkts.extend(_make_tcp_conn(src, f"203.0.113.{i + 1}", float(i + 1)) for i in range(6))
    # Seuil par defaut (5 IPs)
    result_default = detect_fast_flux(pkts)
    # Seuil a 10 IPs
    thresholds = FastFluxThresholds(min_ips=10)
    result_high = detect_fast_flux(pkts, thresholds)
    assert len(result_default.alerts) >= len(result_high.alerts)


# --- Dataclass tests -------------------------------------------------------


def test_dga_alert_dataclass():
    alert = DgaAlert(
        domain="xkqjfwbvt.com",
        score=0.75,
        reason="entropie 3.5",
        points=("A",),
        entropy=3.5,
        consonant_ratio=0.7,
        rare_bigram_ratio=0.6,
        length=10,
        nxdomain_ratio=0.0,
    )
    assert alert.domain == "xkqjfwbvt.com"
    assert alert.score == 0.75


def test_fast_flux_alert_dataclass():
    alert = FastFluxAlert(
        domain="suspicious.example.com",
        alert_type="ip_rotation",
        score=0.8,
        reason="rotation d'IPs",
        points=("A",),
        ips=["1.2.3.4", "5.6.7.8"],
        nxdomain_ratio=0.0,
    )
    assert alert.domain == "suspicious.example.com"
    assert alert.alert_type == "ip_rotation"
    assert len(alert.ips) == 2


def test_dga_result_suspicious():
    result = DgaResult()
    assert result.suspicious is False
    result.alerts.append(DgaAlert(domain="test.com", score=0.7, reason="test", points=("A",)))
    assert result.suspicious is True


def test_fast_flux_result_suspicious():
    result = FastFluxResult()
    assert result.suspicious is False
    result.alerts.append(
        FastFluxAlert(domain="test.com", alert_type="ip_rotation", score=0.8, reason="test", points=("A",))
    )
    assert result.suspicious is True
