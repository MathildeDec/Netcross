"""
Tests de netcross_core.security.flow_stats (issue #145, FLOW-4).
Analyse statistique des flux : SPLT, entropie, ratio up/down,
regularite temporelle, classification.
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.security.flow_stats import (
    CLASSIFICATION_INTERACTIVE,
    CLASSIFICATION_NORMAL,
    CLASSIFICATION_OBFUSCATED,
    CLASSIFICATION_TRANSFER,
    FlowStatsThresholds,
    analyze_flow_stats,
)

# -- Helpers -------------------------------------------------------------------

CLIENT = "192.168.1.10"
SERVER = "10.0.0.1"


def _make_flows(pkts_spec):
    """Construit des paquets a partir d'une liste de (src, dst, size, ts)."""
    return [make_pkt(src=src, dst=dst, length=size, ts=ts) for src, dst, size, ts in pkts_spec]


# -- Tests: SPLT ---------------------------------------------------------------


def test_splt_captures_first_packets():
    """SPLT contient les N premiers paquets avec (taille, delta_t)."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 100, 0.0),
            (CLIENT, SERVER, 200, 1.0),
            (CLIENT, SERVER, 150, 2.5),
        ]
    )
    result = analyze_flow_stats(pkts)

    assert len(result.flows) == 1
    flow = result.flows[0]
    assert len(flow.splt) == 3
    assert flow.splt[0] == (100, 0.0)
    assert flow.splt[1] == (200, 1.0)
    assert flow.splt[2] == (150, 1.5)


def test_splt_capped_at_max():
    """SPLT est limite a splt_max_packets."""
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(30)])
    result = analyze_flow_stats(pkts, thresholds=FlowStatsThresholds(splt_max_packets=10))
    flow = result.flows[0]
    assert len(flow.splt) == 10


# -- Tests: classification interactif ------------------------------------------


def test_classification_interactive():
    """Petits paquets reguliers -> interactif."""
    pkts = _make_flows([(CLIENT, SERVER, 60, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_INTERACTIVE
    assert flow.median_size < 100


# -- Tests: classification transfert -------------------------------------------


def test_classification_transfer():
    """Gros paquets unidirectionnels -> transfert."""
    pkts = _make_flows([(CLIENT, SERVER, 1400, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_TRANSFER
    assert flow.median_size > 500
    assert flow.upload_ratio > 0.8


# -- Tests: classification obfusque --------------------------------------------


def test_classification_obfuscated():
    """Entropie elevee sur les tailles -> obfusque."""
    # Tailles tres variees (distribution aleatoire)
    sizes = [50, 200, 800, 30, 500, 120, 900, 70, 400, 150, 600, 250, 10, 700, 350]
    pkts = _make_flows([(CLIENT, SERVER, sizes[i], float(i)) for i in range(len(sizes))])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_OBFUSCATED
    assert flow.entropy > 3.5


# -- Tests: classification normal ----------------------------------------------


def test_classification_normal():
    """Trafic normal (HTTP classique) -> normal."""
    # Melange de petits et gros paquets, entropie moderee
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 400, 0.0),
            (CLIENT, SERVER, 600, 1.0),
            (CLIENT, SERVER, 350, 2.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.classification == CLASSIFICATION_NORMAL


# -- Tests: ratio up/down ------------------------------------------------------


def test_upload_download_ratio():
    """Ratio up/down calcule correctement."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 1000, 0.0),
            (CLIENT, SERVER, 2000, 1.0),
            (SERVER, CLIENT, 500, 2.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    client_to_server = next(f for f in result.flows if f.src == CLIENT and f.dst == SERVER)
    assert client_to_server.upload_bytes == 3000
    assert client_to_server.download_bytes == 500
    assert 0.8 < client_to_server.upload_ratio < 0.9


# -- Tests: regularite temporelle ---------------------------------------------


def test_regularity_cv_calculated():
    """Coefficient de variation des intervalles calcule."""
    # Intervalles reguliers (1.0s entre chaque)
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert len(flow.inter_arrivals) == 9
    assert flow.regularity_cv < 0.01  # tres regulier


def test_irregular_timing_high_cv():
    """Intervalles irreguliers -> CV eleve."""
    timestamps = [0.0, 0.1, 5.0, 0.2, 10.0, 0.3, 15.0, 0.4, 20.0]
    pkts = _make_flows([(CLIENT, SERVER, 100, ts) for ts in timestamps])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.regularity_cv > 1.0  # tres irregulier


# -- Tests: entropie -----------------------------------------------------------


def test_entropy_uniform_distribution():
    """Distribution uniforme -> entropie maximale."""
    sizes = [100, 200, 300, 400, 500, 600, 700, 800]
    pkts = _make_flows([(CLIENT, SERVER, sizes[i % len(sizes)], float(i)) for i in range(40)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.entropy > 2.5  # 8 valeurs uniformes -> entropie = log2(8) = 3.0


def test_entropy_single_size():
    """Tous les paquets de meme taille -> entropie nulle."""
    pkts = _make_flows([(CLIENT, SERVER, 100, float(i)) for i in range(10)])
    result = analyze_flow_stats(pkts)
    flow = result.flows[0]
    assert flow.entropy == 0.0


# -- Tests: plusieurs flux -----------------------------------------------------


def test_multiple_flows_separated():
    """Deux paires differentes -> deux flux separes."""
    pkts = _make_flows(
        [
            (CLIENT, SERVER, 100, 0.0),
            ("10.0.0.2", "10.0.0.3", 200, 1.0),
        ]
    )
    result = analyze_flow_stats(pkts)
    assert len(result.flows) == 2


# -- Tests: vide ---------------------------------------------------------------


def test_empty_input():
    """Aucun paquet -> aucun flux."""
    result = analyze_flow_stats([])
    assert result.flows == []


# -- Tests: serialisation ------------------------------------------------------


def test_flow_to_dict():
    """to_dict produit un dict structure."""
    pkts = _make_flows([(CLIENT, SERVER, 100, 0.0)])
    result = analyze_flow_stats(pkts)
    d = result.to_dict()

    assert "flows" in d
    assert len(d["flows"]) == 1
    assert d["flows"][0]["src"] == CLIENT
    assert d["flows"][0]["dst"] == SERVER


def test_flow_stat_point_renseigne_depuis_paquet():
    """Issue #346 : FlowStat doit porter le point de capture du paquet,
    sinon flow_stats_findings produit point = null."""
    pkts = [make_pkt(src=CLIENT, dst=SERVER, length=100, ts=0.0, point="A")]
    result = analyze_flow_stats(pkts)
    assert result.flows[0].point == "A"
    assert result.flows[0].to_dict()["point"] == "A"


def test_flow_stats_findings_point_renseigne():
    """Issue #346 : flow_stats_findings doit produire un constat avec le
    point renseigne, pas null."""
    from netcross_core.security.findings import flow_stats_findings

    pkts = [make_pkt(src=CLIENT, dst=SERVER, length=1500, ts=float(i), point="A") for i in range(20)]
    result = analyze_flow_stats(pkts)
    flows = [f.to_dict() for f in result.flows]
    findings = flow_stats_findings(flows)
    # Un flux de 20 paquets de 1500 octets est classifie 'transfert'
    assert len(findings) >= 1
    assert findings[0]["point"] == "A"


# -- Tests: seuils personnalisables -------------------------------------------


def test_custom_small_packet_threshold():
    """Seuil de petit paquet personnalise."""
    # Avec seuil a 50, des paquets de 60 ne sont plus "interactif"
    pkts = _make_flows([(CLIENT, SERVER, 60, float(i)) for i in range(10)])
    custom = FlowStatsThresholds(small_packet_threshold=50)
    result = analyze_flow_stats(pkts, thresholds=custom)
    flow = result.flows[0]
    # Median = 60 > 50, donc pas interactif, pas transfert, pas obfusque -> normal
    assert flow.classification == CLASSIFICATION_NORMAL
