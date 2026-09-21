"""
Tests de netcross_core.discovery (issue #151, SCENARIO-5).
Inventaire passif des actifs, topologie, VLAN, OS detection.
"""

from __future__ import annotations

from conftest import make_pkt

from netcross_core.discovery.assets import build_asset_inventory
from netcross_core.discovery.os_detect import detect_os, guess_os_from_ttl, guess_os_from_window

# -- Tests: inventaire des hotes -----------------------------------------------


def test_host_inventory_basic():
    """Deux hotes communiquant -> 2 entrees dans l'inventaire."""
    pkt1 = make_pkt(src="192.168.1.10", dst="10.0.0.1", ts=1000.0)
    pkt2 = make_pkt(src="192.168.1.10", dst="10.0.0.1", ts=2000.0)
    inventory = build_asset_inventory([pkt1, pkt2])

    assert "192.168.1.10" in inventory.hosts
    assert "10.0.0.1" in inventory.hosts
    assert inventory.hosts["192.168.1.10"].first_seen == 1000.0
    assert inventory.hosts["192.168.1.10"].last_seen == 2000.0


def test_host_mac_from_arp():
    """MAC recuperee depuis un paquet ARP."""
    pkt = make_pkt(src="192.168.1.10", dst="192.168.1.1", arp_sender_mac="aa:bb:cc:dd:ee:ff")
    inventory = build_asset_inventory([pkt])

    assert inventory.hosts["192.168.1.10"].mac == "aa:bb:cc:dd:ee:ff"


def test_host_vlan_mapping():
    """Hotes associes a leur VLAN."""
    pkt = make_pkt(src="192.168.1.10", dst="192.168.1.1", vlan_id=10)
    inventory = build_asset_inventory([pkt])

    assert inventory.hosts["192.168.1.10"].vlan_id == 10
    assert "192.168.1.10" in inventory.vlan_map[10]


# -- Tests: ports exposes -----------------------------------------------------


def test_open_port_detected_by_syn_ack():
    """SYN-ACK = port ouvert cote serveur."""
    pkt = make_pkt(
        src="192.168.1.10",
        dst="10.0.0.1",
        flags="SA",
        sport=443,
    )
    inventory = build_asset_inventory([pkt])

    assert 443 in inventory.hosts["10.0.0.1"].open_ports
    assert inventory.hosts["10.0.0.1"].role == "serveur"


def test_syn_only_no_open_port():
    """SYN seul = pas de port ouvert sur la destination."""
    pkt = make_pkt(
        src="192.168.1.10",
        dst="10.0.0.1",
        flags="S",
        sport=443,
    )
    inventory = build_asset_inventory([pkt])

    assert 443 not in inventory.hosts["10.0.0.1"].open_ports


def test_multiple_open_ports():
    """Plusieurs ports ouverts sur le meme serveur."""
    pkts = [
        make_pkt(src="192.168.1.10", dst="10.0.0.1", flags="SA", sport=80),
        make_pkt(src="192.168.1.10", dst="10.0.0.1", flags="SA", sport=443),
        make_pkt(src="192.168.1.10", dst="10.0.0.1", flags="SA", sport=22),
    ]
    inventory = build_asset_inventory(pkts)

    assert inventory.hosts["10.0.0.1"].open_ports == {80, 443, 22}


# -- Tests: topologie ---------------------------------------------------------


def test_topology_edge_created():
    """Une paire source->destination cree une arete de topologie."""
    pkt = make_pkt(src="192.168.1.10", dst="10.0.0.1", proto="TCP")
    inventory = build_asset_inventory([pkt])

    assert len(inventory.topology) == 1
    edge = inventory.topology[0]
    assert edge.src == "192.168.1.10"
    assert edge.dst == "10.0.0.1"
    assert edge.packet_count == 1
    assert "TCP" in edge.protocols


def test_topology_packet_count_aggregated():
    """Plusieurs paquets sur la meme paire incremente le compteur."""
    pkts = [
        make_pkt(src="192.168.1.10", dst="10.0.0.1", proto="TCP"),
        make_pkt(src="192.168.1.10", dst="10.0.0.1", proto="UDP"),
    ]
    inventory = build_asset_inventory(pkts)

    assert len(inventory.topology) == 1
    edge = inventory.topology[0]
    assert edge.packet_count == 2
    assert "TCP" in edge.protocols
    assert "UDP" in edge.protocols


# -- Tests: roles -------------------------------------------------------------


def test_role_server_has_open_ports():
    """Un hote avec ports exposes est role=serveur."""
    pkt = make_pkt(src="192.168.1.10", dst="10.0.0.1", flags="SA", sport=80)
    inventory = build_asset_inventory([pkt])

    assert inventory.hosts["10.0.0.1"].role == "serveur"
    assert inventory.hosts["192.168.1.10"].role == "client"


# -- Tests: OS detection ------------------------------------------------------


def test_os_windows_ttl():
    """TTL 128 -> Windows."""
    assert guess_os_from_ttl(128) == "Windows"
    assert guess_os_from_ttl(250) == "Windows"


def test_os_linux_ttl():
    """TTL 64 -> Linux/Unix."""
    assert guess_os_from_ttl(64) == "Linux/Unix"


def test_os_none_ttl():
    """TTL None -> None."""
    assert guess_os_from_ttl(None) is None


def test_os_window_based():
    """Fenetre TCP caracteristique."""
    assert guess_os_from_window(8192) == "Windows/macOS"
    assert guess_os_from_window(5840) == "Linux"
    assert guess_os_from_window(None) is None


def test_detect_os_combines_signals():
    """detect_os combine TTL et fenetre."""
    pkt = make_pkt(ttl=64, window=5840)
    result = detect_os(pkt)
    assert result is not None
    assert "Linux" in result


def test_detect_os_no_signals():
    """Pas de TTL ni window -> None."""
    pkt = make_pkt(ttl=None, window=None)
    assert detect_os(pkt) is None


# -- Tests: serialisation -----------------------------------------------------


def test_inventory_to_dict():
    """to_dict produit un dict structuré."""
    pkt = make_pkt(src="192.168.1.10", dst="10.0.0.1", flags="SA", sport=443, ts=1000.0)
    inventory = build_asset_inventory([pkt])
    d = inventory.to_dict()

    assert "hosts" in d
    assert "topology" in d
    assert "vlan_map" in d
    assert "10.0.0.1" in d["hosts"]
    assert 443 in d["hosts"]["10.0.0.1"]["open_ports"]


# -- Tests: vide --------------------------------------------------------------


def test_empty_inventory():
    """Aucun paquet -> inventaire vide."""
    inventory = build_asset_inventory([])
    assert inventory.hosts == {}
    assert inventory.topology == []
