"""
netcross_core.discovery.assets -- issue #151 (SCENARIO-5, parent #141) :
inventaire passif des actifs reseau visibles dans la capture.

Construit un inventaire structuré a partir des paquets observes :
- hotes (IP, MAC, premier/dernier timestamp)
- ports exposes (identifies par SYN-ACK, reponses applicatives)
- topologie deduite (paires source->destination)
- cartographie VLAN (hotes par VLAN)

Aucun scan actif : tout est derive du trafic capture. Un hote qui ne
communique pas n'apparait pas dans l'inventaire -- c'est le principe
meme de la decouverte passive.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from netcross_core.models import Pkt


@dataclass
class HostAsset:
    """Un hote vu dans la capture."""

    ip: str
    mac: str | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    vlan_id: int | None = None
    open_ports: set[int] = field(default_factory=set)
    services: dict[int, str] = field(default_factory=dict)  # port -> proto
    os_guess: str | None = None
    role: str | None = None  # client, serveur, routeur, switch

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "vlan_id": self.vlan_id,
            "open_ports": sorted(self.open_ports),
            "services": dict(self.services),
            "os_guess": self.os_guess,
            "role": self.role,
        }


@dataclass
class TopologyEdge:
    """Un lien source -> destination dans le graphe de topologie."""

    src: str
    dst: str
    packet_count: int = 0
    protocols: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "packet_count": self.packet_count,
            "protocols": sorted(self.protocols),
        }


@dataclass
class AssetInventory:
    """Resultat de l'inventaire passif."""

    hosts: dict[str, HostAsset] = field(default_factory=dict)
    topology: list[TopologyEdge] = field(default_factory=list)
    vlan_map: dict[int, list[str]] = field(default_factory=lambda: defaultdict(list))

    def to_dict(self) -> dict:
        return {
            "hosts": {ip: h.to_dict() for ip, h in self.hosts.items()},
            "topology": [e.to_dict() for e in self.topology],
            "vlan_map": dict(self.vlan_map.items()),
        }


def _is_syn_ack(flags: str | None) -> bool:
    """Detecte un flag SYN-ACK (port ouvert cote serveur)."""
    if flags is None:
        return False
    return "S" in flags and "A" in flags


def _is_syn(flags: str | None) -> bool:
    """Detecte un flag SYN seul (sans ACK)."""
    if flags is None:
        return False
    return "S" in flags and "A" not in flags


def build_asset_inventory(packets: Iterable[Pkt]) -> AssetInventory:
    """
    Construit l'inventaire passif des actifs a partir des paquets captures.

    - Inventaire des hotes : IP, MAC (depuis ARP), premier/dernier vu, VLAN
    - Ports exposes : identifies par SYN-ACK (reponse serveur)
    - Topologie : paires source->destination avec compteurs
    - Cartographie VLAN : hotes par VLAN
    - Role : serveur si ports exposes, client sinon
    """
    inventory = AssetInventory()
    topology_map: dict[tuple[str, str], TopologyEdge] = {}

    for pk in packets:
        # -- Mise a jour de l'hote source --
        src_host = inventory.hosts.get(pk.src)
        if src_host is None:
            src_host = HostAsset(ip=pk.src, first_seen=pk.ts, last_seen=pk.ts)
            inventory.hosts[pk.src] = src_host
        else:
            src_host.first_seen = min(src_host.first_seen, pk.ts)
            src_host.last_seen = max(src_host.last_seen, pk.ts)

        # MAC depuis ARP
        if pk.arp_sender_mac and src_host.mac is None:
            src_host.mac = pk.arp_sender_mac

        # VLAN
        if pk.vlan_id is not None and src_host.vlan_id is None:
            src_host.vlan_id = pk.vlan_id
            inventory.vlan_map[pk.vlan_id].append(pk.src)

        # -- Mise a jour de l'hote destination --
        dst_host = inventory.hosts.get(pk.dst)
        if dst_host is None:
            dst_host = HostAsset(ip=pk.dst, first_seen=pk.ts, last_seen=pk.ts)
            inventory.hosts[pk.dst] = dst_host
        else:
            dst_host.first_seen = min(dst_host.first_seen, pk.ts)
            dst_host.last_seen = max(dst_host.last_seen, pk.ts)

        if pk.arp_sender_mac and dst_host.mac is None:
            dst_host.mac = pk.arp_sender_mac

        if pk.vlan_id is not None and dst_host.vlan_id is None:
            dst_host.vlan_id = pk.vlan_id
            inventory.vlan_map[pk.vlan_id].append(pk.dst)

        # -- Detection des ports exposes (SYN-ACK = serveur repond) --
        if _is_syn_ack(pk.flags) and pk.sport is not None:
            dst_host.open_ports.add(pk.sport)
            if pk.sport not in dst_host.services:
                dst_host.services[pk.sport] = pk.proto
            dst_host.role = "serveur"

        # Role client pour la source si elle initie (SYN seul)
        if _is_syn(pk.flags) and src_host.role is None:
            src_host.role = "client"

        # -- Topologie --
        edge_key = (pk.src, pk.dst)
        edge = topology_map.get(edge_key)
        if edge is None:
            edge = TopologyEdge(src=pk.src, dst=pk.dst)
            topology_map[edge_key] = edge
        edge.packet_count += 1
        edge.protocols.add(pk.proto)

    # Deduire les roles non assignes
    for host in inventory.hosts.values():
        if host.role is None:
            host.role = "client" if not host.open_ports else "serveur"

    inventory.topology = list(topology_map.values())
    return inventory
