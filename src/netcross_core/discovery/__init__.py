"""
netcross_core.discovery -- decouverte et cartographie passive des actifs
reseau (issue #151, SCENARIO-5, parent #141).

Sous-modules :
- ``assets`` : inventaire des hotes (IP, MAC, premier/dernier vu, ports
  exposes, services), topologie deduite, cartographie VLAN.
- ``os_detect`` : fingerprint passif d'OS (TTL, fenetre TCP, options TCP).
"""
