# Session 1 — remplacement scapy -> tshark pour netcross_core.parsing

Résumé de la session de travail avec Claude portant sur le remplacement du
décodage scapy par `tshark -T ek` dans `parse_capture`, sorti en package
indépendant `pcap_parser/`.

## Demande initiale

Remplacer scapy par `tshark -T ek` (meilleur en parsing/vitesse) pour
`parse_capture`, et en faire un package à part entière travaillant en
couches.

## Ce qui a été livré

### `src/pcap_parser/` — nouveau package, indépendant de netcross_core

Organisé en 6 couches (bas -> haut) :

| Fichier | Rôle |
|---|---|
| `ek_source.py` | Subprocess `tshark -T ek`, fichier **ou** interface live, streaming NDJSON ligne par ligne, précision nanoseconde via `frame.time_epoch` |
| `ek_fields.py` | Accès bas niveau aux champs EK (couches empilées -> *innermost*, hex/int tolérants) |
| `tunnels.py` | Détection VLAN/MPLS/GRE/VXLAN/GTP-U/ERSPAN/CAPWAP + sélection de la couche IP/TCP/UDP la plus interne |
| `protocols.py` | RTP/DHCP/SIP — lit d'abord ce que tshark a nativement décodé, repli heuristique sinon |
| `packet.py` | Assemble un `RawPacket` normalisé (aucune dépendance à netcross_core) |
| `capture.py` | API publique : `parse_capture`, `parse_captures_parallel`, **`iter_live`** (nouveau — capture en direct sur interface) |

### `src/netcross_core/parsing.py` — devient un adaptateur fin

Convertit `RawPacket -> Pkt` en attachant le `label` du point de capture.
Garde exactement les mêmes signatures que l'ancienne version scapy
(`parse_capture(label, path, raise_on_error)`, `parse_captures_parallel`,
`compute_mos`, `detect_encapsulation`...) — aucun changement requis dans
`__init__.py`, `analysis.py`, `report_text.py`, `baseline_diff.py`,
`correlate.py`, les CLI, ni `netcross_gtk4`/`netcross_report`.

Fonctions sans équivalent direct (opéraient sur un objet scapy) :
`innermost_layer()` et `parse_dhcp(pkt)` — lèvent `NotImplementedError`
avec pointeur vers le remplaçant dans `pcap_parser`.

## Ce que le passage à tshark simplifie

**CAPWAP** n'a plus besoin de décodage manuel d'octets
(`parse_capwap_data()` dans l'ancien `parsing.py`) : tshark décapsule
nativement le canal data (RFC 5415) et continue de disséquer la trame
Ethernet interne — même quand elle est elle-même encapsulée plus loin.

**RTP/DHCP/SIP** sont lus depuis les champs déjà extraits par le
dissecteur Wireshark natif (activé via `rtp.heuristic_rtp:TRUE` pour le
RTP sans signalisation SDP visible dans la capture), avec repli sur
l'ancienne logique heuristique par octets uniquement si tshark n'a rien
reconnu — comportement au moins équivalent à l'ancienne version, jamais
dégradé.

## Bugs trouvés et corrigés en croisant avec `analysis.py`

En vérifiant la compatibilité avec `analysis.py` (comme demandé), deux
problèmes réels ont été identifiés et corrigés avant livraison :

1. **`tcp.seq`/`tcp.ack` sont relatifs au flux dans tshark** (numérotés à
   partir de 0 par paquet-capture, propres à chaque processus tshark),
   alors que l'ancien code scapy comparait des valeurs de séquence
   *brutes* entre plusieurs fichiers de capture indépendants (matching
   SYN/SYN-ACK, estimation de décalage d'horloge dans
   `_analyse_handshake`). Corrigé en utilisant `tcp.seq_raw`/`tcp.ack_raw`
   (valeurs brutes sur le fil). Vérifié avec un test synthétique
   reproduisant un handshake TCP vu à deux points de capture distincts
   (fichiers pcap séparés, ISN relatifs différents côté tshark) : matching
   SYN/SYN-ACK et calcul de décalage d'horloge corrects après correction.
2. **Export manquant de `compute_mos`** : un nettoyage automatique des
   imports inutilisés (`ruff --fix`) avait supprimé l'import de
   `compute_mos` dans l'adaptateur alors qu'il est ré-exporté pour
   `analysis.py` (`from .parsing import compute_mos`). Corrigé et protégé
   par un commentaire explicite pour éviter la régression.

## Validation effectuée

Testé avec un vrai `tshark` (installé dans l'environnement de dev, pas de
nom de champ EK deviné) sur des pcaps synthétiques générés avec scapy
couvrant : VLAN, GRE (IP empilée), VXLAN (vni), GTP-U (teid), MPLS
(labels empilés), ERSPAN (sur GRE), CAPWAP (décapsulation + repli DTLS),
IPv4 et IPv6, ICMP, DHCP (discover/offer avec server_id et
vendor_class_id), SIP (INVITE natif tshark), RTP (heuristique). Toutes
les valeurs extraites correspondent aux valeurs injectées. Le pipeline
complet a aussi été rejoué via le vrai `netcross_core/__init__.py` du
projet (`parse_capture -> correlate -> analyse -> print_report`) sans
erreur, y compris le scénario de handshake TCP multi-points ci-dessus.

## Modifications de packaging (dépendance système tshark)

`tshark` n'est **pas** un paquet pip — mis à jour en conséquence :

- `requirements.txt` : commentaire clarifiant que `scapy` reste
  nécessaire (pour `tls_diagnostics.py`/`quic_diagnostics.py`, qui font
  leur propre lecture pcap indépendante de `parse_capture` — non touchés
  par ce changement) et que `tshark` doit venir du paquet système.
- `build-rpm/netcross.spec` : `Requires: wireshark-cli` ajouté (nom du
  paquet CLI de Wireshark sur Fedora/RHEL/Rocky récents).
- `build-deb/debian/control` : `tshark` ajouté aux `Depends`.
- `install.sh` : `tshark`/`wireshark-cli` ajoutés aux listes de paquets
  apt/dnf, avec repli automatique sur le paquet `wireshark` complet si
  `wireshark-cli` n'existe pas (bases EL8 plus anciennes).
- `README.md` : note CAPWAP dans "Limites connues" mise à jour (décodage
  désormais délégué au dissecteur tshark natif, plus une implémentation
  maison vérifiée contre la RFC).
- `report_text.py` : ligne d'affichage "CAPWAP non décodé" (vestige de
  l'ancienne limite scapy) corrigée — CAPWAP apparaît maintenant dans la
  liste des tunnels normalement détectés.
- `cross_capture_analyzer_cli.py` : commentaire `--parallel` et note de
  prérequis en tête de fichier mis à jour (ne mentionnaient plus
  correctement scapy comme seule dépendance).

## Hors périmètre de cette session (signalé, non modifié)

- `tls_diagnostics.py` et `quic_diagnostics.py` utilisent toujours scapy
  directement (`rdpcap`), indépendamment de `parse_capture` — non
  demandés, non touchés.
- `report_text.py`/`baseline_diff.py` : l'utilisateur a choisi de
  continuer avec `analysis.py` plutôt que cette couche ; seule la ligne
  CAPWAP factuellement fausse y a été corrigée en aparté.

## Prochaine étape suggérée

Vérifier `report_text.py`/`baseline_diff.py` en détail (formats
d'affichage, éventuelles autres suppositions sur le format des données
héritées de scapy) si besoin, ou s'attaquer à la conversion éventuelle de
`tls_diagnostics.py`/`quic_diagnostics.py` si scapy doit disparaître
complètement du projet.

---

