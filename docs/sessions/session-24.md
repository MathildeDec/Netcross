# Session 24 — analyse L2 : conflit d'adresse IP via ARP

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 23.

### Contrainte d'environnement de cette session

`tshark`, `pytest`/`ruff`/`import-linter`/`pre-commit` et `scapy`
disponibles simultanément (accès réseau disponible). `tshark` 4.2.2,
`scapy` 2.7.0. Suite `pytest` rejouée avant toute modification :
471/471 verts (aucune régression héritée de la Session 23).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : seul candidat 🟢 restant avec un diagnostic
déjà posé plutôt qu'à découvrir depuis zéro, "Analyse L2 (ARP/STP)"
("Angle mort réel : IP dupliquée, boucle, flapping de port — mais cas
d'usage restreint au LAN pur"). **Scope restreint à ARP seul** dès le
départ, décision prise avant d'écrire la moindre ligne de code : `scapy`
2.7.0 (seule version disponible avec accès réseau cette session) n'a pas
de module `scapy.contrib.stp` pour construire des trames BPDU de test
(vérifié par import direct — `ModuleNotFoundError`), et il aurait fallu
construire les trames STP manuellement en bytes bruts (adresse de groupe
`01:80:c2:00:00:00`, en-tête LLC) sans pouvoir vérifier facilement contre
un vrai dissecteur scapy. ARP, lui, est pleinement supporté nativement.
Le couple ARP+STP annoncé par `FEATURES.md` est de toute façon trop
large pour une seule passe disciplinée — même logique de découpage que
Session 21→22 (fragmentation IPv6 puis ICMPv6 dans deux passes
distinctes).

### Exploration empirique préalable

Même discipline que pour ICMPv6 en Session 22 : pcap ARP synthétique
construit avec scapy (requête who-has, réponse is-at, annonce gratuite,
et un scénario de conflit — deux MAC différentes pour la même IP),
inspecté via un vrai `tshark -T ek` 4.2.2.

```python
from scapy.all import ARP, Ether, wrpcap

pkts = [
    Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=1, hwsrc="aa:aa:aa:aa:aa:01", psrc="10.0.0.1", hwdst="00:00:00:00:00:00", pdst="10.0.0.9"),
    Ether(src="aa:aa:aa:aa:aa:09", dst="aa:aa:aa:aa:aa:01")
    / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:09", psrc="10.0.0.9", hwdst="aa:aa:aa:aa:aa:01", pdst="10.0.0.1"),
    Ether(src="aa:aa:aa:aa:aa:02", dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=1, hwsrc="aa:aa:aa:aa:aa:02", psrc="10.0.0.2", hwdst="00:00:00:00:00:00", pdst="10.0.0.2"),
    Ether(src="aa:aa:aa:aa:aa:99", dst="ff:ff:ff:ff:ff:ff")
    / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:99", psrc="10.0.0.9", hwdst="aa:aa:aa:aa:aa:01", pdst="10.0.0.1"),
]
wrpcap("arp_synth.pcap", pkts)
```

`tshark -r arp_synth.pcap -T ek` confirme les noms de champs :
`arp.opcode`→`arp_arp_opcode`, `arp.src.hw_mac`→`arp_arp_src_hw_mac`,
`arp.src.proto_ipv4`→`arp_arp_src_proto_ipv4`,
`arp.dst.proto_ipv4`→`arp_arp_dst_proto_ipv4`. **Découverte utile,
change la conception du détecteur** : sur le 3e paquet (annonce
gratuite, sender == target), tshark émet en plus deux champs booléens
natifs `arp.isgratuitous`/`arp.isannouncement` — inutile de recalculer
`sender_ip == target_ip` à la main. Sur les paquets ordinaires, ces deux
champs sont simplement **absents** du layer (pas `false` explicite) —
même pattern que tous les autres champs booléens optionnels déjà
rencontrés dans ce projet (`ip.flags.df`, `tcp.analysis.retransmission`
etc.), géré par `as_bool(None) -> False`, déjà existant, réutilisé sans
modification.

### Implémentation

**Pipeline de décodage** (`pcap_parser/`) : `build_packet()` retournait
jusqu'ici `None` pour tout paquet sans IPv4 ni IPv6 (`return None # ARP,
STP, etc. -- hors perimetre`). ARP n'a structurellement pas d'en-tête IP
(RFC 826) mais porte lui-même des adresses IP dans son propre protocole
(champs sender/target) — ajout d'une branche `elif arp is not None:`
dédiée, avant ce `return None` devenu final uniquement pour "ni IP ni
ARP" (STP, LLDP, etc., toujours hors périmètre). `src`/`dst` réutilisent
les champs génériques existants pour porter `arp.src.proto_ipv4`/
`arp.dst.proto_ipv4` — cohérent avec le reste du pipeline, qui traite
déjà `src`/`dst` comme des adresses IP génériques quel que soit le
protocole. Trois nouveaux champs dédiés `RawPacket`/`Pkt.arp_opcode`/
`arp_sender_mac`/`arp_is_gratuitous` — **volontairement pas** de
réutilisation de `sport`/`dport` (contrairement à ICMP(v6), qui les
réutilise pour ident/seq) : ARP n'a pas de notion de port, réutiliser
ces champs aurait été une fausse analogie source de confusion. Nouvelle
valeur `proto = "ARP"`.

**Détecteur** (`netcross_core/analysis.py`) : `_analyse_arp_ip_conflict`
— pour chaque point de capture, regroupe les paquets ARP par IP
émettrice (`pk.src`), collecte l'ensemble des adresses MAC différentes
observées (`pk.arp_sender_mac`) pour cette IP ; si plus d'une MAC
distincte, conflit. `Report.arp_ip_conflict`/`arp_ip_conflict_examples`,
nouveaux compteurs **par point** (pas par paire de points comme la
plupart des autres détecteurs de ce module) — un conflit d'adresse se
voit déjà au sein d'un seul point de capture, une corrélation
inter-points n'apporte rien de plus ici. Chaque paquet ARP (requête OU
réponse) porte une revendication implicite "sender IP ↔ sender MAC"
tout aussi valide, y compris une simple requête who-has (dont le champ
sender identifie l'ÉMETTEUR, déjà connu de lui-même mais annoncé pour
permettre une réponse directe) — pas besoin de filtrer par opcode.

### Piège sérieux repéré et corrigé AVANT tout test

Contrairement aux deux pièges de la Session 23 (repérés PAR des tests),
celui-ci a été repéré par relecture attentive du code existant, avant
d'écrire la moindre ligne de détecteur ARP : la boucle principale de
`analyse()` itère sur `flows` (produit par `netcross_core.correlate.
correlate()`) **sans filtrer par protocole du tout**, pour calculer
pertes (`loss_count`), latence, changements QoS, saut de TTL
(`hop_delta`) et **inférence de topologie** (recouvrement de flux entre
points, `_infer_topology`). Ce sont des concepts qui supposent
implicitement une sémantique requête/réponse-PAR-FLUX pour chaque clé de
`flows`. Une trame ARP qui y serait entrée aurait faussé ces métriques
de deux façons concrètes :

1. Une requête ARP broadcast qui n'atteint jamais un point en aval d'un
   routeur (comportement **normal** pour ARP — RFC 826, un routeur ne
   relaie structurellement jamais un broadcast de couche 2) aurait été
   comptée comme une **perte réseau** par `r.loss_count`, un faux signal
   d'anomalie sans aucun rapport avec une vraie perte de paquet.
2. La même trame ARP broadcast, vue à plusieurs points de capture
   simultanément (normal pour un broadcast sur un même segment observé à
   plusieurs endroits), aurait ressemblé à un recouvrement de flux quasi
   parfait entre ces points — faussant potentiellement l'inférence de
   topologie (`_infer_topology`), qui utilise justement le recouvrement
   de flux comme proxy d'adjacence entre points.

Corrigé en excluant `proto == "ARP"` de `correlate()`, avant même la
construction de `flows` :

```python
def correlate(all_packets, nat_tolerant=False, nat_window_ms=200):
    flows = defaultdict(dict)
    for pk in all_packets:
        if pk.proto == "ARP":
            continue
        flows[flow_key(pk, nat_tolerant, nat_window_ms)].setdefault(pk.point, []).append(pk)
    return flows
```

ARP reste disponible via `all_packets` pour les détecteurs qui le
veulent explicitement (`_analyse_arp_ip_conflict`) — même principe que
DNS/SIP/DHCP/RTP, déjà tous analysés depuis `all_packets` plutôt que
`flows` pour des raisons similaires (sémantique applicative propre, pas
celle d'un flux TCP/UDP générique). `compute_throughput`/
`compute_topn_series`, qui eux opèrent directement sur `all_packets` (pas
sur `flows`), incluent en revanche légitimement le trafic ARP dans le
débit et la répartition par protocole — pas le même problème, ces deux
fonctions n'ont aucune hypothèse de sémantique requête/réponse par flux.

Testé explicitement par `test_correlate_exclut_arp`, et confirmé en
bout-en-bout (voir plus bas : section "Pertes : aucune détectée" malgré
une requête ARP broadcast présente à un seul point sur les deux
scénarios réels).

### Aucun changement nécessaire côté charts/JSON/GUI

Vérifié par lecture de code avant d'écrire quoi que ce soit, comme les
sessions précédentes : `json_report.py` est entièrement générique sur
les objets `Finding`, `pdf.py`/`charts.py`/la GUI GTK4 ne contiennent
aucune référence à PMTUD/idle_timeout ni n'en auraient besoin non plus
pour ce nouveau finding — confirmé par `grep` ciblé, aucune modification
apportée à ces fichiers.

### Non traité dans cette passe

- **STP** (boucle, flapping de port) — voir "Choix de la feature
  suivante" ci-dessus. Resterait à faire dans une session future, avec
  soit un environnement scapy plus complet (`scapy.contrib.stp`), soit
  une construction manuelle de trame BPDU.
- **Fenêtre temporelle pour la détection de conflit** — deux MAC
  revendiquant la même IP à n'importe quel moment de la capture (même
  très espacées) sont actuellement considérées en conflit, sans
  distinction avec un remplacement matériel légitime au cours d'une
  capture très longue. Documenté comme limite assumée dans le docstring.
- **Distinction conflit réel / failover IP flottante légitime**
  (VRRP/keepalived) — les deux se traduisent de la même façon côté ARP
  (nouvelle MAC qui revendique une IP déjà vue avec une autre MAC).
  Distinguer les deux demanderait de connaître la configuration réseau
  (IP virtuelles déclarées), hors de portée d'une simple lecture de
  capture.

### Validation effectuée

- **Tests unitaires** : suite complète rejouée avant toute modification
  (471/471 hérités de la Session 23, aucune régression préalable). 19
  nouveaux tests, 2 tests existants corrigés
  (`test_build_packet_sans_ip_renvoie_none` et
  `test_parse_capture_ignore_les_paquets_non_decodables` supposaient
  qu'ARP retournait `None` — désormais faux, remplacés par un scénario
  STP toujours hors périmètre, avec commentaire expliquant le
  changement) : `tests/test_tunnels.py` (sélection de couche `arp`, avec
  et sans tunnel, couche absente) ; `tests/test_packet.py` (requête,
  réponse, annonce gratuite, `arp.isgratuitous` absent → False, champs
  IP/TTL/DSCP/fragmentation neutres pour une trame sans en-tête IP) ;
  `tests/test_correlate.py` (exclusion d'ARP de `flows`) ;
  `tests/test_analysis.py` (détection nominale, pas de conflit à une
  seule MAC, détection indépendante du type de paquet requête/réponse,
  ignore les paquets non-ARP, indépendance stricte par point, plusieurs
  IP comptées séparément, exemples plafonnés à 5) ; `tests/
  test_synthesis.py`, `tests/test_report_text.py`, `tests/
  test_baseline_diff.py` (finding, affichage texte y compris message par
  défaut, comparaison de baseline) — **490/490** au total, aucune
  régression.
- **Bout en bout réel** : deux scénarios construits avec de vrais pcap
  scapy et un vrai `tshark -T ek`, rejoués via le **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --triage --json-report`) :
  1. Conflit d'adresse IP au point A (`10.0.0.9` revendiquée par deux MAC
     différentes, `aa:aa:aa:aa:aa:09` puis `aa:aa:aa:aa:aa:99`), point B
     avec un trafic ARP normal sans lien (`10.0.0.5`/`10.0.0.6`, une
     seule MAC chacune). Détecté et remonté correctement en console
     (« 1 adresse(s) IP revendiquee(s) par plusieurs MAC differentes »),
     dans le triage (catégorie "ARP") et dans le JSON (`category:
     "ARP"`, `severity: "anomalie"`, `segment: "A"`). **Section "Pertes"
     du rapport texte : "aucune détectée"** malgré une requête ARP
     broadcast présente uniquement au point A — confirme concrètement
     que le correctif `correlate()` fonctionne (sans lui, cette requête
     aurait été comptée comme une perte entre A et B).
  2. Même schéma mais avec une seule MAC stable dans le temps par IP (la
     même MAC revendique deux fois la même IP, à 10 secondes
     d'intervalle) : aucun faux positif, message par défaut "aucun
     conflit d'adresse IP détecté" affiché.
- **Outillage qualité** : `ruff check` (0 erreur), `ruff format --check`
  (49 fichiers conformes, aucun reformatage nécessaire cette fois — pas
  de nouvel effet de bord `.md` comme en Session 23), `PYTHONPATH=src
  lint-imports` (aucun cycle introduit, 1 contrat respecté), `pre-commit
  run --all-files` (les 3 hooks passent) — tous rejoués réellement sur
  un dépôt git temporaire créé pour l'occasion (supprimé après coup).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 — trois nouveaux paragraphes (`pcap_
  parser` pour le décodage ARP, `netcross_core.correlate` pour
  l'exclusion d'ARP de `flows`, `netcross_core.analysis` pour le
  détecteur lui-même) ; section 4 — nouvelle sous-section "Analyse L2 —
  conflit d'adresse IP via ARP (Session 24)" en tête, avant la Session
  23 ; section 5.2 — ligne "Analyse L2 (ARP/STP)" déplacée vers "fait"
  pour la partie ARP, avec STP explicitement laissé ouvert et sa raison
  documentée (limite d'environnement `scapy`, pas un choix de scope
  arbitraire).
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouvelle entrée "Fonctionnalités" pour la détection
  de conflit d'adresse IP ; nouvelle entrée dans "Limites connues"
  (pas de fenêtre temporelle, pas de distinction conflit/failover
  légitime, STP non couvert) ; compteur de tests mis à jour (471 → 490).

