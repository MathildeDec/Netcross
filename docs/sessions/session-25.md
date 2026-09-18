# Session 25 — analyse L2 : instabilité STP (tempête de topologie / racine)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 24.

### Contrainte d'environnement de cette session

`tshark`, `pytest`/`ruff`/`import-linter`/`pre-commit` et `scapy`
disponibles simultanément (accès réseau disponible). `tshark` 4.2.2,
`scapy` 2.7.0. Suite `pytest` rejouée avant toute modification :
490/490 verts (aucune régression héritée de la Session 24).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : dernier reliquat de "Analyse L2 (ARP/STP)",
laissé explicitement ouvert en Session 24 avec la note "scapy 2.7.0 n'a
pas de module `scapy.contrib.stp`". **Première chose faite cette
session, avant tout code** : revérifier cette limitation supposée.

```python
from scapy.layers.l2 import STP

STP().show()
```

Résultat : `scapy.layers.l2.STP` existe et fonctionne parfaitement,
avec tous les champs attendus (`proto`, `version`, `bpdutype`,
`bpduflags`, `rootid`, `rootmac`, `pathcost`, `bridgeid`, `bridgemac`,
`portid`, `age`, `maxage`, `hellotime`, `fwddelay`). La Session 24
avait cherché dans `scapy.contrib.stp` (qui effectivement n'existe pas)
sans jamais vérifier `scapy.layers.l2` — erreur de recherche, pas une
vraie limitation d'environnement. STP est donc pleinement réalisable
cette session, la piste ARP/STP peut être entièrement close.

### Exploration empirique préalable

Même discipline que pour ARP en Session 24 : pcap STP synthétique
construit avec `scapy.layers.l2.STP` (Configuration BPDU normale,
Configuration BPDU avec bit TC actif, et une TCN — celle-ci construite
en bytes bruts, scapy n'ayant pas de classe dédiée pour cette variante
minimale du protocole), inspecté via un vrai `tshark -T ek` 4.2.2.

```python
from scapy.all import Ether, LLC, wrpcap
from scapy.layers.l2 import STP


def bpdu(rootmac, bridgemac, flags=0, ts=0.0):
    stp = STP(
        proto=0,
        version=0,
        bpdutype=0,
        bpduflags=flags,
        rootid=32768,
        rootmac=rootmac,
        pathcost=0,
        bridgeid=32768,
        bridgemac=bridgemac,
        portid=0x8001,
        age=0,
        maxage=20,
        hellotime=2,
        fwddelay=15,
    )
    p = Ether(src=bridgemac, dst="01:80:c2:00:00:00") / LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / stp
    p.time = ts
    return p


def tcn(src_mac, ts):
    p = Ether(src=src_mac, dst="01:80:c2:00:00:00") / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    p = p / bytes([0x00, 0x00, 0x00, 0x80])  # proto(2)=0, version(1)=0, type(1)=0x80
    p.time = ts
    return p
```

`tshark -r ... -T ek` confirme les noms de champs :
`stp.type`→`stp_stp_type`, `stp.flags.tc`→`stp_stp_flags_tc` (booléen
**natif** tshark), `stp.root.prio`→`stp_stp_root_prio`,
`stp.root.hw`→`stp_stp_root_hw`. **Découverte empirique clé, confirme
un choix de conception avant même d'écrire le détecteur** : sur la TCN
(type 0x80), les champs `stp.flags.tc` et `stp.root.*` sont
**absents** du layer EK (pas juste vides ou à zéro) — cohérent avec le
format du protocole (IEEE 802.1D définit la TCN comme une BPDU minimale
de 4 octets utiles : identifiant de protocole, version, type — rien
d'autre). Testé directement contre le vrai flux tshark avant d'écrire
le moindre test unitaire :

```python
pk.proto, pk.src, pk.dst, pk.stp_bpdu_type, pk.stp_flags_tc, pk.stp_root_id
# Config sans TC : STP aa:aa:...:01 01:80:c2:00:00:00 0   False 32768/aa:aa:...:01
# Config avec TC : STP aa:aa:...:01 01:80:c2:00:00:00 0   True  32768/aa:aa:...:01
# TCN            : STP aa:aa:...:02 01:80:c2:00:00:00 128 False None
```

### Implémentation

**Pipeline de décodage** (`pcap_parser/`) : nouvelle branche `elif stp
is not None:` dans `build_packet()`, après la branche ARP (Session 24),
avant le `return None` final (désormais réservé à "ni IP, ni ARP, ni
STP" — LLDP, CDP, etc., toujours hors périmètre). Différence de
conception importante avec ARP : ARP porte ses **propres** adresses IP
(réutilisées pour `src`/`dst`), mais STP ne porte **aucune** adresse IP
— seulement des adresses MAC (l'émettrice, celle du pont racine, celle
du pont annonçant). `src`/`dst` réutilisent donc l'adresse MAC
Ethernet de la trame elle-même (`eth.src`/`eth.dst`, cette dernière
toujours l'adresse de groupe bien connue `01:80:c2:00:00:00`) —
récupérée directement via la couche `eth` du dict `layers` (jamais
tunnelée dans ce projet, pas besoin de passer par `select_innermost_
layers`). Trois nouveaux champs dédiés `RawPacket`/`Pkt.stp_bpdu_type`/
`stp_flags_tc`/`stp_root_id` (`stp_root_id` : chaîne combinant
priorité et MAC du pont racine, `None` si absent comme sur une TCN).
Nouvelle valeur `proto = "STP"`.

**Détecteur** (`netcross_core/analysis.py`) : `_analyse_stp_instability`
— deux compteurs indépendants, par point (comme ARP, pas par paire) :

1. `stp_topology_change` : un événement de changement de topologie est
   signalé par une TCN **ou** une Configuration BPDU avec le bit TC
   actif — les deux comptent séparément si elles apparaissent toutes
   les deux (ce sont deux trames distinctes, même si elles signalent le
   même phénomène réseau : la TCN est émise par le pont qui détecte le
   changement, la Configuration-avec-TC est émise ensuite par le pont
   racine pour propager l'information).
2. `stp_root_change` : le pont racine annoncé change de valeur d'une
   Configuration BPDU à la suivante, au même point.

### Piège anticipé et neutralisé AVANT tout test

Contrairement au piège ARP de la Session 24 (repéré par relecture après
coup) et aux pièges idle_timeout de la Session 23 (repérés PAR des
tests), celui-ci a été anticipé pendant la conception, avant même
d'écrire le détecteur : la comparaison "racine précédente → racine
actuelle" pour `stp_root_change` DOIT être triée par horodatage au sein
de chaque point avant comparaison. Raison : le CLI construit
`all_packets` en concaténant les paquets **point par point** (voir
`cross_capture_analyzer_cli.py` -- `all_packets.extend(packets_by_
point[label])` pour chaque point dans l'ordre), pas par un merge
chronologique global entre points. À l'intérieur du bloc de chaque
point, l'ordre EST chronologique (celui de la capture), donc parcourir
`all_packets` tel quel aurait fonctionné dans TOUS les cas produits par
le CLI réel -- mais rien ne garantit cet ordre pour un appelant qui
construirait `all_packets` autrement (tests unitaires en particulier).
Le détecteur trie donc explicitement chaque point avant comparaison
(`pkts.sort(key=lambda p: p.ts)`), même discipline défensive que
`_analyse_idle_timeout` en Session 23 (qui utilise `sorted()` plutôt
que de faire confiance à l'ordre d'entrée). Testé explicitement par
`test_stp_root_change_trie_par_timestamp_avant_comparaison`, où les
paquets sont volontairement fournis dans le désordre chronologique.

### `netcross_core.correlate` étendu

L'exclusion de `flows` introduite pour ARP en Session 24 est
généralisée : `if pk.proto in ("ARP", "STP"): continue`. Même
raisonnement exact que pour ARP -- STP est diffusé en multicast local
au segment (adresse de groupe IEEE 802.1D, jamais relayé par un
routeur), sans la sémantique requête/réponse-par-flux que suppose
`flows`. Sans cette extension, le même risque de pollution des
statistiques de perte/latence/topologie identifié pour ARP se serait
reproduit à l'identique pour STP -- le trafic STP est d'ailleurs
généralement PLUS régulier et prévisible que l'ARP (BPDU périodiques
toutes les 2 secondes par défaut, IEEE 802.1D), donc l'aurait pollué de
façon encore plus systématique s'il n'avait pas été exclu.

### Aucun changement nécessaire côté charts/JSON/GUI

Vérifié par lecture de code avant d'écrire quoi que ce soit, comme les
sessions précédentes : `json_report.py` est entièrement générique sur
les objets `Finding`, `pdf.py`/`charts.py`/la GUI GTK4 ne contiennent
aucune référence a ARP/PMTUD/idle_timeout ni n'en auraient besoin non
plus pour ces deux nouveaux findings.

### Non traité dans cette passe -- limite architecturale, pas un chantier reporté

"Flapping de port" au sens strict (un port de COMMUTATEUR qui bascule
haut/bas de façon répétée) n'est **pas** directement observable depuis
une capture réseau : cette information vit dans la table d'état interne
du commutateur (SNMP/syslog), pas sur le fil. Ce détecteur observe la
CONSÉQUENCE visible sur le fil (tempête de changements de topologie,
réélections de racine) plutôt que la cause exacte (quel port précis,
sur quel commutateur) -- documenté explicitement comme limite
architecturale honnête d'un outil basé sur la capture de trafic, pas un
oubli ou un chantier pour une session future. Avec cette session, la
piste "Analyse L2 (ARP/STP)" de la section 5.2 est désormais entièrement
traitée dans les limites de ce qu'une capture de trafic peut observer.

### Validation effectuée

- **Tests unitaires** : suite complète rejouée avant toute modification
  (490/490 hérités de la Session 24, aucune régression préalable). 16
  nouveaux tests, 2 tests existants corrigés
  (`test_build_packet_sans_ip_ni_arp_renvoie_none` et
  `test_parse_capture_ignore_les_paquets_non_decodables` supposaient que
  STP retournait `None` -- désormais faux, remplacés par un scénario
  LLDP toujours hors périmètre) : `tests/test_tunnels.py` (sélection de
  couche `stp`, avec et sans tunnel, couche absente) ; `tests/
  test_packet.py` (Configuration BPDU normale, avec bit TC, TCN avec
  champs root absents, `src`/`dst` = adresse MAC Ethernet, ttl/dscp/ecn
  neutres) ; `tests/test_correlate.py` (exclusion de STP de `flows`) ;
  `tests/test_analysis.py` (détection via TCN, détection via bit TC,
  pas de signal sur Configuration normale, TCN et bit TC comptés
  séparément si tous deux présents, détection de changement de racine
  avec exemple, pas de changement si racine stable, TCN sans champ root
  ignorée sans casser la comparaison encadrante, indépendance stricte
  par point, tri explicite par horodatage avant comparaison, ignore les
  paquets non-STP) ; `tests/test_synthesis.py`, `tests/
  test_report_text.py`, `tests/test_baseline_diff.py` (deux findings
  distincts pour les deux compteurs, affichage texte y compris message
  par défaut, comparaison de baseline pour les deux compteurs) --
  **514/514** au total, aucune régression. Une erreur `ruff` (`F841`,
  variable `root_by_point` devenue inutilisée après une refonte de la
  logique de tri) repérée et corrigée avant la passe qualité finale.
- **Bout en bout réel** : deux scénarios construits avec de vrais pcap
  scapy et un vrai `tshark -T ek`, rejoués via le **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --triage --json-report`) :
  1. Réseau instable au point A (une TCN à t=1.0, une Configuration BPDU
     avec bit TC à t=1.2, une réélection de racine à t=3.0 -- nouvelle
     priorité/MAC), point B stable et sans lien (Configuration BPDU
     périodiques normales uniquement). Détecté et remonté correctement
     en console (« 2 changement(s) de topologie, 1 reelection(s) de
     racine », avec l'exemple « racine changee de 32768/aa:aa:aa:aa:
     aa:01 vers 32768/aa:aa:aa:aa:aa:02 »), dans le triage et dans le
     JSON (deux findings catégorie "STP" distincts, un par compteur).
     **Section "Pertes" du rapport texte : "aucune détectée"** malgré du
     trafic STP multicast présent uniquement au point A -- confirme
     concrètement que l'extension du correctif `correlate()` fonctionne.
  2. Trafic STP stable et périodique uniquement (même capture des deux
     côtés) : aucun faux positif, message par défaut "aucune instabilité
     STP détectée" affiché.
- **Outillage qualité** : `ruff check` (0 erreur après correction du
  F841 ci-dessus), `ruff format --check` (49 fichiers conformes),
  `PYTHONPATH=src lint-imports` (aucun cycle introduit, 1 contrat
  respecté), `pre-commit run --all-files` (les 3 hooks passent) -- tous
  rejoués réellement sur un dépôt git temporaire créé pour l'occasion
  (supprimé après coup).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 -- trois nouveaux paragraphes
  (`pcap_parser` pour le décodage STP, `netcross_core.correlate` pour
  l'extension de l'exclusion à STP, `netcross_core.analysis` pour le
  détecteur lui-même) ; section 4 -- nouvelle sous-section "Analyse L2 --
  instabilité STP (Session 25)" en tête, avant la Session 24 ; section
  5.2 -- ligne "Analyse L2 (ARP/STP)" marquée entièrement faite (ARP en
  Session 24, STP en Session 25), avec la limite du "flapping de port"
  documentée comme architecturale plutôt que comme reliquat.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouvelle entrée "Fonctionnalités" pour la détection
  d'instabilité STP ; nouvelle entrée dans "Limites connues" ("flapping
  de port" non observable depuis une capture, limite architecturale) ;
  compteur de tests mis à jour (490 → 514).

