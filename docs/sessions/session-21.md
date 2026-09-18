# Session 21 — fragmentation IPv6

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 20.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark`, `pytest`/`ruff`/
`import-linter`/`pre-commit` et `scapy` étaient **tous disponibles
simultanément** (accès réseau disponible, `apt-get install tshark`
et `pip install pytest ruff import-linter scapy` tous réussis sans
erreur) — situation identique aux Sessions 9/10/11/14/17/18/19/20,
différente de la majorité des sessions précédentes. `tshark` 4.2.2,
comme toutes les sessions précédentes qui ont eu ce même accès. Suite
`pytest` rejouée avant toute modification : 432/432 verts (aucune
régression héritée de la Session 20).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : le seul candidat 🟠 urgence moyenne restant
après la Session 20 (validation CAPWAP sur vraie capture vendeur
Aruba/Cisco/Fortinet) reste hors d'atteinte sans matériel/trafic réel,
quel que soit l'outillage logiciel disponible. Passage à la section 🟢
urgence faible : "Fragmentation IPv6" retenue — seule ligne de ce
tableau formulée comme un doute non résolu ("trou identifié à
l'origine, non confirmé comme corrigé") plutôt que comme une évolution
à construire depuis zéro, et le fait d'avoir `tshark` disponible cette
session permettait justement de lever ce doute empiriquement plutôt que
de devoir à nouveau le laisser ouvert faute d'environnement adéquat —
même raisonnement "correspond à l'outillage disponible cette session"
que les Sessions 9/13/17 en leur temps.

Confirmation immédiate que le trou était réel (pas juste un doute
théorique) en relisant `pcap_parser/packet.py` : la branche IPv6 de
`build_packet()` mettait inconditionnellement `is_fragment = False` et
ne renseignait jamais `ip_id`, contrairement à la branche IPv4 qui lit
`ip.flags.mf`/`ip.frag_offset`/`ip.id`. `README.md` contenait même un
renvoi orphelin ("voir aussi la fragmentation IPv6 ci-dessus") pointant
vers un paragraphe qui n'existait pas encore — signe que cette lacune
avait déjà été anticipée dans la documentation sans jamais être comblée
dans le code.

### Exploration empirique préalable (avant tout code)

Même discipline que PMTUD/retransmissions/options TCP/HTTP en leur
temps (Sessions 9-11/17) : générer un vrai scénario IPv6 fragmenté et
inspecter la sortie `tshark -T ek` brute avant d'écrire quoi que ce
soit.

```python
from scapy.all import *

pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=12345, dport=53) / Raw(load=b"A" * 3000)
frags = fragment6(pkt, 1280)
wrpcap("ipv6_frag_test.pcap", frags)  # 3 fragments
```

Rejoué par un vrai `tshark -r ipv6_frag_test.pcap -T ek`. Deux
découvertes qui ont directement influencé la conception :

1. **Le PREMIER fragment porte déjà l'en-tête Fragment** (offset=0,
   more=True), pas seulement les fragments suivants — intuition à
   corriger : il n'y a pas de "premier fragment sans en-tête Fragment"
   à distinguer d'un paquet non fragmenté par sa seule présence/absence
   de couche `tcp`/`udp` (voir point 2 ci-dessous). Le nom de couche EK
   réel : `ipv6["ipv6_fraghdr"]` (imbriqué dans la couche `ipv6`, pas une
   couche EK de premier niveau à part), avec les sous-champs
   `ipv6_fraghdr_ipv6_fraghdr_ident` (identifiant 32 bits, hexadécimal
   préfixé `"0x711aec75"`), `_offset` (décimal, en unités de 8 octets)
   et `_more` (booléen JSON natif, comme `ip.flags.df`/`.mf` déjà vérifié
   en Session 9 côté IPv4).
2. **tshark ne dissèque la couche transport (UDP/TCP) que sur le
   fragment qui complète la réassemblage** — les fragments précédents
   n'exposent que `data` (charge utile brute) en plus de `ipv6`/`frame`,
   pas de couche `udp`/`tcp`. Comportement de la réassemblage tshark par
   défaut (`ip.defragment`), pas spécifique à ce projet ni à ce test —
   confirmé cohérent avec le comportement déjà connu côté IPv4 (le code
   existant gérait déjà ce cas via le repli générique `proto = "IP"` en
   l'absence de couche `tcp`/`udp`/`icmp` identifiée, aucun changement
   nécessaire ici).

### Implémentation

`pcap_parser/packet.py`, branche `elif ip6 is not None:` de
`build_packet()` : lecture de `ip6["ipv6_fraghdr"]` (normalisée
liste/dict par prudence, comme `layer()`/`innermost()` — jamais observée
en liste sur les captures de test, RFC 8200 n'autorisant qu'un seul
en-tête Fragment par datagramme, mais coût de la tolérance nul). Si
présent : `is_fragment = True`, `ip_id` = l'identifiant 32 bits parsé via
`hex_or_dec_to_int()` (déjà existant, gère la forme hexadécimale
préfixée). Si absent : `is_fragment = False`, `ip_id` reste `None` —
comportement inchangé pour tout datagramme IPv6 jamais fragmenté (déjà
le comportement avant cette session, test `test_build_packet_ipv6`
préexistant toujours vert sans modification).

**Aucun changement dans `netcross_core.analysis`** : le bloc
"fragmentation / MTU" (`r.frag_count`, `r.frag_new`,
`r.encap_frag_correlated`) était déjà entièrement générique sur
`pk.ip_id`/`pk.is_fragment`, sans branche par famille d'adresse — la
seule chose qui manquait était que `pcap_parser` les renseigne
réellement côté IPv6. Confirme après coup que cette piste était en
réalité plus proche d'un "câblage à coût faible" (section 4) qu'une
"évolution" au sens plein (section 5.2) — classification historique du
document qui datait d'avant que le code de `analysis.py` soit audité
pour cette session.

### Décision de conception : accepter la limite protocolaire plutôt que la contourner

`ipv6.fragment.id` n'existe QUE sur un datagramme déjà fragmenté — un
datagramme IPv6 jamais fragmenté n'a par construction aucun identifiant
à exposer, contrairement à `ip.id` en IPv4 (champ ordinaire de l'en-tête,
toujours présent, fragmenté ou non). Conséquence directe sur
`r.frag_new`/`r.encap_frag_correlated` (appariement inter-points par
`(src, dst, ip_id)`, voir section "fragmentation / MTU" de
`analysis.py`) : la détection d'une fragmentation qui *apparaît*
nouvellement entre deux points (typiquement un tunnel qui réduit le MTU
disponible en cours de route) ne peut fonctionner côté IPv6 que si le
datagramme est **déjà** fragmenté aux deux points — jamais dans le cas
"non fragmenté en amont, fragmenté en aval" qui est justement le
scénario que `frag_new` sert à détecter.

Option explicitement écartée : traiter l'absence d'`ip_id` comme une clé
de corrélation `None` propre à chaque paquet plutôt que de l'exclure du
suivi (comme le fait déjà le filtre `if pk.ip_id is None: continue` en
tête du bloc, inchangé). Aurait permis de "détecter" un faux `frag_new`
sur n'importe quelle paire de paquets IPv6 non fragmenté/fragmenté du
même flux sans lien réel de causalité entre les deux (contrairement à
IPv4, où le même `ip.id` garantit qu'il s'agit du même datagramme
original) — pire que l'absence de détection actuelle, donc rejeté.

Cette limite est en réalité cohérente avec le protocole plutôt qu'une
faiblesse de l'implémentation : en IPv6, seule la source fragmente
(jamais un routeur intermédiaire en cours de route, contrairement à
IPv4) — le scénario "fragmentation qui apparaît en aval à cause d'un
tunnel" que `frag_new` détecte côté IPv4 n'a donc pas de réel équivalent
réseau côté IPv6 pour commencer.

### Piste identifiée mais volontairement non traitée : décodage ICMPv6

En creusant cette feature, confirmation que ce projet ne décode toujours
pas ICMPv6 : `pcap_parser/tunnels.py::select_innermost_layers()` ne
sélectionne qu'une couche `icmp` (IPv4), pas `icmpv6`. Un paquet ICMPv6
(Echo Request/Reply, Neighbor Discovery, ou *Packet Too Big* — le
message qui aurait permis une détection PMTUD IPv6, déjà documentée
comme hors périmètre depuis la Session 9) est aujourd'hui classé
`proto="IP"` générique par le repli par défaut, sans `icmp_type`/
`icmp_code`. Volontairement pas traité dans cette passe : nécessiterait
une nouvelle couche EK sélectionnée dans `tunnels.py`, une décision de
conception sur le chevauchement avec les champs `RawPacket.icmp_type`/
`icmp_code` existants (les réutiliser tels quels risquerait de mélanger
deux espaces de valeurs différents — les types/codes ICMPv4 et ICMPv6 ne
se recouvrent pas numériquement), et resterait un vrai chantier à part
plutôt qu'une extension mineure de la fragmentation IPv6 visée ici.
Ajoutée à `FEATURES.md` section 5.2 comme nouvelle piste distincte pour
une session future.

### Validation effectuée

- **Tests unitaires** : suite complète rejouée avant toute modification
  (432/432 hérités de la Session 20, aucune régression préalable). 4
  nouveaux tests dans `tests/test_packet.py`
  (`test_build_packet_fragment_ipv6_premier_fragment`,
  `test_build_packet_fragment_ipv6_dernier_fragment` — vérifient que le
  même `ip_id` est bien extrait sur le premier ET le dernier fragment,
  pas seulement un des deux —,
  `test_build_packet_ipv6_non_fragmente_pas_dip_id` — cas négatif
  explicite, absence de la clé plutôt qu'une valeur vide —, et
  `test_build_packet_ipv6_fraghdr_normalise_liste` — tolérance
  défensive) et 3 dans `tests/test_analysis.py`
  (`test_frag_count_generique_ipv6` — le compteur brut fonctionne sans
  aucune modification d'`analysis.py` —,
  `test_frag_new_ipv6_fonctionne_si_deja_fragmente_aux_deux_points` — cas
  positif de la corrélation IPv6 —, et
  `test_frag_new_ipv6_ne_detecte_pas_une_nouvelle_fragmentation_sans_ip_id_amont`
  — la limite assumée documentée ci-dessus, testée explicitement plutôt
  que laissée implicite, par symétrie avec le test IPv4 existant
  `test_fragmentation_nouvelle_apparait_entre_points`) — **439/439** au
  total, aucune régression.
- **Bout en bout réel** : scénario à 2 points construit avec de vrais
  pcap scapy et un vrai `tshark` — point A : un datagramme IPv6 UDP de
  3000 octets fragmenté en 3 via `fragment6(pkt, 1280)` ; point B : le
  même datagramme (mêmes adresses/ports/charge utile) non fragmenté.
  Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --capture A=... --capture B=...
  --order A,B --pdf-report --json-report --triage`) : section console
  "Fragmentation / MTU" affiche correctement `A : 3 paquets fragmentés
  vus` ; PDF (176 Ko) et JSON générés sans erreur ; JSON relu et vérifié
  qu'aucun `Finding` de fragmentation n'est présent (cohérent avec la
  limite documentée : `r.frag_new` reste à 0 entre A et B puisque le
  paquet du point A n'a pas d'`ip_id` à apparier — confirmé empiriquement,
  pas seulement en théorie).
- **Outillage qualité** : `ruff check` (0 erreur), `ruff format --check`
  (49 fichiers déjà conformes, aucun reformatage nécessaire cette fois),
  `PYTHONPATH=src lint-imports` (aucun cycle introduit, 1 contrat
  respecté), `pre-commit run --all-files` (les 3 hooks passent) — tous
  rejoués réellement sur un dépôt git temporaire créé pour l'occasion
  (`pre-commit` a besoin d'un `.git/`, absent de l'archive livrée par
  construction, supprimé après coup).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 (`pcap_parser`) — nouveau paragraphe
  détaillant la fragmentation IPv6, la limite protocolaire assumée et la
  piste ICMPv6 identifiée ; section 4 — nouvelle sous-section "Fragmentation
  IPv6 (Session 21)" en tête, avant la Session 20 ; section 5.2 — ligne
  déplacée vers "fait", nouvelle ligne "Décodage ICMPv6" ajoutée comme
  piste distincte issue de cette session.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouvelle entrée dans "Limites connues" (fragmentation
  IPv6, juste avant le paragraphe PMTUD qui y faisait déjà un renvoi
  orphelin — désormais résolu) ; compteur de tests corrigé (432 → 439).

### Non traité dans cette passe

- **Décodage ICMPv6** — voir discussion de conception ci-dessus ; nouvelle
  piste distincte en section 5.2, pas une extension mineure de cette
  session.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  autre candidat 🟠 restant, toujours hors d'atteinte sans matériel/trafic
  vendeur réel, quel que soit l'outillage logiciel disponible.

