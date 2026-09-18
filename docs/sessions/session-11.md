# Session 11 — négociation des options TCP (MSS/Window Scale/SACK)

### Demande initiale

"Continuer" (puis "continue tu fais du bon travail") — reprise directe
après la Session 10, même consigne de fond. Accès à un vrai `tshark`
toujours disponible (même conteneur, troisième session consécutive).

### Choix de la feature suivante

`FEATURES.md` section 5.2, 🟠 urgence moyenne : "Négociation options TCP
(MSS/Window Scale/SACK) | `tcp.options.mss_val` disponible nativement
côté tshark ; symptômes proches du PMTUD mais cause différente au
handshake". Choisie parmi les candidats restants (comparaison client vs
client, résolution DNS, sortie JSON structurée) parce que c'est la seule
qui bénéficie directement de l'accès actuel à un vrai `tshark` — un
avantage rare qu'il valait mieux exploiter maintenant plutôt que de le
garder pour une feature (JSON structuré notamment) qui n'en a de toute
façon pas besoin et peut attendre une session sans cet accès.

### Ce qui a été livré

**Recherche empirique préalable** (même discipline que les Sessions 9 et
10) : pcap `scapy` avec un vrai SYN portant les trois options (MSS,
WScale, SACK Permitted) et un second SYN n'en portant qu'une partie,
décodés par le vrai `tshark -T ek`. Résultat, plus simple que la
découverte de la Session 10 : `tcp.options.mss_val` et
`tcp.options.wscale.shift` sont des champs de protocole ORDINAIRES
(comme `ip.flags.df` en Session 9), simplement absents du layer quand
l'option n'est pas dans le paquet — pas de niveau `_ws_expert` à gérer
ici. `tcp.options.sack_perm` n'a pas de valeur numérique exploitable
(option à longueur fixe, valeur brute `"04:02"` = les octets de
l'option elle-même) : seule sa présence comme clé compte, exposée
directement en `bool`.

**`RawPacket`/`Pkt`** : trois nouveaux champs `mss_val`/`wscale_shift`
(`int | None`) et `sack_permitted` (`bool`), présents uniquement sur les
paquets SYN/SYN-ACK (absents, donc `None`/`False`, sur tout autre
paquet — pas de garde explicite nécessaire côté code, tshark ne les émet
simplement pas ailleurs).

**`netcross_core.analysis._analyse_tcp_options(r, flows, pairs,
nat_tolerant, points_order)`** — même schéma de corrélation que
`_analyse_pmtud`/`_analyse_handshake` : pour chaque flux TCP dont le
premier paquet porte le flag SYN, compare les options du même paquet
observé à deux points adjacents. Contrairement à `_analyse_pmtud`, pas
de condition de perte à vérifier ici (le paquet doit au contraire avoir
été vu aux DEUX points pour que la comparaison ait un sens) :
- `mss_clamped` : la valeur change entre les deux points (comparaison de
  valeur, pas de présence — un équipement qui clampe le MSS le fait
  généralement des deux côtés d'un tunnel, en modifiant l'option plutôt
  qu'en la retirant) ;
- `wscale_stripped`/`sack_stripped` : l'option est présente en amont
  mais absente en aval (comparaison de présence, la valeur elle-même
  n'a pas de sens à comparer pour SACK Permitted, et une modification de
  la valeur de Window Scale en cours de route sans rupture de la
  correlation par 5-tuple/`seq` serait de toute façon un événement
  distinct, pas rencontré dans les captures de test).

Désactivé en mode `--nat-tolerant` (comme `_analyse_handshake`) : sans
corrélation stricte par 5-tuple, rien ne garantit que le paquet comparé
aux points A et B est bien le même événement sur le fil.

**Câblage, automatique, sans nouveau flag CLI** (même schéma que PMTUD
et la classification de retransmission) : `synthesis.build_findings`
(catégorie "TCP", sévérités différenciées : `mss_clamped` = info,
`wscale_stripped`/`sack_stripped` = a_surveiller) ; nouvelle section
console ; nouvelles comparaisons `baseline_diff` (seuils par défaut pour
`mss_clamped`, `min_delta=1`/`rel_threshold=0.0` comme PMTUD pour les
deux autres — une perte d'option, même unique, est un événement notable) ;
PDF/GUI/triage : aucune ligne de code, même mécanisme générique déjà
vérifié depuis la Session 9.

Une seule correction en cours de route, mineure : `ruff format` a
signalé une ligne trop longue dans le message d'exemple de
`mss_clamped_examples` (dépassement des 120 caractères une fois
assemblée) — reformatée sur deux lignes avant validation, comme la
Session 9 l'avait déjà rencontré une fois.

### Validation

Même rigueur que les sessions précédentes, avec le même accès `tshark` :
- `pytest` : 280 tests, tous verts (263 hérités de la Session 10 + 17
  nouveaux : extraction des 3 champs sur `RawPacket` (3), `_analyse_tcp_
  options` (9), `synthesis` (3), `baseline_diff` (2), section console (1)) ;
- pcap synthétique à deux flux (un MSS clampé, un Window Scale + SACK
  tous deux retirés) sur deux points de capture réels, décodé par le vrai
  `tshark`, rejoué via `parse_capture` → `correlate` → `analyse` : les
  trois compteurs se déclenchent exactement comme prévu, avec les bonnes
  sévérités et le bon message d'exemple pour `mss_clamped` ;
- génération réelle de PDF, texte relu avec `pypdf` : les trois mots-clés
  ("MSS", "Window Scale", "SACK") y apparaissent ;
- rejeu du vrai CLI `cross_capture_analyzer_cli.py --triage` sur ce même
  scénario : section affichée correctement ;
- `ruff check`/`ruff format --check` : 1 fichier reformaté
  (`analysis.py`, la ligne d'exemple trop longue), 0 sur le reste après
  correction ;
- `lint-imports` : contrat toujours respecté (52 fichiers, 113
  dépendances) ;
- `pre-commit run --all-files` (dépôt git temporaire, supprimé ensuite) :
  3/3 hooks passés.

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 1 (263 → 280 tests) ; section 2
  `pcap_parser` (les 3 nouveaux champs, insérés cette fois-ci
  correctement à la fin de la section — vigilance particulière après
  l'erreur de placement corrigée en Session 10) et `netcross_core.
  analysis` (`_analyse_tcp_options` documenté, placé juste après le
  bullet retransmissions) ; section 5.2, ligne déplacée vers ⚠️ urgence
  haute et cochée.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouveau point dans "Ce que fait l'outil" ; pas de
  nouvelle limite ajoutée dans "Limites connues" (contrairement aux deux
  sessions précédentes) — la dépendance à la corrélation stricte par
  5-tuple est déjà documentée pour `_analyse_handshake`/`_analyse_pmtud`
  et s'applique ici de façon identique, sans nuance supplémentaire à
  apporter.

### Non traité dans cette passe

- **`--live` sur `cross_capture_diff_cli.py`** — toujours hors périmètre.
- **Score de confiance/`sample_size`** — toujours différé pour une
  session dédiée transversale.
- **Comparaison client vs client / résolution DNS / sortie JSON
  structurée** — candidats restants, aucun traité ici, une feature à la
  fois. La sortie JSON structurée ne dépendant pas de `tshark`, elle
  reste un bon candidat pour une session future même sans cet accès.
- **Valeur du Window Scale non comparée en cas de changement** (seule la
  présence/absence l'est) — pas rencontré dans les scénarios de test,
  et modifier une valeur sans casser la corrélation 5-tuple/`seq` serait
  un cas plus exotique qu'un simple retrait d'option ; laissé de côté.

