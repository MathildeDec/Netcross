# Session 27 — fusion de captures segmentées (`NOM=chemin1,chemin2,...`)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 26.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark`, `pytest`/`ruff`/
`import-linter`/`pre-commit`, `scapy` et un accès réseau étaient **tous
disponibles simultanément** (`apt-get install tshark` et `pip install
pytest ruff import-linter pre-commit scapy` tous réussis sans erreur) —
même situation que les Sessions 9/10/11/14/17/18/19/20/21/22/24/25/26.
`editcap`/`mergecap` installés au passage avec le paquet `tshark`
(binaires de la suite Wireshark). Suite `pytest` rejouée avant toute
modification : 540/540 verts (aucune régression héritée de la Session 26).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : le seul candidat 🟠 urgence moyenne restant
(validation CAPWAP sur vraie capture vendeur) reste hors d'atteinte sans
matériel/trafic réel, quel que soit l'outillage disponible. Côté 🟢,
"Anonymisation (`--redact`) / fusion de captures segmentées" regroupait
deux idées sans rapport technique — scindée en deux lignes distinctes
avant de choisir : `--redact` réécrit des adresses dans des paquets déjà
chargés (nouvelle machinerie de transformation), la fusion change
uniquement la façon de charger des fichiers déjà pris en charge par le
pipeline existant. Retenue : la fusion, nettement plus "câblage" que
"nouveau moteur" — même critère de sélection que les sessions
précédentes qui ont privilégié le candidat le plus isolé/rapide à cadrer
correctement en une seule passe (PMTUD en Session 9, JSON en Session 12,
DNS en Session 13...).

### Constat clé, trouvé en lisant le code avant d'écrire quoi que ce soit

`--capture NOM=chemin` (et `--baseline`/`--current` sur le CLI de diff)
n'acceptait qu'un seul fichier par point — une capture segmentée par
rotation (`tcpdump -C`/`tshark -b`) obligeait donc à fusionner les
segments au préalable avec un outil externe (`mergecap`) avant de les
donner à netcross. En lisant `main()` des deux CLI avant d'écrire le
moindre code, découverte que le mécanisme qui rend cette fonctionnalité
"quasi gratuite" existait déjà sans que personne ne l'ait exploité ni
documenté : `captures` est une simple liste de tuples `(label, chemin)`,
jamais dédupliquée ni indexée par label, et la boucle de chargement
séquentielle (`for label, path in captures: ... all_packets.extend(pkts)`)
concatène déjà tout ce qu'elle contient quel que soit le nombre
d'entrées portant le même label. Fournir deux fois le même label aurait
donc déjà "fonctionné" avant cette session (jamais testé ni présenté
comme un cas d'usage). Cette session n'ajoute donc aucune nouvelle
machinerie de décodage/corrélation : elle expose une syntaxe explicite
(`NOM=chemin1,chemin2,...`, virgules — même convention que
`--client-group NOM=IP1,IP2` en Session 14) sur un mécanisme déjà
présent, avec la validation qui allait avec.

### Ce qui a été livré

- **`cross_capture_analyzer_cli.py`** : nouvelle fonction pure
  `_parse_capture_spec(spec, flag_name)` (`NOM=chemin1[,chemin2,...] ->
  (label, [chemin1, chemin2, ...])`), même style que
  `_parse_client_group_spec` déjà présente dans ce fichier. Validation :
  format sans `=` refusé, label vide refusé, tout segment de chemin vide
  refusé (ex: virgule en trop en fin ou au milieu de liste) — message
  d'erreur explicite dans chaque cas, `sys.exit(1)`. La boucle de
  construction de `captures` dans `main()` appelle cette fonction puis
  étale (`extend`) une entrée `(label, path)` par chemin.
- **`cross_capture_diff_cli.py`** : `_parse_capture_args` (fonction
  existante, déjà partagée par `--baseline`/`--current`) étendue avec la
  même logique de split/validation — pas de nouvelle fonction ici,
  contrairement à l'autre CLI, puisque cette fonction faisait déjà le
  travail d'aplatissement `raw_list -> captures` que `_parse_capture_spec`
  vient tout juste d'introduire côté analyzer CLI.
- **`--parallel` en profite automatiquement, sans aucune modification**
  de `parse_captures_parallel`/`_load_packets` : chaque segment devient
  sa propre entrée `(label, chemin)`, donc son propre processus `tshark`
  — une capture très segmentée peut gagner plus de parallélisme qu'un
  seul gros fichier par point.
- **Décision assumée** : aucun tri par timestamp des paquets fusionnés,
  les segments doivent être listés par l'appelant dans l'ordre
  chronologique. Vérifié avant de prendre cette décision que les deux
  seules analyses sensibles à l'ordre au sein d'un même point
  (`_analyse_stp_instability` Session 25, `_analyse_idle_timeout`
  Session 23) trient déjà explicitement en interne (`sorted()`/`.sort()`)
  plutôt que de faire confiance à l'ordre de `all_packets` — un tri
  global supplémentaire ici aurait été un coût sans bénéfice réel de
  justesse, seulement de confort d'affichage.
- **Aidé et vérifié empiriquement plutôt que supposé possible** : la
  suite Wireshark installe `editcap`/`mergecap` aux côtés de `tshark` —
  confirmé disponible dans cet environnement (`which mergecap`), mais
  volontairement **pas utilisé** dans l'implémentation : fusionner en
  Python (lire chaque segment séparément via le pipeline `tshark -T ek`
  déjà en place, puis concaténer les `Pkt` obtenus) évite une dépendance
  supplémentaire à un second binaire externe et un fichier temporaire à
  gérer/nettoyer, pour un résultat strictement équivalent sur les
  scénarios testés (voir Validation).

### Validation

- **Tests unitaires** : suite complète rejouée avant toute modification
  (540/540 hérités de la Session 26, aucune régression préalable). 14
  nouveaux tests dans `tests/test_capture_segments.py` — fonctions de
  parsing pures des deux CLI (chemin unique, plusieurs chemins,
  tolérance aux espaces autour des virgules, format invalide, label vide,
  segment vide en fin/au milieu de liste), et deux scénarios bout-en-bout
  par CLI (`parse_capture` monkeypatché pour retourner des paquets
  différents selon le chemin reçu, afin de confirmer que les segments
  sont bien concaténés dans le `Report` final — via `r.seen_count`
  affiché en console — et pas seulement dans la liste intermédiaire
  `captures`) — **554/554** au total, aucune régression. Trois
  corrections `ruff` (`PERF401` × 2, boucles `for ... append` réécrites
  en `list.extend(... for ...)` ; `RUF059`, variable `label` non utilisée
  renommée `_label` dans un test) appliquées avant la validation finale.
- **Bout en bout avec un vrai `tshark` et de vrais pcap `scapy`** : un
  flux TCP de 6 paquets généré en un seul fichier (`lan_full.pcap`) puis
  rejoué une seconde fois découpé en deux fichiers de 3 paquets chacun
  (`lan_seg1.pcap`/`lan_seg2.pcap`, simulant une rotation `tcpdump -C`).
  Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --capture LAN=lan_seg1.pcap,lan_seg2.pcap`) :
  6 paquets comptés au point LAN, identique au fichier unique non
  segmenté — chaque segment rapporté séparément en console (`[LAN] 3
  paquets ... depuis lan_seg1.pcap`, puis `lan_seg2.pcap`). Confirmé
  aussi avec `--parallel` (deux lignes de timing distinctes, une par
  segment) et côté CLI de diff (`--baseline LAN=base1.pcap,base2.pcap
  --current LAN=full.pcap`, les deux segments du baseline rapportés
  séparément sous `[baseline/LAN]`). Erreur de format (virgule en trop)
  testée avec le vrai CLI : message d'erreur clair mentionnant le bon
  nom de flag (`--capture`), code de sortie 1.
- **Outillage qualité** : `ruff check` (0 erreur après les 3 corrections
  ci-dessus), `ruff format --check` (50 fichiers conformes),
  `PYTHONPATH=src lint-imports` (55 fichiers, 131 dépendances, aucun
  cycle, 1 contrat respecté), `pre-commit run --all-files` (les 3 hooks
  passent) — tous rejoués réellement sur un dépôt git temporaire créé
  pour l'occasion (supprimé après coup, comme les sessions précédentes).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 (CLIs) — nouveau paragraphe détaillant
  la syntaxe `NOM=chemin1,chemin2,...`, le mécanisme déjà présent
  exploité, et la synergie avec `--parallel` ; section 4 — nouvelle
  sous-section "Fusion de captures segmentées (Session 27)" en tête,
  avant la Session 26 ; section 5.2 — la ligne groupée "Anonymisation /
  fusion" scindée en deux, seule la fusion marquée faite,
  l'anonymisation (`--redact`) restant ouverte comme piste distincte.
- **`claude.md`** (ce fichier) : cette section, ajoutée en fin de
  fichier (l'ordre des sections précédentes dans ce fichier n'est déjà
  plus strictement chronologique depuis l'insertion de la Session 26 —
  non corrigé ici, hors périmètre d'une session dédiée à une nouvelle
  fonctionnalité).
- **`README.md`** : nouvelle puce dans "Options utiles" (section CLI)
  documentant `--capture NOM=chemin1,chemin2,...` ; nouvelle entrée en
  tête de "Limites connues" (pas de tri par timestamp, à lister dans
  l'ordre chronologique) ; compteur de tests corrigé (540 → 554).

### Non traité dans cette passe

- **Anonymisation (`--redact`)** — scindée de la piste d'origine, reste
  ouverte comme candidat distinct en section 5.2 : nécessiterait une
  vraie transformation des adresses/identifiants dans les paquets déjà
  chargés (nouveau composant), pas seulement un changement de la façon
  de les charger.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  autre candidat 🟠 restant, toujours hors d'atteinte sans matériel/
  trafic vendeur réel, quel que soit l'outillage logiciel disponible.
- **GUI GTK4** — pas de sélecteur de fichiers multiples pour un même
  point dans l'interface graphique ; la fonctionnalité reste pour
  l'instant limitée aux deux CLI, cohérent avec le fait qu'elle
  nécessiterait un vrai travail d'interface (widget de sélection
  multi-fichiers), pas un simple câblage.

