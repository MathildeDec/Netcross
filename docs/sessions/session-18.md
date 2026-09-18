# Session 18 — Score de santé synthétique (0-100)

Demande : "Continue les features à faire" — reprise de la liste 🟠/🟢 de
`FEATURES.md` section 5.2. Seul item 🟠 restant (validation CAPWAP sur
vraie capture Aruba/Cisco/Fortinet) nécessite du vrai matériel/trafic
vendeur indisponible ici ; parmi les 🟢, retenu : **score de santé
synthétique (0-100)**, seule entrée explicitement qualifiée "coût faible,
calculable à partir du triage déjà existant".

### Environnement

`tshark` **et** `pytest` **et** `editcap` tous les trois disponibles
simultanément cette session (installés en tout début de session via
`apt-get`/`pip` — accès réseau disponible) — rare, voir Sessions
9/10/11/14/17 pour les précédents. Suite héritée rejouée avant tout
nouveau code : 399/399 verts, confirmant l'absence de régression
préalable.

### Conception

`health_score(ranked)` dans `netcross_report/triage.py` : décroissance
exponentielle (`100 * exp(-total/HEALTH_SCORE_SCALE)`, `HEALTH_SCORE_SCALE
= 12.0`) de la somme des scores de segment déjà produits par
`rank_segments()` — jamais un recalcul indépendant depuis les findings
bruts, pour garantir que le score affiché est toujours cohérent avec le
triage affiché à côté (même donnée, condensée). Décroissance exponentielle
choisie plutôt qu'une soustraction linéaire plafonnée à 0 : une dizaine de
constats mineurs ne doit pas mécaniquement écraser le score à zéro de la
même manière qu'une grosse anomalie unique, et le résultat reste
strictement borné dans [0, 100] sans seuil de coupure arbitraire à
documenter à part. La constante d'échelle (12.0) est calibrée
empiriquement, pas issue d'une norme : choisie pour qu'une seule anomalie
isolée (score de segment 3.0, voir `DEFAULT_SEVERITY_WEIGHTS`) fasse déjà
sortir le score de la tranche "bon" (>= 85) sans l'écraser à elle seule —
documenté comme tel dans le docstring plutôt que présenté comme un calcul
objectif.

4 tranches (`HEALTH_LABEL_THRESHOLDS`) : bon (>=85) / à surveiller (>=60)
/ dégradé (>=35) / critique (<35), avec un libellé affichable
(`HEALTH_LABELS`) distinct de la clé courte utilisée en JSON (même choix
que `severity`/`category`, qui exposent déjà des clés courtes plutôt que
du texte français directement consommable par un pipeline externe).

Même duck-typing que `rank_segments`/`print_triage` : fonctionne
indifféremment sur `Finding` (score "instantané" d'un run) et
`DiffFinding` (ici le score reflète l'ampleur des régressions détectées
entre baseline et courant — 100 = aucune régression significative, pas
"réseau parfait", même réserve d'interprétation que le reste du module sur
un diff). Décision assumée : ne PAS distinguer les deux cas dans le nom de
la fonction ou le libellé — le sens se déduit du contexte (quel triage a
produit `ranked`), comme pour `rank_segments`/`print_triage` déjà
génériques sur les deux vocabulaires.

`format_health_line(score)` : rendu texte unique partagé entre les deux
CLI et les deux points d'accroche GTK4, pour que le texte affiché ne
puisse pas diverger légèrement d'un endroit à l'autre.

### Câblage

- `netcross_report/__init__.py` : exports `health_score`, `health_label`,
  `format_health_line`, `HEALTH_LABELS`.
- `cross_capture_analyzer_cli.py`/`cross_capture_diff_cli.py` : affiché en
  console juste après `print_triage`, sous le même flag `--triage` (pas de
  nouveau flag — même raisonnement "câblage à coût faible" que les
  fonctionnalités automatiques précédentes DNS/HTTP/PMTUD).
- `netcross_gtk4/app.py` : les 2 points d'accroche existants du triage
  (mode fichier et mode live) impriment aussi la ligne de score dans le
  buffer de sortie.
- `netcross_report/json_report.py` : clés `health_score` (entier) et
  `health_label` (clé courte) ajoutées au niveau racine du document, dans
  `generate_json_report` **et** `generate_json_diff`.
- `netcross_report/pdf.py` : nouvelle fonction `_health_badge(ranked,
  styles)` — paragraphe coloré (`HEALTH_BADGE_COLORS`, une couleur par
  tranche, palette cohérente avec `SEVERITY_COLORS` existant) affiché
  juste au-dessus de la table de triage, dans `generate_pdf` **et**
  `generate_diff_pdf`.

### Validation

12 nouveaux tests, tous `pytest` réels :
- `tests/test_triage.py` (8 tests) : `ranked` vide -> 100/bon ; score
  toujours borné [0, 100] même avec un grand nombre de segments à fort
  score ; décroissance strictement monotone avec plus de findings ; une
  anomalie isolée sort de la tranche "bon" sans être écrasée (calibration
  documentée ci-dessus, testée explicitement) ; générisme sur le
  vocabulaire `DiffFinding` (même poids que `Finding` pour une sévérité de
  poids équivalent) ; les 4 seuils de `health_label` testés à leurs bornes
  exactes ; `format_health_line` contient bien le score et le libellé.
- `tests/test_json_report.py` (4 tests) : `health_score`/`health_label`
  exposés cohérents avec un recalcul indépendant côté test (pas une
  simple présence de clé) sur `generate_json_report` et
  `generate_json_diff`, plus le cas 100/bon sans finding pour les deux.

411/411 au total (399 hérités + 12 nouveaux), aucune régression.
`ruff check`, `ruff format --diff` (49 fichiers déjà formatés,
aucun changement nécessaire), `PYTHONPATH=src lint-imports` (aucun cycle,
1 contrat respecté) et `pre-commit run --all-files` (les 3 hooks) rejoués
réellement — tout passe.

**Validation bout-en-bout avec du vrai trafic**, au-delà des tests
unitaires, profitant de la disponibilité simultanée rare de
`tshark`/`pytest`/`editcap` cette session : contrairement aux sessions
précédentes qui monkeypatchaient `parse_capture`/`parse_live` avec des
paquets synthétiques (tshark absent), cette fois un vrai serveur HTTP
(`http.server` standard) a été lancé sur `127.0.0.1`, capturé en direct
sur l'interface `lo` par un vrai processus `tshark`, avec un mélange de
vraies réponses 200/500/404. Un second point de capture a été fabriqué à
partir du premier via `editcap -r` en retirant précisément une
transaction `/error` (requête+réponse) — perte réelle au niveau paquet,
pas une simulation applicative.

Les deux vraies CLI (pas des appels de fonction internes) rejouées de
bout en bout sur ces deux fichiers, avec `--triage --json-report
--pdf-report` simultanément :
- `cross_capture_analyzer_cli.py --capture A=... --capture B=... --order
  A,B` : score de santé 31/100 "Critique" affiché en console, retrouvé à
  l'identique dans le JSON (`health_score`/`health_label`) et dans le PDF
  (badge rouge, page "Par où commencer").
- `cross_capture_diff_cli.py --baseline A=capA --baseline B=capA
  --current A=capA --current B=capB` (baseline = les deux points
  identiques sans perte, courant = la perte réelle injectée côté B) :
  1 régression détectée (taux de perte 0% -> 4.4%), score de santé
  69/100 "A surveiller", cohérent entre console/JSON/PDF (badge ambre).

Badge PDF inspecté visuellement dans les deux rapports via `pdf2image`
(conversion en image, comme la méthode déjà utilisée en Session 8) :
couleur correcte selon la tranche dans les deux cas, position au-dessus
de la table de triage conforme, non-régression du reste du PDF vérifiée
sur la même génération (page synthèse, tableau des constats intacts).

### Fichiers de suivi/documentation mis à jour

- `FEATURES.md` : section 2 (`netcross_report.triage`), section 4
  (nouvelle entrée "Score de santé synthétique — Session 18" en tête,
  avant celle de la Session 17), section 5.2 (entrée barrée avec renvoi).
- `claude.md` : cette entrée.
- `README.md` : mention du score de santé dans la liste de
  fonctionnalités en tête, dans la description de `--triage` des deux
  CLI, et le compteur de tests mis à jour (399 -> 411).

### Non traité dans cette passe

Reste de la section 5.2 de `FEATURES.md`, inchangé par rapport à la fin
de la Session 17 (validation CAPWAP sur vraie capture vendeur, gestion
mémoire des grosses captures, graphiques temporels, TLS approfondi,
analyse L2, fragmentation IPv6, timeout d'inactivité, historique
inter-sessions, anonymisation, CAPWAP Fortinet, NetFlow/sFlow, capture
continue + diff en direct, pistes GitHub, validations admin) — une
feature à la fois, comme convenu.

---

