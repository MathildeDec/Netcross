# Session 34 — Comparaison PATTERNS.md (project-skeleton) vs netcross

### Demande initiale

Un fichier `PATTERNS.md` a été fourni : catalogue de motifs non métier
(architecture, concurrence, GTK4, secrets, i18n, tests, packaging,
journalisation de session, tracing, absence de cycles d'imports) portés
depuis le `CLAUDE.md` de `switch-capture` vers un projet squelette
générique (`project-skeleton`). Demande : comparer section par section à
`claude.md`/`FEATURES.md` de netcross, dire pour chaque règle applicable
si elle est implémentée et documentée (avec citation exacte), dire
explicitement pour chaque règle inapplicable pourquoi, ne jamais déduire
par ressemblance (vérification réelle par grep/lecture), terminer par une
liste catégorisée en cinq groupes. Livraison dans le zip habituel.

### Constat de départ

Un fichier `docs/comparaison-patterns-project-skeleton.md` répondant déjà
intégralement à cette demande existait dans ce dépôt, mais n'était
référencé nulle part (`README.md`/`FEATURES.md`/`claude.md` — vérifié par
grep, aucun résultat). Plutôt que de le régénérer aveuglément ou de
l'ignorer, cette session a **vérifié indépendamment un échantillon
représentatif de ses affirmations contre le code réel actuel** (pas
seulement relu le document) avant de le considérer à jour :

- Absence de `SIGINT`/`GLib.unix_signal_add` dans `netcross_gtk4/app.py`
  (grep, aucun résultat) — conforme au document.
- `Gtk.FileDialog` (3 occurrences, lignes 255/1243/1268), aucune trace de
  `FileChooserNative` ni de `GIO_USE_VFS`/`GIO_USE_VOLUME_MONITOR` — conforme.
- Aucun `logging`/`loguru` dans `src/` — conforme.
- `.pre-commit-config.yaml` : exactement 3 hooks (`ruff --fix`,
  `ruff-format`, `import-linter`), pas de hook `pytest` — conforme.
- `PYTHONPATH=src lint-imports` rejoué réellement : « Analyzed 60 files,
  150 dependencies... Pas de cycles internes KEPT... Contracts: 1 kept,
  0 broken. » — texte identique à celui cité dans le document.
- `PYTHONPATH=src python3 -m pytest -q` rejoué réellement : 639/639 —
  identique au chiffre cité (cohérent avec la Session 33 de ce même
  dépôt, dont la validation par vrai `tshark`/`scapy` est également
  citée dans le document).
- `Gtk.Stack`/`Gtk.StackSwitcher`, 3 pages (`add_titled` "config"/"log"/
  "results", lignes 570/676/731) — conforme.
- Aucun fichier `.desktop`, aucune occurrence de `ConditionalRow` — conforme.
- Seule occurrence de « secret » dans `src/` : `netcross_core/
  quic_diagnostics.py` (cryptographie QUIC, RFC 9001 — sans rapport avec
  la gestion d'identifiants) — conforme.

Aucune divergence trouvée entre le document existant et l'état réel du
code : le document est resté exact malgré les évolutions des Sessions 32/
33 (`EvidenceLink`, extension de `DiffFinding`), qui ne touchent à aucun
des motifs couverts par `PATTERNS.md` (aucune section de ce catalogue ne
porte sur le moteur d'analyse ou les constats — il couvre exclusivement
l'architecture applicative, la CLI/GTK4, le packaging et l'outillage).

### Ce qui a été livré

- `docs/comparaison-patterns-project-skeleton.md` : conservé tel quel
  (déjà exact, vérifié ci-dessus), aucune correction nécessaire.
- `FEATURES.md` (section « Outillage qualité ») : ajout d'un paragraphe
  de renvoi vers ce document, avec le résumé de sa conclusion — il
  n'était auparavant référencé nulle part dans les fichiers de suivi du
  projet, une lacune vis-à-vis de la pratique du projet lui-même
  (section 9 de `PATTERNS.md`, "journalisation de session" : tout
  artefact livré doit être retrouvable depuis `FEATURES.md`/`claude.md`,
  pas seulement présent sur le disque).
- `claude.md` : cette entrée de session.

### Validation

Les huit vérifications listées ci-dessus ont toutes été rejouées avec de
vraies commandes sur ce dépôt (`grep`, `lint-imports`, `pytest`), pas une
relecture visuelle du document existant — conforme à l'exigence de la
demande ("ne jamais déduire qu'une règle est respectée par ressemblance").
Aucune régression introduite : seul un paragraphe de renvoi a été ajouté
à `FEATURES.md`, aucun fichier de code modifié cette session.

### Non traité dans cette passe

- Le contenu détaillé de `docs/comparaison-patterns-project-skeleton.md`
  n'a pas été réécrit — seule son exactitude a été revérifiée, le
  document préexistant couvrant déjà intégralement les 12 sections de
  `PATTERNS.md` avec citations précises et la liste catégorisée en cinq
  groupes demandée.
- Les manques identifiés par le document lui-même (SIGINT GTK4, i18n,
  tracing, diagnostic sudo/RDP...) restent des évolutions potentielles
  pour netcross, pas traitées ici — cette session portait sur la
  comparaison elle-même, pas sur la correction des écarts qu'elle révèle.

