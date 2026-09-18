# Session 29 — historique inter-runs SQLite (`--history-db`)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 28.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark` (4.2.2), `pytest`/`ruff`/
`import-linter`, `scapy` et un accès réseau étaient **tous disponibles
simultanément** — même situation que les Sessions 9/10/11/14/17/18/19/
20/21/22/24/25/26/27/28. `editcap`/`mergecap` installés au passage avec
le paquet `tshark`. `reportlab`/`matplotlib`/`networkx`/`cryptography`
installés en plus (pas strictement nécessaires à cette feature précise,
mais utiles pour rejouer la suite héritée sans faux négatif sur les
tests `--pdf-report`/`--quic`).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : le seul candidat 🟠 urgence moyenne restant
(validation CAPWAP sur vraie capture vendeur) reste hors d'atteinte sans
matériel réel, comme en Session 28. Côté 🟢, les candidats restants
après `--redact` (Session 28) : "Historique inter-sessions (SQLite)",
CAPWAP Fortinet, ingestion NetFlow/sFlow, capture continue + diff en
direct, pistes GitHub, validations admin. Les quatre derniers écartés
pour la même raison qu'en Session 28 (déjà notée en section 5.2 par la
session précédente) : CAPWAP Fortinet peu couvert même par Wireshark en
natif (post-dissecteur Lua, hors d'atteinte sans trafic vendeur réel) ;
NetFlow/sFlow explicitement qualifié de "chantier plus large, architecture
à part" ; la capture continue explicitement qualifiée de "plus gros
chantier des pistes d'origine [...] à cadrer avant de coder" (donc pas à
coder directement) ; les pistes GitHub purement exploratoires, aucun
engagement pris. Les "validations admin" (.rpm Rocky, gain `--parallel`,
FIXME/licence) explicitement qualifiées "tests/ménage, pas de code" —
donc hors du type de tâche visé ici (une fonctionnalité, pas une
vérification). Reste "Historique inter-sessions (SQLite)" : seul
candidat 🟢 qui soit à la fois un vrai chantier de code et isolé/cadrable
en une seule passe. Retenu.

### Périmètre décidé avant d'écrire le code

- **Désambiguïsation du mot "session"** : la piste s'appelle "Historique
  inter-**sessions**" dans `FEATURES.md`, mais ce mot y a deux sens sans
  rapport dans ce projet — une session de développement Claude (comme
  "Session 29", ce fichier) et une exécution de la CLI (le sens voulu
  par la piste). Décidé de nommer les fonctions `record_run`/
  `record_diff_run` plutôt que `record_session`, pour ne pas entretenir
  la confusion dans le code lui-même. La docstring de module
  (`netcross_report/history.py`) explicite ce choix.
- **Résumé compact par run, pas le détail des constats** : score de
  santé, compteurs par sévérité, points, étiquette libre. Décision prise
  en relisant la justification retenue en section 5.2 ("nouveau
  composant de stockage, pas juste du câblage") — un nouveau composant
  mérite un vrai périmètre propre, pas une duplication du détail déjà
  couvert par `--json-report`/`--pdf-report`/`--detail-csv`. Cette
  décision a eu une conséquence directe sur le câblage CLI : pas besoin
  d'un nouveau mode "interrogation seule sans capture" (`--capture`/
  `--baseline`/`--current` restent `required` sur les deux CLI, jamais
  retouché) — `--history-show` affiche l'historique **après** un run
  normal, jamais à sa place. Une CLI dédiée à l'interrogation pure,
  indépendante d'une analyse, notée comme piste distincte en section 5.2
  pour une session future si le besoin se confirme.

### Piège trouvé en lisant le code avant d'écrire quoi que ce soit

En lisant `cross_capture_analyzer_cli.py` pour situer où calculer le
score de santé nécessaire à l'enregistrement : `findings` (résultat de
`build_findings(r)`) y est **paresseux**, calculé seulement si
`args.triage or args.pdf_report or args.json_report` — contrairement à
`cross_capture_diff_cli.py`, où `findings` (résultat de `diff_reports`)
est **toujours** calculé. Une implémentation naïve de `--history-db` sur
l'analyzer, appelée après ce bloc sans y toucher, aurait donc enregistré
un résumé systématiquement à 0 constat/score 100 dès que ni `--triage`
ni `--pdf-report` ni `--json-report` n'étaient fournis — silencieusement
faux, puisque `--history-db` seul est justement l'usage attendu (un
contrôle périodique n'a pas forcément besoin d'un PDF à chaque fois).
Corrigé en ajoutant `or args.history_db` à la condition qui déclenche le
calcul. Repéré en lisant le CLI existant avant d'écrire le câblage, pas
après un test qui aurait échoué en silence (un score à 100/100 ne lève
aucune exception).

### Décisions de conception

- **Asymétrie `record_run`/`record_diff_run` assumée sur TLS/QUIC** :
  `record_run` intègre `tls_findings`/`quic_findings` au même triage que
  `--json-report` sur un run d'analyse simple (mêmes paramètres,
  `generate_json_report`). `record_diff_run` n'accepte **volontairement
  pas** de paramètres `tls_findings_baseline/current`/
  `quic_findings_baseline/current` : sur un diff, ces deux diagnostics ne
  connaissent qu'un état à un instant donné (pas de vraie diff sémantique,
  voir `--tls`/`--quic` sur `cross_capture_diff_cli.py`), donc ne
  participent déjà à aucun `rank_segments`/`health_score` sur le PDF/JSON
  de diff existants (`generate_json_diff`/`generate_diff_pdf`) — choix de
  reproduire cette asymétrie déjà établie plutôt que d'inventer un
  comportement différent pour l'historique. Vérifié par un test dédié
  (introspection de signature : `tls_findings_baseline` absent des
  paramètres de `record_diff_run`).
- **Schéma SQLite minimal, une seule table** : `runs`, colonnes
  scalaires + JSON sérialisé pour les champs structurés (`points`,
  `finding_counts`, `meta`). Pas de schéma normalisé multi-tables : le
  volume attendu (un résumé par exécution manuelle de CLI, pas un flux
  continu) ne le justifie pas, et une table unique reste trivialement
  lisible par un outil tiers (`sqlite3`, DBeaver...) sans documentation
  supplémentaire — vérifié explicitement en lecture brute `sqlite3.
  connect()` dans un test dédié. `CREATE TABLE IF NOT EXISTS` exécuté à
  chaque connexion (écriture et lecture) : idempotent, pas de migration
  à gérer pour cette v1.
- **`list_history` sur fichier absent renvoie `[]` sans créer le
  fichier** : `sqlite3.connect()` crée le fichier dès la connexion, même
  pour une lecture seule. Sans vérification explicite
  (`os.path.exists()` avant de se connecter), un simple `--history-show`
  sur un chemin encore jamais utilisé aurait créé un fichier `.db` vide
  comme effet de bord surprenant — repéré en écrivant le test
  correspondant avant l'implémentation.
- **Tri par `id` auto-incrémenté, pas par `recorded_at`** : plus récent
  d'abord obtenu via `ORDER BY id DESC` plutôt que sur l'horodatage
  texte stocké — robuste à une horloge système qui reculerait entre deux
  runs (changement d'heure, resynchronisation NTP), l'ordre d'insertion
  restant, par construction, toujours croissant.
- **`--history-show` filtré automatiquement sur `--history-label` si
  elle est fournie pour ce run, pas de flag séparé pour ça** : un run
  étiqueté n'a normalement d'intérêt à comparer que vis-à-vis de runs de
  la même étiquette (même site/scénario) — sans étiquette, montre tout
  le fichier `.db` (utile quand un seul scénario suivi par fichier).
  Évite un flag supplémentaire (`--history-filter` ou équivalent) pour
  un besoin déjà couvert par un flag existant.
- **Compatible avec `--redact` sans restriction** : contrairement à
  `--tls`/`--quic`/`--client-group`, l'historique ne lit ni ne réaffiche
  aucune adresse — seulement un score et des compteurs agrégés. Aucune
  combinaison refusée ; `meta={"Anonymisation": ...}` reporté
  automatiquement dans la ligne SQLite quand `--redact` est actif, même
  plomberie `meta` déjà réutilisée pour PDF/JSON depuis la Session 28.

### Ce qui a été livré

- **`src/netcross_report/history.py`** (nouveau module) : `record_run`,
  `record_diff_run`, `list_history`, `print_history`, dataclass
  `HistoryEntry`. Exporté depuis `netcross_report/__init__.py`
  (`HistoryEntry`, `list_history`, `print_history`, `record_diff_run`,
  `record_run` ajoutés à `__all__`). `sqlite3` (bibliothèque standard,
  comme `json`/`datetime` pour `json_report.py`) : aucune dépendance
  supplémentaire, importé sans garde `try/except` (contrairement à
  `pdf.py`).
- **`cross_capture_analyzer_cli.py`** : `--history-db CHEMIN`,
  `--history-label ÉTIQUETTE`, `--history-show [N]` (`nargs="?"`,
  `const=10`). Validation : `--history-label`/`--history-show` sans
  `--history-db` refusés. Condition de calcul de `findings` étendue à
  `args.history_db` (voir piège ci-dessus). Enregistrement placé après
  le bloc `--json-report`, réutilise `findings`/`tls_findings`/
  `quic_findings` déjà calculés. `meta={"Anonymisation": ...}` reporté
  si `--redact` actif.
- **`cross_capture_diff_cli.py`** : mêmes trois flags, même validation.
  `findings` (résultat de `diff_reports`) déjà systématiquement calculé
  sur ce CLI : aucun ajustement de laziness nécessaire de ce côté.
  Enregistrement placé après le bloc `--json-report`, avant le
  `sys.exit(1)` conditionnel sur régression détectée (code de sortie
  vérifié inchangé, voir Validation).
- **Docstrings de module** (les deux CLI) : nouvel exemple d'utilisation
  `--history-db ... --history-label ... --history-show ...` ajouté à la
  suite des exemples existants.
- **Aucune modification** dans `analysis.py`, `correlate.py`,
  `report_text.py`, `synthesis.py`, `pdf.py`, `json_report.py`,
  `baseline_diff.py`, `client_diff.py`, `redact.py` : la fonctionnalité
  se branche uniquement en aval, sur des `Report`/`Finding`/
  `DiffFinding` déjà entièrement calculés. Seule `triage.py` est
  réutilisée telle quelle (`rank_segments`/`health_score`/
  `health_label`/`HEALTH_LABELS`), aucune modification là non plus.

### Validation

594/594 tests verts (581 hérités + 13 nouveaux dans
`tests/test_history.py` : structure de base de `record_run`/
`record_diff_run`, cohérence du score avec un calcul indépendant via
`triage.rank_segments`/`health_score`, `findings` précalculé non
recalculé — même garde que `json_report.py` — intégration TLS/QUIC sur
`record_run` et son absence volontaire sur `record_diff_run` vérifiée
par introspection de signature, méta/étiquette reportées, ordre plus
récent d'abord et `limit`, filtre par étiquette, absence de fichier créé
sur une lecture à vide, lecture brute `sqlite3` d'un fichier réellement
exploitable par un outil tiers, `print_history` sur liste vide et sur un
run diff). `ruff check`/`ruff format --check` et `PYTHONPATH=src
lint-imports` (59 fichiers, 146 dépendances, aucun cycle) tous
réexécutés après modification, tout passe.

Validation bout-en-bout avec un **vrai `tshark`** et de vrais pcap
`scapy` (pas de mock) : flux TCP de 40 segments entre deux IP réelles,
vu à deux points LAN/WAN, pertes introduites côté WAN par construction
(paquets retirés du pcap WAN mais présents côté LAN) — `--order LAN,WAN`
fourni explicitement, car la corrélation de pertes (`r.loss_count`) ne
s'active que si `points_order` est fourni à `analyse()` (vérifié en
relisant `analysis.py` : un premier essai sans `--order` donnait un
score de santé 100/100 malgré les pertes réellement présentes dans les
pcap, corrigé en ajoutant `--order` au rejeu). Trois runs successifs de
`cross_capture_analyzer_cli.py --history-db` sur le même fichier
(étiquettes `Site-A`, `Site-B`, puis sans étiquette) : score de santé et
compteurs de constats affichés par `--history-show` confirmés cohérents
avec le triage affiché juste au-dessus sur le même run ; `--history-show`
confirmé filtré sur `Site-A` seul quand l'étiquette est fournie pour ce
run, confirmé montrant les trois runs (mélange d'étiquettes) quand elle
ne l'est pas. Un run de `cross_capture_diff_cli.py --history-db` sur le
**même fichier** que les runs d'analyse (baseline = pcap sans
aggravation, courant = pcap avec pertes WAN aggravées, 6→14 paquets
manqués) : régression "Pertes" détectée et reportée dans l'historique
(`run_type="diff"`), lecture brute `sqlite3` confirmant les deux
`run_type` (`analyse`/`diff`) coexistant dans la même table, filtre par
étiquette confirmé fonctionner à travers les deux types. Combinaison
avec `--redact` vérifiée : `meta.Anonymisation` présent dans la ligne
SQLite insérée (lu directement via `sqlite3`, pas seulement via
`list_history`). Code de sortie du CLI diff vérifié inchangé (`exit 1`
sur régression détectée) malgré l'ajout du bloc `--history-db` juste
avant ce test. Les 2 refus (`--history-label`/`--history-show` sans
`--history-db`) rejoués avec le vrai CLI sur les deux outils (message
clair, code de sortie 1, 3 invocations testées au total — 2 sur
l'analyzer, 1 sur le diff).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : nouvelle sous-section `netcross_report.history` en
  section 2 (juste avant `netcross_gtk4.app`, à la place occupée par le
  module le plus récemment ajouté, même convention que `redact` en
  Session 28 et `json_report` en Session 12) ; nouvelle entrée en tête
  de section 4 ("Session 29") détaillant le piège de la condition de
  calcul paresseuse, les décisions de conception et la validation
  complète ; section 5.2, ligne "Historique inter-sessions (SQLite)"
  barrée et marquée faite, nouvelle ligne ajoutée pour la piste laissée
  de côté (CLI d'interrogation seule sans capture).
- **`claude.md`** (ce fichier) : cette section, ajoutée en fin de
  fichier (même remarque qu'en Sessions 27/28 : l'ordre des sections
  n'est déjà plus strictement chronologique depuis la Session 26, non
  corrigé ici, hors périmètre d'une session dédiée à une nouvelle
  fonctionnalité).
- **`README.md`** : nouvelle puce dans "Ce que fait l'outil" ; nouvelles
  puces `--history-db`/`--history-label`/`--history-show` dans "Options
  utiles" (CLI analyzer) et dans les options du CLI diff ; nouvelle
  entrée dans "Limites connues" (résumé seulement, pas de mode
  interrogation seule, asymétrie TLS/QUIC sur diff, GUI non câblée) ;
  compteur de tests corrigé (581 → 594).

### Non traité dans cette passe

- **CLI d'interrogation seule de l'historique** (sans `--capture`/
  `--baseline`/`--current`) — écarté du périmètre dès la phase de
  cadrage (voir "Périmètre décidé avant d'écrire le code" ci-dessus).
  `--history-show` reste conditionné à l'exécution d'un run normal.
  Nouvelle entrée ajoutée en section 5.2 pour une session future si le
  besoin se confirme.
- **GUI GTK4** — pas de champ `--history-db` dans l'interface graphique.
  PyGObject/GTK4 indisponible dans cet environnement pour valider
  visuellement/fonctionnellement un câblage (contrairement aux deux CLI,
  entièrement rejouées avec un vrai `tshark`), et la GUI n'est de toute
  façon couverte par aucun test automatisé dans ce projet à ce jour —
  décision assumée, pas un oubli, même situation qu'en Session 28.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  autre candidat 🟠 restant, toujours hors d'atteinte sans matériel/
  trafic vendeur réel.
- **Rapprochement TLS/QUIC avec le score de l'historique sur un diff**
  (`record_diff_run`) — asymétrie assumée avec `record_run`, voir
  "Décisions de conception" ci-dessus ; retravailler ce point
  demanderait d'abord de retravailler `generate_json_diff`/
  `generate_diff_pdf` de la même façon (chantier plus large que cette
  seule fonctionnalité, non entamé ici).

