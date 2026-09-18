# Session 55 — migration `pip` → `uv`, aucune erreur `ruff`, premier pilote du moteur d'exécution de règles

### Demande initiale

« On passe `uv` pour remplacer `poetry`. Correction de toutes les
erreurs `ruff`. Continuer les features à faire. Fait évoluer les
fichiers de suivi, de tests et de documentation. Livraison du zip
horodaté `{YYYYMMDD-HHMMSS}` sans passer à la suite. » — trois demandes
indépendantes en une session, en plus de la consigne récurrente
habituelle.

### 1. Migration `pip` → `uv`

Avant toute action : recherche exhaustive de `poetry` dans le projet
(`grep -ril poetry .`, hors caches `.mypy_cache`/`.ruff_cache`) —
**aucune occurrence**. `pyproject.toml` ne contenait avant cette
session que `[tool.ruff]`/`[tool.ruff.lint]`/
`[tool.ruff.lint.flake8-tidy-imports]`/`[tool.importlinter]` — jamais
de `[tool.poetry]`, et aucun `poetry.lock` livré dans le zip. La
gestion des dépendances réellement en place était `pip install -r
requirements.txt` (+`requirements-dev.txt` pour le dev), documentée
comme repli explicite d'`install.sh` (qui privilégie les paquets
système). La consigne « remplacer poetry » est donc interprétée comme
« remplacer la gestion de dépendances actuelle (pip + requirements*.txt)
par `uv` » — c'est la seule lecture qui a un référent réel dans ce
projet.

**Ce qui a été fait** :

- `pyproject.toml` : ajout de `[project]` (nom, version, description,
  `requires-python`, `dependencies` — mêmes bornes `>=` que
  `requirements.txt`) et `[project.optional-dependencies.dev]` (mêmes
  bornes que `requirements-dev.txt`), plus `[tool.uv] package = false`
  (netcross est une application lancée via `PYTHONPATH=src`, pas une
  bibliothèque distribuée comme wheel — évite d'exiger un
  `[build-system]`/backend de build pour une simple gestion de
  dépendances).
- `requires-python` fixé à `>=3.10`, pas `>=3.9` (la cible historique
  de `ruff target-version`, qui ne contraint que la syntaxe autorisée,
  jamais l'interpréteur minimal d'exécution) : `uv lock` échouait sur
  la résolution de l'extra `dev` (`import-linter>=2.13` exige lui-même
  Python≥3.10 — message d'erreur `uv` explicite, reproduit ci-dessous).
  Aucun changement de syntaxe nécessaire dans `src/` : le code
  applicatif reste compatible 3.9, seule la borne déclarée a changé.

  ```text
  × No solution found when resolving dependencies for split (markers:
    python_full_version > '3.9' and python_full_version < '3.10'):
    ╰─▶ Because the requested Python version (>=3.9) does not satisfy
        Python>=3.10 and import-linter>=2.13 depends on Python>=3.10 [...]
  ```

- `uv lock` : 49 paquets résolus (`uv.lock` livré). `uv sync --extra
  dev` : 39 paquets installés dans `.venv/` (dont `pytest==9.1.1`,
  `ruff==0.16.4` — bien la version épinglée, cohérente avec
  `requirements-dev.txt`/`.pre-commit-config.yaml`, pas seulement la
  dernière disponible —, `import-linter==2.15`, `pre-commit==4.6.2`,
  `cryptography==50.0.1`, `reportlab==5.0.1`, `matplotlib==3.11.2`,
  `networkx==3.6.1`).
- `requirements.txt`/`requirements-dev.txt` **conservés**, pas
  supprimés : `install.sh` les référence encore comme repli documenté
  pour les distributions non reconnues ou sans GTK4 (chemin d'erreur),
  et ce script privilégie de toute façon les paquets système — hors
  périmètre de cette session, non modifié. En-tête des deux fichiers
  mis à jour pour expliquer la bascule et le statut de repli.
  Volontairement **pas régénérés via `uv export`** : testé
  (`uv export --no-dev --no-hashes --no-annotate --no-header`), le
  résultat est un pin transitif complet avec marqueurs de version
  Python (`contourpy==1.3.2 ; python_full_version < '3.11'`, etc.) —
  style radicalement différent des bornes `>=` larges et commentées
  déjà en place, aurait perdu le contexte explicatif existant pour un
  gain nul (ces fichiers ne sont plus le chemin recommandé). Décision :
  les garder synchronisés manuellement avec `pyproject.toml` si les
  dépendances changent, documenté dans leur en-tête.
- `.gitignore` créé (absent du projet avant cette session — zip livré
  sans `.git`, voir CLAUDE.md) : couvre `.venv/` (nouveau, créé par
  `uv sync`) et les caches d'outillage déjà présents dans le zip livré
  (`.mypy_cache/`, `.ruff_cache/`, `.import_linter_cache/`,
  `.pytest_cache/`, `__pycache__/`).
- `README.md` : sections « Tests » et « Qualité de code » mises à jour
  pour mentionner `uv sync --extra dev`/`uv run <commande>` en premier,
  avec le chemin `pip install -r requirements*.txt` gardé en repli
  explicite. Tableau « Architecture du dépôt » : ligne `uv.lock`
  ajoutée, lignes `requirements*.txt`/`pyproject.toml` reformulées pour
  refléter leur nouveau statut.

**Validation** : `uv run pytest` (959/959 à ce stade, avant la feature
ci-dessous), `uv run ruff check .`/`uv run ruff format --check .`
(propres), `PYTHONPATH=src uv run lint-imports` (65 fichiers, 164
dépendances, contrat respecté — inchangé) : migration transparente,
aucune régression.

### 2. Correction de toutes les erreurs `ruff`

`uv run ruff check .` → `All checks passed!`. `uv run ruff format
--check .` → `120 files already formatted`. **Aucune erreur trouvée**,
rien à corriger — état inchangé depuis la Session 50 (qui avait déjà
conclu à 0 erreur avec la même version épinglée `ruff==0.16.4`).

### 3. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 54) laissait deux chantiers
ouverts, aucune décision explicite à trancher (contrairement à la
Session 54 elle-même) :

1. un début de moteur d'EXÉCUTION qui évaluerait une `Rule` du
   catalogue contre un `Report` pour PRODUIRE elle-même un
   `Finding`/`ExpertEvent`, au lieu du sens actuel où `rule_id`
   annote seulement un `Finding` déjà produit par le code procédural ;
2. cause probable/impact — bascule vers la Session 3 (corrélation
   causale, difficulté 5/5).

Retenu : le point 1. Raisons : (a) c'est la suite directe et déjà
nommée par `CLAUDE.md` depuis la Session 54 elle-même (« l'utiliser
[le catalogue] pour PILOTER la détection [...] en est la suite
logique ») — pas un nouveau chantier improvisé cette session ; (b) une
brique préalable existe déjà et est complète (41 règles, catalogue
stable) sur laquelle s'appuyer directement, contrairement à la Session
3 qui démarre de zéro ; (c) un premier PILOTE borné à une seule règle
(même discipline que le pilote `PacketEvidence`/PMTUD de la Session 35,
ou le premier lot `ExpertEvent` de la Session 40) est vérifiable de
bout en bout dans le temps d'une seule session, contrairement à un
moteur de corrélation causale complet.

### Conception : où placer le moteur ?

Point vérifié avant d'écrire le moindre code : produire un `Finding`
exige d'importer `netcross_report.synthesis.Finding`. Le contrat de
couches (`pyproject.toml` `[tool.importlinter]`,
`netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser`)
interdit à `netcross_core` (où vit `expert_rules.Rule`) de dépendre de
`netcross_report`. Le moteur ne peut donc PAS vivre dans
`netcross_core` à côté du catalogue qu'il consomme — il vit dans
`netcross_report`, au même niveau que `synthesis.py`, et importe dans
le sens autorisé (`netcross_report -> netcross_core.expert_rules`).
Vérifié après coup avec `PYTHONPATH=src uv run lint-imports` : 66
fichiers, 168 dépendances, contrat toujours respecté, aucun cycle
introduit.

### Ce qui a été livré

- `src/netcross_report/rule_engine.py` — `evaluate(rule_id: str,
  report: Report) -> list[Finding]`, plus `available_rule_ids() ->
  list[str]`.
- **Une seule règle pilotée** : `loss_per_segment`. Choisie car c'est
  la plus simple du catalogue — un seul seuil numérique nommé
  (`Rule.thresholds["anomalie_rate_pct"]`, 5.0), aucun
  `correlation_rule` (pas de fusion de deux signaux bruts distincts,
  contrairement à saturation/bufferbloat/remarquage QoS/fragmentation/
  PMTUD black hole). L'évaluateur reproduit EXACTEMENT le bloc
  `-- pertes --` de `synthesis.py::build_findings()` (même boucle sur
  `Report.loss_count`/`Report.seen_count`, même message, même
  `sample_size`), avec une seule différence volontaire : le seuil de
  sévérité est lu depuis `rule.thresholds["anomalie_rate_pct"]` plutôt
  que la constante `5` codée en dur côté procédural — c'est
  précisément le sens de « piloter » plutôt qu'« annoter ».
- Les 40 autres règles du catalogue n'ont **pas** d'évaluateur
  enregistré dans `_EVALUATORS` : `evaluate()` lève
  `NotImplementedError` pour elles (jamais un mapping deviné sans
  l'avoir vérifié dans le code procédural existant — même discipline
  que le catalogue lui-même, voir docstring de module
  d'`expert_rules.py`) — distinct de `KeyError` pour un `rule_id`
  totalement absent du catalogue (`get_rule()` renvoie `None`).
- `synthesis.py::build_findings()` **non modifié**, reste l'unique
  chemin de production en CLI/GUI aujourd'hui. `rule_engine.py` est un
  second consommateur indépendant du même `Report`, pas un
  remplacement — la bascule effective (si elle a lieu un jour) est
  explicitement hors périmètre de ce pilote (voir CLAUDE.md).

### Validation

- `tests/test_rule_engine.py` (9 tests) : les trois seuils classiques
  (anomalie ≥5%, à_surveiller <5%, aucun `Finding` si `loss_count==0`,
  calqués sur `test_synthesis.py`), `rule_id`/`category` repris de la
  `Rule` du catalogue, `sample_size`, un test d'**équivalence
  explicite** avec `build_findings()` sur un `Report` à trois points
  (deux comparaisons Finding-par-Finding sur tous les champs), et deux
  tests d'erreur (`KeyError` pour un id inconnu, `NotImplementedError`
  pour `tcp_rst_localized` — une règle réelle du catalogue mais sans
  évaluateur enregistré).
- `pytest` : 959/959 → **968/968** (+9 net).
- `ruff check .`/`ruff format --check .` : propres (le nouveau module
  et son fichier de test compris dès l'écriture, aucun correctif
  nécessaire après coup).
- `lint-imports` : 65→66 fichiers, 164→168 dépendances, contrat
  toujours respecté.
- `mypy --ignore-missing-imports` sur les deux fichiers ajoutés
  (`rule_engine.py`, `test_rule_engine.py`) : la commande remonte 27
  erreurs au total en suivant les imports, mais **0 erreur dans les
  deux fichiers eux-mêmes** (vérifié par `grep -c
  "rule_engine.py:\|test_rule_engine.py:"` sur la sortie → 0) — les 27
  proviennent toutes de modules préexistants déjà comptés dans les 49
  erreurs de la Session 50. Reconfirmé sur l'intégralité de `src/` :
  toujours **49 erreurs sur 9 fichiers**, décompte inchangé.

### Non traité dans cette passe

- Extension du pilote à d'autres règles du catalogue (candidats à
  seuil simple sans `correlation_rule` : `tcp_zero_window`,
  `hop_delta_outliers`, les quatre compteurs DNS bruts...).
- Câblage de `evaluate()`/`available_rule_ids()` à un CLI ou à la GUI
  GTK4 — appelés aujourd'hui uniquement par les tests.
- Bascule effective de `build_findings()` vers ce moteur.
- Section 13.3 de `docs/features-backlog.md` (tableau de découpage des
  sessions) non retouchée cette session — seule la section 4 (dette/
  historique de passes) a été mise à jour, même pratique que les
  sessions précédentes pour ce type d'entrée.
- `README.md` : compteur de tests (« 720 tests », section « Tests »)
  resté stale — déjà en décalage avec le compte réel avant cette
  session (959, maintenant 968), pratique héritée des sessions
  précédentes de ne pas le corriger systématiquement ; hors périmètre
  explicite de cette session (seules les commandes `pip`/`uv` de cette
  section ont été touchées).
