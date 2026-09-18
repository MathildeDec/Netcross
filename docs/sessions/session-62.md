# Session 62 — deux dernières règles confirmées du moteur d'exécution (http_client_error, http_server_error)

## Demande initiale

« Continuer les features à faire. Fait évoluer les fichiers de suivi,
de tests et de documentation. Livraison du zip horodaté
`{YYYYMMDD-HHMMSS}` sans passer à la suite. » — consigne récurrente
habituelle, sans demande explicite supplémentaire cette fois (comme
les Sessions 60/61).

## 1. État de référence (avant tout nouveau code)

```
$ uv run pytest -q
1058 passed in 6.93s
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
128 files already formatted
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Conforme à l'état de fin de Session 61 (`CLAUDE.md`) : 1058/1058,
ruff/lint-imports propres.

## 2. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 61) listait quatre candidats
restants depuis la Session 59, déjà tous audités bloc par bloc
Session 60, répartis en deux paires hétérogènes :

- `dhcp_issues`/`sip_issues` — fusionnent chacune deux à trois
  compteurs `Report` de formes DIFFÉRENTES entre eux, `sip_issues`
  ajoutant en plus une troisième forme jamais pilotée jusqu'ici (une
  liste de chaînes déjà formatées construisant directement un
  `Finding` par entrée via une compréhension, `Report.sip_failed_calls`,
  segment `"global"` fixe, pas de compteur `dict` du tout) ;
- `http_client_error`/`http_server_error` — nécessitent de copier
  localement une DEUXIÈME fonction privée de `synthesis.py`
  (`_http_error_evidence()`, filtrage des exemples par classe de
  statut HTTP 4xx/5xx sur le champ brut partagé
  `Report.http_error_examples`), jamais fait jusqu'ici pour ce pilote
  (une seule fonction privée copiée à ce stade, `_evidence()`).

**Décision** : cette session reprend la paire `http_client_error`/
`http_server_error` — une seule brique supplémentaire à écrire
(`_http_error_evidence()`, copie mécanique vérifiée ligne à ligne),
contre un choix de conception à trancher pour `dhcp_issues`/
`sip_issues` (formes hétérogènes entre les compteurs fusionnés, pas
seulement entre les règles). Chaque bloc source re-vérifié malgré tout
dans `synthesis.py` ET `netcross_core/models.py` avant rédaction, pas
seulement supposé reproductible sur la foi de l'audit Session 60 :

```
$ grep -n "http_client_error\|http_server_error\|_http_error_evidence" src/netcross_report/synthesis.py
$ grep -n "http_client_error_count\|http_server_error_count\|http_error_examples\|http_error_frames" src/netcross_core/models.py
$ grep -n "http_client_error\|http_server_error" src/netcross_core/expert_rules.py
```

Confirmations obtenues :

- **`Report.http_client_error_count`**/**`Report.http_server_error_count`**
  (`models.py`) : `dict[str, int]` PAR POINT, commentés `# 4xx`/`# 5xx`
  — compteurs entiers, pas des listes (contrairement à `http_timeout`/
  `http_missing`, Session 61).
- **`Report.http_error_examples`**/**`Report.http_error_frames`**
  (`models.py`) : champ PARTAGÉ entre les deux règles — un seul champ
  qui mélange volontairement 4xx et 5xx à la collecte
  (`analysis.py::_analyse_http`), commentaire explicite dans
  `models.py` : « Filtre 4xx/5xx applique au meme moment que
  `_http_error_evidence` ».
- **`_http_error_evidence()`** (`synthesis.py`, fonction privée) :
  filtre `examples` (et `frames` en parallèle) sur le suffixe
  `"-> NNN"` de chaque exemple, `code // 100 == status_class` — corps
  de dix lignes, aucune logique de détection, uniquement du filtrage
  sur une liste déjà collectée.
- **Bloc source** (`synthesis.py::build_findings()`, `-- HTTP --`) :
  `for p, n in r.http_client_error_count.items(): if n > 0:` — même
  condition que les compteurs entiers déjà pilotés
  (`tcp_zero_window` et consorts, Session 56), mais `evidence` non
  vide ici, construite via `_evidence(p, texts, frames)` où
  `texts, frames = _http_error_evidence(r.http_error_examples.get(p, []), 4, r.http_error_frames.get(p, []))`.
  Même structure pour `http_server_error` avec `status_class=5`.
- **Catalogue** (`expert_rules.py`) : `http_client_error`
  `severity="info"`, `http_server_error` `severity="anomalie"` ;
  aucun seuil dans `rule.thresholds` pour les deux (dict vide, vérifié
  par recherche de `thresholds=` dans chaque bloc `Rule`).

## Implémentation

Une fonction privée copiée localement, puis deux évaluateurs dans
`rule_engine.py` :

```python
def _http_error_evidence(
    examples: list[str], status_class: int, frames: list[int | None] | None = None
) -> tuple[list[str], list[int | None]]:
    texts = []
    filtered_frames = []
    for i, ex in enumerate(examples):
        try:
            code = int(ex.rsplit(" ", 1)[-1])
        except ValueError:
            continue
        if code // 100 == status_class:
            texts.append(ex)
            if frames is not None and i < len(frames):
                filtered_frames.append(frames[i])
    return texts, filtered_frames


def _evaluate_http_client_error(rule: Rule, report: Report) -> list[Finding]:
    findings: list[Finding] = []
    for p, n in report.http_client_error_count.items():
        if n > 0:
            texts, frames = _http_error_evidence(
                report.http_error_examples.get(p, []), 4, report.http_error_frames.get(p, [])
            )
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} reponse(s) HTTP 4xx (erreur cote client -- pas forcement un probleme reseau)",
                    evidence=_evidence(p, texts, frames),
                    rule_id=rule.id,
                )
            )
    return findings
```

`_evaluate_http_server_error` — même forme, `status_class=5`, message
5xx, `rule.severity` lu depuis le catalogue (`"anomalie"`).

`_EVALUATORS` passe de vingt-quatre à **vingt-six** entrées. Aucun
nouvel import nécessaire (mêmes `Rule`/`Report`/`Finding` déjà
utilisés). Docstring de module étendue (paragraphe « Portee de la
Session 62 »), docstring de `evaluate()` corrigée au passage (15
règles restantes sans évaluateur, contre 17 affiché par erreur depuis
plusieurs sessions — jamais mis à jour alors que le compteur avançait
à chaque lot).

## Tests

`tests/test_rule_engine.py` : dix nouveaux tests, cinq par règle —
même structure que le lot « compteur entier + evidence » de la
Session 61 (`tls_cert_invalid_dates` et consorts), plus un test dédié
au filtrage par classe de statut sur le champ partagé :

```python
def test_http_client_error_declenche_severite_du_catalogue(): ...
def test_http_client_error_absent_pas_de_finding(): ...
def test_http_client_error_compteur_nul_pas_de_finding(): ...
def test_http_client_error_evidence_filtre_les_5xx_du_champ_partage(): ...
def test_http_client_error_equivalent_a_build_findings(): ...
```

Même quintette pour `http_server_error` (filtre inverse : vérifie que
les 4xx du champ partagé sont exclus de l'`evidence`).

**Un test préexistant mis à jour** :
- `test_available_rule_ids_ne_contient_que_les_regles_pilotees` —
  liste étendue aux vingt-six règles.

`test_regle_connue_sans_evaluateur_leve_not_implemented_error`
utilisait déjà `dhcp_issues` comme exemple de « règle connue mais non
pilotée » — toujours vrai, `dhcp_issues` n'a pas d'évaluateur dans ce
lot, aucun changement nécessaire.

```
$ uv run pytest -q
1068 passed in 1.12s
```

1058/1058 → **1068/1068** (+10 net).

## Contrôles qualité

```
$ uv run ruff check .
E501 Line too long (127 > 120) -- rule_engine.py:1075
E501 Line too long (127 > 120) -- rule_engine.py:1106
Found 2 errors.
$ uv run ruff format .
1 file reformatted, 128 files left unchanged
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
129 files already formatted
```

Les deux lignes d'appel à `_http_error_evidence()` (un seul appel,
trois arguments) dépassaient 120 caractères — repliées automatiquement
par `ruff format` sur trois lignes. Même type de reformatage
occasionnel que les Sessions 58/59, pas un défaut de conception.
`pytest` rejoué après reformatage : toujours 1068/1068.

```
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Inchangé depuis la Session 61 : aucun nouveau module, aucun nouvel
import.

```
$ uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py
Found 27 errors in 7 files (checked 1 source file)
$ uv run mypy --ignore-missing-imports tests/test_rule_engine.py
Success: no issues found in 1 source file
$ uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes erreurs préexistantes, mêmes fichiers, qu'aux Sessions 50, 55 à
61. 0 erreur imputable à cette session. Baseline inchangée (49
erreurs, 9 fichiers).

## Non traité dans cette passe

- **`dhcp_issues`/`sip_issues`** : toujours sans évaluateur, formes
  hétérogènes déjà auditées Session 60 (compteurs de formes
  DIFFÉRENTES fusionnés sous un même `rule_id` ; `sip_issues` ajoute
  une troisième forme jamais pilotée, une liste de chaînes déjà
  formatées). Seuls candidats restants déjà audités — voir CLAUDE.md
  « Prochaine feature ».
- **Au-delà de ces deux** : ~13 règles jamais auditées (pas
  d'inventaire fait à ce stade).
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait toujours de traiter d'abord les cinq règles à
  `correlation_rule` non `None`.
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-61.
- **Les 49 erreurs `mypy` préexistantes** : nettoyage optionnel jamais
  priorisé, hors périmètre de cette session.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — une fonction privée copiée
  (`_http_error_evidence`), deux évaluateurs
  (`_evaluate_http_client_error`, `_evaluate_http_server_error`),
  extension de `_EVALUATORS`, docstrings mises à jour (module +
  `evaluate()`, correction du décompte de règles restantes).
- `tests/test_rule_engine.py` — dix nouveaux tests, extension de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`.
- `CLAUDE.md` — État courant (nouvelle entrée Session 62), Prochaine
  feature (26/41, deux candidats restants au lieu de quatre), phrase
  de méthode de fin de section « Prochaine feature ».
- `docs/features-backlog.md` — nouvelle entrée section 4.
