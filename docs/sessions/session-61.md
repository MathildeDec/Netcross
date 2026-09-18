# Session 61 — six règles supplémentaires du moteur d'exécution (TLS x4, http_timeout, http_missing)

## Demande initiale

« Continuer les features à faire. Fait évoluer les fichiers de suivi,
de tests et de documentation. Livraison du zip horodaté
`{YYYYMMDD-HHMMSS}` sans passer à la suite. » — consigne récurrente
habituelle, sans demande explicite supplémentaire cette fois
(comme la Session 60).

## 1. État de référence (avant tout nouveau code)

```
$ uv run pytest -q
1029 passed in 3.32s
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
128 files already formatted
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Conforme à l'état de fin de Session 60 (`CLAUDE.md`) : 1029/1029,
ruff/lint-imports propres.

## 2. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 60) listait dix candidats restants
depuis la Session 59, déjà TOUS audités bloc par bloc cette
session-là, répartis en deux groupes : SIX confirmés de forme
directement reproductible avec les briques déjà en place
(`tls_cert_invalid_dates`, `tls_cert_mismatch`, `tls_handshake_no_reply`,
`tls_handshake_incomplete`, `http_timeout`, `http_missing`) et QUATRE
de forme plus éloignée nécessitant une brique supplémentaire
(`dhcp_issues`, `sip_issues`, `http_client_error`, `http_server_error`).

Cette session reprend le lot des SIX déjà confirmés — aucune nouvelle
brique à écrire, mais chaque bloc source re-vérifié malgré tout dans
`synthesis.py` ET `netcross_core/models.py` avant rédaction, pas
seulement supposé reproductible sur la foi de l'audit Session 60 :

```
$ grep -n "tls_cert_invalid_dates\|tls_cert_mismatch\|tls_handshake_no_reply\|tls_handshake_incomplete\|http_timeout\|http_missing" src/netcross_report/synthesis.py
$ grep -n "tls_cert_invalid_dates\|tls_cert_mismatch\|tls_handshake_no_reply\|tls_handshake_incomplete\|http_timeout\|http_missing" src/netcross_core/models.py
```

Confirmations obtenues :

- **`tls_cert_invalid_dates`** : `dict[str, int]` PAR POINT (bloc
  `-- certificat TLS (Session 26) --`, premier des deux). `evidence`
  via `_evidence()` à TROIS arguments (`tls_cert_invalid_dates_examples`/
  `_frames`). Catalogue : `severity="anomalie"`, `thresholds` absent
  (dict vide).
- **`tls_cert_mismatch`** : `dict[tuple[str, str], int]` PAR PAIRE de
  points adjacents (second bloc de la même section), segment
  `f"{a} -> {b}"`, `evidence` à trois arguments
  (`tls_cert_mismatch_examples`/`_frames`). Catalogue :
  `severity="anomalie"`, `thresholds` vide.
- **`tls_handshake_no_reply`** et **`tls_handshake_incomplete`** :
  bloc `-- negociations TLS incompletes (Session 54) --`, deux boucles
  consécutives PAR POINT, `dict[str, int]`, `evidence` à trois
  arguments chacune. Catalogue : `severity="anomalie"` pour les deux,
  `thresholds` vide.
- **`http_timeout`** : `dict[str, list[str]]` PAR POINT — un compteur
  en LISTE de textes déjà formatés, pas un entier (condition
  `if timeouts:`, message via `len(timeouts)`), forme IDENTIQUE à
  `dns_timeout` (Session 57). `evidence` à trois arguments
  (`timeouts` directement comme `texts`, `http_timeout_frames`).
  Catalogue : `severity="anomalie"`, `thresholds` vide.
- **`http_missing`** : `dict[tuple[str, str], list[str]]` PAR PAIRE,
  condition `if missing:`, message via `len(missing)`, forme IDENTIQUE
  à `dns_missing` (Session 57) — y compris l'absence de troisième
  argument `frames` : `Report` n'expose aucun `http_missing_frames`
  (confirmé, absent de `models.py`), `evidence(seg, missing)` à DEUX
  arguments seulement. Catalogue : `severity="a_surveiller"` — seule
  des six règles de ce lot à ne pas être `anomalie`, `thresholds` vide.

Aucun seuil numérique trouvé dans `rule.thresholds` pour les six
règles (vérifié par recherche de `thresholds=` dans le bloc de chaque
`Rule` du catalogue — absent des six, présent seulement pour d'autres
règles du fichier).

**Décision** : les SIX règles confirmées sont implémentées dans cette
session, en un seul lot (contrairement au resserrement volontaire de
la Session 60) : aucune ne nécessite de nouvelle brique, toutes
partagent une forme déjà pilotée par un évaluateur existant
(`tcp_mss_clamped`, `dns_timeout` ou `dns_missing`).

## Implémentation

Six nouveaux évaluateurs dans `rule_engine.py`, chacun lisant
`rule.severity`/`rule.domain`/`rule.id` depuis le catalogue plutôt que
de recopier les valeurs en dur (même discipline que tous les
évaluateurs précédents) :

```python
def _evaluate_tls_cert_invalid_dates(rule: Rule, report: Report) -> list[Finding]:
    findings: list[Finding] = []
    for p, n in report.tls_cert_invalid_dates.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} certificat(s) presente(s) hors de leur fenetre de validite sur ce point "
                    f"(deja expire, ou pas encore valide)",
                    evidence=_evidence(
                        p,
                        report.tls_cert_invalid_dates_examples.get(p, []),
                        report.tls_cert_invalid_dates_frames.get(p, []),
                    ),
                    rule_id=rule.id,
                )
            )
    return findings
```

`_evaluate_tls_handshake_no_reply` et `_evaluate_tls_handshake_incomplete`
— même forme, PAR POINT.

`_evaluate_tls_cert_mismatch` — même forme, clé PAR PAIRE (`(a, b)`,
segment `f"{a} -> {b}"`), comme `_evaluate_tcp_mss_clamped`.

`_evaluate_http_timeout` — compteur en LISTE (`if timeouts:`, message
via `len(timeouts)`), reproduit `dns_timeout` (Session 57).

`_evaluate_http_missing` — compteur en LISTE PAR PAIRE (`if missing:`),
`evidence(seg, missing)` à deux arguments seulement (pas de `frames`),
reproduit `dns_missing` (Session 57).

`_EVALUATORS` passe de dix-huit à **vingt-quatre** entrées. Aucun
nouvel import nécessaire (mêmes `Rule`/`Report`/`Finding` déjà
utilisés). Docstring de module étendue (paragraphe « Portee de la
Session 61 »), docstring de `evaluate()` mise à jour (dix-sept règles
restantes sans évaluateur, contre vingt-trois avant).

## Tests

`tests/test_rule_engine.py` : vingt-neuf nouveaux tests.

Pour les cinq règles à compteur (`tls_cert_invalid_dates`,
`tls_cert_mismatch`, `tls_handshake_no_reply`, `tls_handshake_incomplete`,
`http_timeout`), structure identique au lot « evidence » de la Session
57/59 — déclenchement avec sévérité du catalogue, absence, compteur
nul ou liste vide selon le type, `evidence` (textes + frames), et
équivalence avec `build_findings()` filtrée par `rule_id` — cinq tests
chacune :

```python
def test_tls_cert_invalid_dates_declenche_severite_du_catalogue(): ...
def test_tls_cert_invalid_dates_absent_pas_de_finding(): ...
def test_tls_cert_invalid_dates_nul_pas_de_finding(): ...
def test_tls_cert_invalid_dates_evidence_reprend_les_textes_et_les_frames(): ...
def test_tls_cert_invalid_dates_equivalent_a_build_findings(): ...
```

Pour `http_missing`, structure identique à `test_dns_missing_*`
(Session 57) — quatre tests, sans notion de compteur « nul » pour une
liste, et vérification explicite que l'`evidence` ne porte pas de
`packet` :

```python
def test_http_missing_declenche_severite_du_catalogue(): ...
def test_http_missing_absent_pas_de_finding(): ...
def test_http_missing_evidence_reprend_les_textes_sans_packet(): ...
def test_http_missing_equivalent_a_build_findings(): ...
```

**Un test préexistant mis à jour** :
- `test_available_rule_ids_ne_contient_que_les_regles_pilotees` —
  liste étendue aux vingt-quatre règles.

`test_regle_connue_sans_evaluateur_leve_not_implemented_error`
utilisait déjà `dhcp_issues` comme exemple de « règle connue mais non
pilotée » (remplacement fait Session 60) — toujours vrai, `dhcp_issues`
n'a pas d'évaluateur dans ce lot, aucun changement nécessaire.

```
$ uv run pytest -q
1058 passed in 3.32s
```

1029/1029 → **1058/1058** (+29 net).

## Contrôles qualité

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
128 files already formatted
```

Propre du premier coup, aucun reformatage nécessaire.

```
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Inchangé depuis la Session 60 : aucun nouveau module, aucun nouvel
import.

```
$ uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)
$ uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes erreurs préexistantes, mêmes fichiers, qu'aux Sessions 50, 55 à
60. 0 erreur imputable à cette session. Baseline inchangée (49
erreurs, 9 fichiers).

## Non traité dans cette passe

- **Les QUATRE derniers candidats nommés depuis la Session 59** :
  toujours sans évaluateur, forme plus éloignée déjà auditée Session
  60 — `dhcp_issues`/`sip_issues` (compteurs de formes hétérogènes
  fusionnés sous un même `rule_id`, `sip_issues` ajoutant une
  troisième forme jamais pilotée) et `http_client_error`/
  `http_server_error` (nécessitent de copier une deuxième fonction
  privée de `synthesis.py`, `_http_error_evidence()`). Candidats
  naturels pour la session suivante, voir CLAUDE.md « Prochaine
  feature ».
- **Au-delà de ces quatre** : ~13 règles jamais auditées (pas
  d'inventaire fait à ce stade).
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait toujours de traiter d'abord les cinq règles à
  `correlation_rule` non `None`.
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-60.
- **Les 49 erreurs `mypy` préexistantes** : nettoyage optionnel jamais
  priorisé, hors périmètre de cette session.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — six évaluateurs
  (`_evaluate_tls_cert_invalid_dates`, `_evaluate_tls_cert_mismatch`,
  `_evaluate_tls_handshake_no_reply`,
  `_evaluate_tls_handshake_incomplete`, `_evaluate_http_timeout`,
  `_evaluate_http_missing`), extension de `_EVALUATORS`, docstrings
  mises à jour.
- `tests/test_rule_engine.py` — vingt-neuf nouveaux tests, un test
  préexistant corrigé, docstring de module mise à jour.
- `CLAUDE.md` — État courant (nouvelle entrée Session 61), Prochaine
  feature, Commandes qualité (compteur pytest, décompte mypy), phrase
  de méthode de fin de section « Prochaine feature ».
- `docs/features-backlog.md` — nouvelle entrée section 4.
- `docs/sessions/session-61.md` — ce fichier.
