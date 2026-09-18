# Session 60 — trois règles supplémentaires du moteur d'exécution (ttl_variation, pcp_change, icmp_fragmentation_needed)

## Demande initiale

« Continuer les features à faire. Fait évoluer les fichiers de suivi,
de tests et de documentation. Livraison du zip horodaté
`{YYYYMMDD-HHMMSS}` sans passer à la suite. » — consigne récurrente
habituelle, sans demande explicite supplémentaire cette fois
(contrairement aux Sessions 57/58/59 qui portaient chacune une
re-vérification `uv`/`ruff`).

## 1. État de référence (avant tout nouveau code)

```
$ uv run pytest -q
1018 passed in 3.10s
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
127 files already formatted
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Conforme à l'état de fin de Session 59 (`CLAUDE.md`) : 1018/1018,
ruff/lint-imports propres.

## 2. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 59) listait TREIZE candidats « de
forme simple mais NON vérifiés bloc par bloc » pour poursuivre
l'extension de `_EVALUATORS`, le bloc source `-- TCP avance --` étant
désormais entièrement pilotée : `ttl_variation`, `pcp_change`,
`icmp_fragmentation_needed`, `dhcp_issues`, `sip_issues`,
`http_client_error`/`http_server_error`/`http_timeout`/`http_missing`,
`tls_cert_invalid_dates`/`tls_cert_mismatch`/`tls_handshake_no_reply`/
`tls_handshake_incomplete`. Aucun n'avait encore été vérifié bloc par
bloc — fait cette session, pour les treize, avant toute rédaction.

### Vérification bloc par bloc dans `synthesis.py` et `models.py`

```
$ grep -n "ttl_variation\|pcp_change\|icmp_fragmentation_needed\|dhcp_issues\|sip_issues\|http_client_error\|http_server_error\|http_timeout\|http_missing\|tls_cert_invalid_dates\|tls_cert_mismatch\|tls_handshake_no_reply\|tls_handshake_incomplete" src/netcross_report/synthesis.py
```

Chaque bloc source lu individuellement (`synthesis.py::build_findings()`)
et chaque champ `Report` correspondant vérifié dans
`netcross_core/models.py` :

- **`ttl_unstable`** : `dict[str, int]` PAR POINT — bloc source
  identique à `tcp_zero_window` (itération directe, `if n > 0`, aucune
  `evidence`). `expert_rules.py` : `severity="a_surveiller"`,
  `thresholds` absent (dict vide par défaut).
- **`pcp_change`** : `dict[tuple[str, str], int]` PAR PAIRE de points
  adjacents — bloc source identique à `hop_delta_outliers`. Catalogue :
  `severity="a_surveiller"`, `thresholds` vide.
- **`icmp_frag_needed`** (IPv4) et **`icmpv6_too_big`** (IPv6) : tous
  deux `dict[str, int]` PAR POINT — DEUX blocs sources consécutifs
  partageant le même `rule_id="icmp_fragmentation_needed"`, comme
  `tcp_options_stripped` (Session 59), mais par point (pas par paire)
  et sans `evidence`. Catalogue : une seule `Rule`
  (`severity="info"`) couvre les deux compteurs — confirmé, pas de
  seconde entrée.
- **`dhcp_issues`** : fusionne `dhcp_nak_count` (`dict[str, int]` PAR
  POINT, sans `evidence`) et `dhcp_missing` (`dict[tuple[str, str],
  list[str]]` PAR PAIRE, avec `evidence` via `_evidence(seg, missing)`
  à DEUX arguments) — deux compteurs de formes DIFFÉRENTES entre eux,
  contrairement à `icmp_fragmentation_needed` ci-dessus. Écarté de ce
  lot (voir « Non traité »).
- **`sip_issues`** : fusionne `sip_failed_calls` (une simple `list[str]`
  DÉJÀ FORMATÉE, un `Finding` par entrée via une compréhension,
  segment `"global"` fixe — aucun compteur `dict`, forme jamais pilotée
  jusqu'ici) et `sip_missing` (`dict[tuple[str, str], list[str]]` PAR
  PAIRE, avec `evidence` à deux arguments comme `dhcp_missing`) — TROIS
  formes mélangées. Écarté de ce lot.
- **`http_client_error`/`http_server_error`** : PAR POINT, `evidence`
  construite via `_http_error_evidence()` — une DEUXIÈME fonction
  privée de `synthesis.py`, jamais copiée localement dans
  `rule_engine.py` (seule `_evidence()` l'est à ce stade), qui filtre
  `Report.http_error_examples` par classe de statut (4xx/5xx). Écarté
  de ce lot : nécessite une nouvelle brique, pas seulement une
  reproduction directe.
- **`http_timeout`** : `dict[str, list[str]]` PAR POINT, `evidence` à
  TROIS arguments (`_evidence(p, timeouts, r.http_timeout_frames.get(p,
  []))`) — forme IDENTIQUE à `dns_timeout` (Session 57). Confirmé
  directement reproductible, mais laissé pour un prochain lot (voir
  « Non traité » — choix de resserrer ce lot-ci sur les candidats sans
  `evidence`).
- **`http_missing`** : `dict[tuple[str, str], list[str]]` PAR PAIRE,
  `evidence` à DEUX arguments (sans `frames`) — forme IDENTIQUE à
  `dns_missing` (Session 57). Même remarque.
- **`tls_cert_invalid_dates`**, **`tls_handshake_no_reply`**,
  **`tls_handshake_incomplete`** : PAR POINT, compteur `int`, `evidence`
  à TROIS arguments (examples + frames) — forme IDENTIQUE à
  `tcp_mss_clamped` (Session 59) mais par point plutôt que par paire.
  **`tls_cert_mismatch`** : PAR PAIRE, même forme, correspond exactement
  à `tcp_mss_clamped`. Les quatre confirmés directement reproductibles,
  laissés pour un prochain lot (même remarque que HTTP ci-dessus).

**Décision** : lot resserré sur les TROIS candidats sans `evidence` ni
seuil, formes déjà rigoureusement identiques à des règles déjà pilotées
— `ttl_variation`, `pcp_change`, `icmp_fragmentation_needed` — plutôt
que d'ajouter d'un coup les neuf autres candidats déjà confirmés
simples (six à évidence directement reproductible + trois formes plus
éloignées nécessitant une nouvelle brique). Continuité de discipline
avec les Sessions 56/58 (lots de règles homogènes « sans évidence »)
avant de rouvrir, dans une session dédiée, le lot « evidence HTTP/TLS »
dans l'esprit de la Session 57 pour `dns_timeout`/`dns_missing`.

## Implémentation

Trois nouveaux évaluateurs dans `rule_engine.py`, chacun lisant
`rule.severity`/`rule.domain`/`rule.id` depuis le catalogue plutôt que
de recopier les valeurs en dur (même discipline que tous les
évaluateurs précédents) :

```python
def _evaluate_ttl_variation(rule: Rule, report: Report) -> list[Finding]:
    findings: list[Finding] = []
    for p, n in report.ttl_unstable.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    p,
                    f"{n} flux avec TTL variable au meme point (routage asymetrique possible)",
                    rule_id=rule.id,
                )
            )
    return findings
```

`_evaluate_pcp_change` — même forme, clé par paire (`(a, b)`, segment
`f"{a} -> {b}"`), comme `_evaluate_hop_delta_outliers`.

`_evaluate_icmp_fragmentation_needed` — reproduit les DEUX boucles
sources consécutives (`icmp_frag_needed` puis `icmpv6_too_big`), même
ordre, même `rule_id` sur les deux `Finding` — DEUXIÈME évaluateur de
ce pilote (après `_evaluate_tcp_options_stripped`, Session 59) à
fusionner deux compteurs `Report` distincts, mais plus simple : par
point, sans `evidence`.

`_EVALUATORS` passe de quinze à **dix-huit** entrées. Aucun nouvel
import nécessaire (mêmes `Rule`/`Report`/`Finding` déjà utilisés).

## Tests

`tests/test_rule_engine.py` : onze nouveaux tests.

Pour `ttl_variation` et `pcp_change`, structure identique aux lots
« sans évidence » précédents (déclenchement avec sévérité du
catalogue, silence/absence, équivalence avec `build_findings()` filtrée
par `rule_id`) — trois tests chacune.

Pour `icmp_fragmentation_needed`, structure élargie comme
`tcp_options_stripped` (Session 59), adaptée à deux compteurs PAR POINT
au lieu de PAR PAIRE :

```python
def test_icmp_fragmentation_needed_ipv4_seul_declenche(): ...
def test_icmp_fragmentation_needed_ipv6_seul_declenche(): ...
def test_icmp_fragmentation_needed_ipv4_et_ipv6_deux_findings(): ...
def test_icmp_fragmentation_needed_absent_pas_de_finding(): ...
def test_icmp_fragmentation_needed_equivalent_a_build_findings(): ...
```

**Deux tests préexistants mis à jour** :
- `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  ciblait `ttl_variation` — désormais fausse. Remplacée par
  `dhcp_issues` (vérifiée présente dans le catalogue, toujours sans
  évaluateur — voir § 2 ci-dessus).
- `test_available_rule_ids_ne_contient_que_les_regles_pilotees` — liste
  étendue aux dix-huit règles.

```
$ uv run pytest -q
1029 passed in 1.36s
```

1018/1018 → **1029/1029** (+11 net).

## Contrôles qualité

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
127 files already formatted
```

Propre du premier coup, aucun reformatage nécessaire (contrairement aux
Sessions 58/59, qui avaient chacune signalé une ligne vide
surnuméraire).

```
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Inchangé depuis la Session 59 : aucun nouveau module, aucun nouvel
import.

```
$ uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)
$ uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes erreurs préexistantes, mêmes fichiers, qu'aux Sessions 50, 55,
56, 57, 58 et 59. 0 erreur imputable à cette session. Baseline
inchangée (49 erreurs, 9 fichiers).

## Non traité dans cette passe

- **Les DIX autres candidats nommés depuis la Session 59** : désormais
  TOUS audités bloc par bloc (fait cette session, § 2 ci-dessus) —
  SIX confirmés de forme directement reproductible avec les briques
  déjà en place (`tls_cert_invalid_dates`, `tls_cert_mismatch`,
  `tls_handshake_no_reply`, `tls_handshake_incomplete`, `http_timeout`,
  `http_missing`) et QUATRE de forme plus éloignée (`dhcp_issues`/
  `sip_issues` — compteurs hétérogènes fusionnés ; `http_client_error`/
  `http_server_error` — nouvelle fonction privée à copier). Candidats
  naturels pour la session suivante, voir CLAUDE.md « Prochaine
  feature ».
- **Au-delà de ces dix** : ~13 règles jamais auditées (pas d'inventaire
  fait à ce stade).
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait toujours de traiter d'abord les cinq règles à
  `correlation_rule` non `None`.
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-59.
- **Les 49 erreurs `mypy` préexistantes** : nettoyage optionnel jamais
  priorisé, hors périmètre de cette session.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — trois évaluateurs
  (`_evaluate_ttl_variation`, `_evaluate_pcp_change`,
  `_evaluate_icmp_fragmentation_needed`), extension de `_EVALUATORS`,
  docstrings mises à jour.
- `tests/test_rule_engine.py` — onze nouveaux tests, deux tests
  préexistants corrigés, docstring de module mise à jour.
- `CLAUDE.md` — État courant (nouvelle entrée Session 60), Prochaine
  feature, Commandes qualité (compteur pytest, décompte mypy).
- `docs/features-backlog.md` — nouvelle entrée section 4.
- `docs/sessions/session-60.md` — ce fichier.
