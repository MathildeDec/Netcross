# Session 64 — première règle jamais auditée pilotée (vlan_change)

## Demande initiale

« Continuer les features à faire. Fait évoluer les fichiers de suivi,
de tests et de documentation. Livraison du zip horodaté
`{YYYYMMDD-HHMMSS}` sans passer à la suite. » — consigne récurrente
habituelle, sans demande explicite supplémentaire cette fois.

## 1. État de référence (avant tout nouveau code)

```
$ uv run pytest -q
1083 passed in 3.50s
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
131 files already formatted
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Conforme à l'état de fin de Session 63 (`CLAUDE.md`) : 1083/1083,
ruff/lint-imports propres.

## 2. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 63) ne listait plus AUCUN candidat
déjà audité : les treize règles restantes sont toutes **jamais
auditées**, un changement de nature par rapport aux Sessions 60-63 qui
partaient toujours d'un audit déjà fait par une session antérieure.
Deux sous-groupes :

- **cinq règles à `correlation_rule` non `None`** (`qos_dscp_remarking`,
  `fragmentation_new`, `saturation`, `bufferbloat`, `pmtud_blackhole`) —
  fusionnent chacune deux signaux distincts, forme jamais rencontrée
  par ce pilote, les plus éloignées.
- **huit règles sans corrélation** (`rtp_quality_mos`,
  `dns_slow_resolution`, `nat_fw_silent_drop`, `arp_ip_conflict`,
  `stp_instability`, `vlan_change`, `server_processing_dominant`,
  `http_slow_response`) — portant pour la plupart un ou deux seuils
  dans `rule.thresholds`, forme proche de `loss_per_segment`
  (Session 55).

Décision : auditer d'abord les huit règles sans corrélation (coût de
lecture le plus faible, aucune décision architecturale requise), en
commençant par celles dont le catalogue (`expert_rules.py`) ne déclare
aucun seuil — signe possible d'une forme aussi simple que
`hop_delta_outliers`/`pcp_change`, déjà pilotées.

## 3. Audit bloc par bloc

Lecture de l'entrée catalogue `vlan_change` dans `expert_rules.py` :
`domain="VLAN"`, `severity="a_surveiller"`, aucun champ `thresholds`
déclaré (donc dict vide par défaut de la dataclass `Rule`).
`required_metrics=("Report.vlan_change", "Pkt.vlan_id")`.

Recherche du bloc source dans `synthesis.py::build_findings()` :

```python
# -- VLAN --
for (a, b), n in r.vlan_change.items():
    if n > 0:
        findings.append(
            Finding(
                "a_surveiller",
                "VLAN",
                f"{a} -> {b}",
                f"{n} flux changent d'ID VLAN entre ces deux points",
                rule_id="vlan_change",
            )
        )
```

Aucun `evidence`, aucune référence à un seuil. Vérification du type
réel dans `netcross_core/models.py` :

```python
vlan_change: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
```

`dict[tuple[str, str], int]` PAR PAIRE de points adjacents, exactement
la forme déjà pilotée par `_evaluate_hop_delta_outliers` (Session 56)
et `_evaluate_pcp_change` (Session 60) : itération directe sur
`.items()`, condition `n > 0`, segment `f"{a} -> {b}"`, sévérité UNIQUE
lue depuis `rule.severity`, aucune `evidence`. Confirmé reproductible
sans aucune brique nouvelle.

## 4. Évaluateur

```python
def _evaluate_vlan_change(rule: Rule, report: Report) -> list[Finding]:
    findings: list[Finding] = []
    for (a, b), n in report.vlan_change.items():
        if n > 0:
            findings.append(
                Finding(
                    rule.severity,
                    rule.domain,
                    f"{a} -> {b}",
                    f"{n} flux changent d'ID VLAN entre ces deux points",
                    rule_id=rule.id,
                )
            )
    return findings
```

Enregistré dans `_EVALUATORS["vlan_change"]`, portant le pilote à
vingt-neuf entrées sur 41.

## 5. Tests

Trois nouveaux tests, même discipline que
`hop_delta_outliers`/`pcp_change` : déclenchement (`severity`,
`category`, `segment`, `rule_id`, message), absence de `Finding` quand
le compteur est vide, équivalence de contenu avec `build_findings()`
sur un `Report` à trois points (une paire à `n=0` incluse pour vérifier
qu'elle ne déclenche ni côté procédural ni côté moteur).

`test_available_rule_ids_ne_contient_que_les_regles_pilotees` étendu à
`vlan_change`. `test_regle_connue_sans_evaluateur_leve_not_implemented_
error` **non modifié** : il utilise `saturation` depuis la Session 63,
et `vlan_change` n'est pas ce rôle.

```
$ uv run pytest -q
1086 passed in 1.34s   # 1083 -> 1086, +3 net
```

## 6. Outillage qualité

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
131 files already formatted
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

`lint-imports` inchangé en dépendances (169) est attendu : cet
évaluateur ne consomme que `Report.vlan_change`, déjà exposé, aucun
nouvel import.

`mypy` sur les deux fichiers modifiés :

```
$ uv run mypy --ignore-missing-imports src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)   # 0 imputable
$ PYTHONPATH=src uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)  # baseline Session 50 reconfirmee
```

Même précision méthodologique que la Session 63 : la commande sans
`PYTHONPATH=src` est celle qui reproduit le chiffre de 27 erreurs/7
fichiers.

## Non traité dans cette passe

- **Les douze autres règles jamais auditées** : `arp_ip_conflict` et
  `stp_instability` ont été survolées en même temps que `vlan_change`
  (même section `synthesis.py`) mais pas auditées aussi complètement :
  `arp_ip_conflict` porte une `evidence` et un seuil
  (`min_distinct_macs`) dans son entrée catalogue ; `stp_instability`
  fusionne DEUX compteurs `Report` (`stp_topology_change` sans
  `evidence`, `stp_root_change` avec `evidence`) — plus proches
  respectivement de `tls_cert_invalid_dates`/`loss_per_segment` et de
  `dhcp_issues` que de `vlan_change`, donc pas retenues pour ce lot
  volontairement minimal. `rtp_quality_mos`, `dns_slow_resolution`,
  `nat_fw_silent_drop`, `server_processing_dominant`,
  `http_slow_response` : non ouvertes du tout cette session.
- **Les cinq règles à `correlation_rule` non `None`** : toujours hors
  de portée sans décision architecturale.
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  inchangé, hors périmètre.
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-63.
- **Les 49 erreurs `mypy` préexistantes** : nettoyage optionnel jamais
  priorisé, hors périmètre.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — un évaluateur
  (`_evaluate_vlan_change`), extension de `_EVALUATORS` (28 → 29),
  docstrings mises à jour (module : « Portee de la Session 64 » ;
  `evaluate()` : décompte des règles restantes, 13 → 12).
- `tests/test_rule_engine.py` — trois nouveaux tests, mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`.
- `CLAUDE.md` — État courant (nouvelle entrée Session 64), Prochaine
  feature (29/41, douze candidats restants dont sept sans corrélation
  après retrait de `vlan_change`).
- `docs/features-backlog.md` — nouvelle entrée section 4.
