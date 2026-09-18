# Session 66 — troisième règle jamais auditée pilotée (stp_instability)

## Demande initiale

« Continuer les features à faire. Fait évoluer les fichiers de suivi,
de tests et de documentation. Livraison du zip horodaté
`{YYYYMMDD-HHMMSS}` sans passer à la suite. » — consigne récurrente
habituelle, sans demande explicite supplémentaire cette fois.

## 1. État de référence (avant tout nouveau code)

```
$ PYTHONPATH=src python3 -m pytest -q
1091 passed in 2.84s
$ python3 -m ruff check .
All checks passed!
$ python3 -m ruff format --check .
133 files already formatted
$ PYTHONPATH=src lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

Conforme à l'état de fin de Session 65 (`CLAUDE.md`) : 1091/1091,
ruff/lint-imports propres. Environnement livré sans `.git` (zip) ni
`.venv` : dépendances (`pytest`, `ruff`, `import-linter`, `mypy`, et
les dépendances d'exécution `cryptography`/`reportlab`/`matplotlib`/
`networkx`) réinstallées via `pip install --break-system-packages`,
`uv` non disponible dans ce conteneur — mêmes commandes que `uv run
<...>` mais invoquées directement, sans changement de comportement
attendu.

## 2. Choix de la feature suivante

`CLAUDE.md` (état de fin de Session 65) liste onze candidats jamais
audités : les cinq règles à `correlation_rule` non `None`
(`qos_dscp_remarking`, `fragmentation_new`, `saturation`,
`bufferbloat`, `pmtud_blackhole`) et six règles sans corrélation
(`rtp_quality_mos`, `dns_slow_resolution`, `nat_fw_silent_drop`,
`stp_instability`, `server_processing_dominant`, `http_slow_response`).

`stp_instability` est nommée explicitement par CLAUDE.md comme le
candidat le mieux connu de ce groupe : survolée (pas auditée
complètement) aux Sessions 64-65 en même temps que
`vlan_change`/`arp_ip_conflict`, son entrée catalogue
(`required_metrics`) nomme déjà DEUX champs `Report` distincts
(`Report.stp_topology_change`, `Report.stp_root_change`) — signe
repéré d'une fusion à deux compteurs, comme `dhcp_issues` (Session 63)
et `icmp_fragmentation_needed` (Session 60), plutôt qu'un ajout
mécanique simple.

Décision : auditer `stp_instability` en priorité plutôt que les cinq
autres règles sans corrélation (jamais survolées, coût de lecture
inconnu) ou les cinq règles à corrélation (toujours hors de portée
sans décision architecturale sur l'ORDONNANCEMENT et la fusion de deux
signaux distincts, voir CLAUDE.md).

## 3. Audit bloc par bloc

Lecture de l'entrée catalogue `stp_instability` dans
`expert_rules.py` : `domain="STP"`, `severity="anomalie"`,
`confidence=0.8`, `required_metrics=("Report.stp_topology_change",
"Report.stp_root_change", "Pkt.stp_bpdu_type", "Pkt.stp_flags_tc",
"Pkt.stp_root_id")`, **aucun `thresholds`** (dict vide — confirmé,
contrairement à `arp_ip_conflict`). `required_context` précise une
détection PAR POINT uniquement (STP, comme ARP, n'est jamais relayé
par un routeur) et que « les deux compteurs sont deux signatures
indépendantes du même phénomène, comptées séparément mais avec la
même sévérité ».

Recherche du bloc source dans `synthesis.py::build_findings()` :

```python
# -- instabilite STP (Session 25) --
# Par point, voir Report.stp_topology_change/stp_root_change.
for p, n in r.stp_topology_change.items():
    if n <= 0:
        continue
    findings.append(
        Finding(
            "anomalie",
            "STP",
            p,
            f"{n} evenement(s) de changement de topologie STP observe(s) sur ce point "
            f"(BPDU TCN ou bit TC actif) -> reseau instable possible (boucle de commutation, "
            f"lien ou port qui flappe)",
            rule_id="stp_instability",
        )
    )
for p, n in r.stp_root_change.items():
    if n <= 0:
        continue
    findings.append(
        Finding(
            "anomalie",
            "STP",
            p,
            f"{n} reelection(s) du pont racine STP observee(s) sur ce point -> reseau instable "
            f"possible (boucle de commutation, lien ou port qui flappe)",
            evidence=_evidence(p, r.stp_root_change_examples.get(p, []), r.stp_root_change_frames.get(p, [])),
            rule_id="stp_instability",
        )
    )
```

DEUX boucles consécutives partageant le MÊME `rule_id`
(`"stp_instability"`), même sévérité/domaine codés en dur (`"anomalie"`,
`"STP"`) que `rule.severity`/`rule.domain` du catalogue.

Vérification des types réels dans `netcross_core/models.py` :

```python
stp_topology_change: dict[str, int] = field(default_factory=lambda: defaultdict(int))
stp_root_change: dict[str, int] = field(default_factory=lambda: defaultdict(int))
stp_root_change_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
stp_root_change_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
```

**Résultat de l'audit, différent de l'attente initiale fondée sur la
ressemblance avec `dhcp_issues`** : `dhcp_issues` fusionnait deux
compteurs de GRANULARITÉS différentes (`dhcp_nak_count` par point sans
`evidence`, `dhcp_missing` par paire avec `evidence`). Ici, les DEUX
compteurs STP sont `dict[str, int]` PAR POINT — **même granularité**
— et partagent la MÊME condition de garde (`n <= 0: continue`, comme
`arp_ip_conflict`). La seule différence entre les deux boucles est la
présence d'`evidence` (absente pour `stp_topology_change`, présente à
trois arguments pour `stp_root_change`). Chacune des deux formes est
donc déjà individuellement pilotée ailleurs dans ce pilote
(`icmp_fragmentation_needed` pour la première, `arp_ip_conflict` pour
la seconde) : aucune brique technique nouvelle à écrire, seule la
question de conception « un évaluateur ou deux ? » reste — tranchée
comme `tcp_options_stripped`/`icmp_fragmentation_needed`/`dhcp_issues`
en faveur d'UN seul évaluateur (le catalogue ne porte qu'UNE `Rule`
`stp_instability`, vérifié, et `_EVALUATORS` est clé par `Rule.id`).

Absence de seuil confirmée : `rule.thresholds` vide dans le catalogue,
aucune lecture de seuil à reproduire (contrairement à
`arp_ip_conflict`, dont le seuil `min_distinct_macs` documentait une
comparaison faite en amont dans `analysis.py`).

## 4. Évaluateur

```python
def _evaluate_stp_instability(rule: Rule, report: Report) -> list[Finding]:
    findings: list[Finding] = []
    for p, n in report.stp_topology_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                p,
                f"{n} evenement(s) de changement de topologie STP observe(s) sur ce point "
                f"(BPDU TCN ou bit TC actif) -> reseau instable possible (boucle de commutation, "
                f"lien ou port qui flappe)",
                rule_id=rule.id,
            )
        )
    for p, n in report.stp_root_change.items():
        if n <= 0:
            continue
        findings.append(
            Finding(
                rule.severity,
                rule.domain,
                p,
                f"{n} reelection(s) du pont racine STP observee(s) sur ce point -> reseau instable "
                f"possible (boucle de commutation, lien ou port qui flappe)",
                evidence=_evidence(
                    p,
                    report.stp_root_change_examples.get(p, []),
                    report.stp_root_change_frames.get(p, []),
                ),
                rule_id=rule.id,
            )
        )
    return findings
```

Enregistré dans `_EVALUATORS["stp_instability"]`, portant le pilote à
trente et une entrées sur 41.

## 5. Tests

Sept nouveaux tests, même discipline que `dhcp_issues` (tests dédiés à
chaque compteur source séparément, en plus des tests habituels) :

- déclenchement de `stp_topology_change` seul (`severity`, `category`,
  `segment`, `rule_id`, message, `evidence == []`) ;
- déclenchement de `stp_root_change` seul (mêmes champs, message
  distinct) ;
- les deux compteurs déclenchés ensemble → deux `Finding`, dans l'ordre
  des deux boucles du bloc source (topologie puis réélection) ;
- absence de `Finding` quand aucune clé n'est présente ;
- absence de `Finding` quand les deux compteurs sont présents mais
  explicitement nuls (`n = 0`) — ici les deux compteurs partagent la
  MÊME garde, contrairement à `dhcp_issues` où les deux gardes
  différaient (entier vs liste non vide) ;
- `evidence` reprend bien les textes ET les numéros de trame
  (`EvidenceLink.packet`) pour `stp_root_change` ;
- équivalence de contenu avec `build_findings()` sur un `Report` à deux
  points (un point à `n=0` inclus pour vérifier qu'il ne déclenche ni
  côté procédural ni côté moteur) — comparaison positionnelle valable
  ici par coïncidence (même remarque que `dhcp_issues`) : les deux
  segments produits sont identiques (`"A"` puis `"A"`), le tri final
  stable de `build_findings()` préserve donc l'ordre de construction.

`test_available_rule_ids_ne_contient_que_les_regles_pilotees` étendu à
`stp_instability`. `test_regle_connue_sans_evaluateur_leve_
not_implemented_error` **non modifié** : il utilise `saturation`
depuis la Session 63, et `stp_instability` n'est pas ce rôle.

```
$ PYTHONPATH=src python3 -m pytest -q
1098 passed in 1.49s   # 1091 -> 1098, +7 net
```

## 6. Outillage qualité

```
$ python3 -m ruff check .
All checks passed!
$ python3 -m ruff format --check .
133 files already formatted
$ PYTHONPATH=src lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

`lint-imports` inchangé en dépendances (169) est attendu : cet
évaluateur ne consomme que `Report.stp_topology_change`/
`stp_root_change` (et les deux listes d'accompagnement de ce dernier),
déjà exposées, aucun nouvel import.

`mypy` sur les deux fichiers modifiés :

```
$ python3 -m mypy --ignore-missing-imports src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)   # 0 imputable
$ PYTHONPATH=src python3 -m mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)  # baseline Session 50 reconfirmee
```

Même précision méthodologique que les Sessions 63-65 : la commande
sans `PYTHONPATH=src` est celle qui reproduit le chiffre de 27
erreurs/7 fichiers.

## Non traité dans cette passe

- **Les cinq autres règles sans corrélation jamais auditées** :
  `rtp_quality_mos`, `dns_slow_resolution`, `nat_fw_silent_drop`,
  `server_processing_dominant`, `http_slow_response` — toujours non
  ouvertes du tout, aucune n'étant a priori mieux connue qu'une autre à
  ce stade (contrairement à `stp_instability` qui bénéficiait d'une
  survol préalable).
- **Les cinq règles à `correlation_rule` non `None`** : toujours hors
  de portée sans décision architecturale.
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  inchangé, hors périmètre.
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-65.
- **Les 49 erreurs `mypy` préexistantes** : nettoyage optionnel jamais
  priorisé, hors périmètre.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — un évaluateur
  (`_evaluate_stp_instability`), extension de `_EVALUATORS` (30 → 31),
  docstrings mises à jour (module : « Portee de la Session 66 » ;
  `evaluate()` : décompte des règles restantes, 11 → 10).
- `tests/test_rule_engine.py` — sept nouveaux tests, mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`.
- `CLAUDE.md` — État courant (nouvelle entrée Session 66), Prochaine
  feature (31/41, dix candidats restants dont cinq sans corrélation
  après retrait de `stp_instability`).
- `docs/features-backlog.md` — nouvelle entrée section 4.
