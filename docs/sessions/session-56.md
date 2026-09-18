# Session 56 — Extension du moteur d'exécution à quatre règles supplémentaires

## Contexte et choix de périmètre

CLAUDE.md « Prochaine feature », à l'issue de la Session 55, laissait
un chantier explicitement ouvert et non refermé : le premier pilote du
moteur d'**exécution** (`netcross_report/rule_engine.py::evaluate()`)
ne couvrait qu'une seule règle du catalogue (`loss_per_segment`), sur
41. Trois extensions étaient nommées, par ordre de coût croissant :

- (a) étendre `_EVALUATORS` à d'autres règles « à seuil unique simple,
  sans corrélation entre deux signaux » — candidats cités : `tcp_zero_window`,
  `hop_delta_outliers`, « les compteurs DNS bruts » ;
- (b) câbler `evaluate()`/`available_rule_ids()` à un CLI ou au GTK4 ;
- (c) faire basculer `build_findings()` lui-même vers ce moteur.

Une bascule vers la **Session 3** (corrélation et causalité, difficulté
5/5) restait l'alternative de fond, mais sans brique préalable et avec
un périmètre bien plus large — le même arbitrage qu'en Session 55, pour
les mêmes raisons.

**Choix retenu pour cette session : (a).** Justification : c'est la
suite directe et bornée du travail de la Session 55 (même module, même
discipline de reproduction exacte du code procédural), vérifiable de
bout en bout dans une seule session, et (b)/(c) n'ont de sens qu'une
fois (a) suffisamment avancé (câbler un CLI sur un moteur qui ne couvre
qu'une seule règle sur 41 apporterait peu ; basculer `build_findings()`
nécessite d'abord d'avoir traité la quasi-totalité des règles simples).

## Vérification préalable des candidats (a)

Avant d'écrire le moindre évaluateur, chaque candidat nommé par
CLAUDE.md a été vérifié dans le code — pas supposé sur la seule foi de
la note de la Session 55.

**Recherche des règles à `correlation_rule` non `None`** (celles à
exclure d'office de ce lot) :

```
$ grep -n "correlation_rule=(" src/netcross_core/expert_rules.py
```

→ cinq occurrences, correspondant à `qos_dscp_remarking`,
`fragmentation_new`, `saturation`, `bufferbloat`, `pmtud_blackhole` —
confirmation qu'aucune des quatre règles retenues ci-dessous n'en fait
partie.

**Types exacts des compteurs `Report`** (`netcross_core/models.py`) :

```
loss_count: dict[str, int]
zero_window: dict[str, int]
dns_nxdomain_count: dict[str, int]
dns_servfail_count: dict[str, int]
hop_delta_outliers: dict[tuple[str, str], int]
dns_missing: dict[tuple[str, str], list[str]]
dns_timeout: dict[str, list[str]]
```

Cette vérification a immédiatement révélé que « les compteurs DNS
bruts », tels que nommés par la note de la Session 55, ne forment PAS
un groupe homogène : `dns_nxdomain_count`/`dns_servfail_count` sont de
simples entiers par point, mais `dns_timeout`/`dns_missing` portent des
LISTES (de transaction IDs, vraisemblablement), et leur bloc procédural
dans `synthesis.py` passe par un helper `_evidence()` pour construire
le champ `evidence` du `Finding` — absent des trois autres. **Correction
apportée cette session** : seuls `dns_nxdomain`/`dns_servfail` sont
retenus dans ce lot ; `dns_timeout`/`dns_missing` sont explicitement
laissés de côté (voir « Non traité » plus bas), une distinction que la
note de la Session 55 ne faisait pas.

**Blocs procéduraux sources** (`netcross_report/synthesis.py`), lus
intégralement avant rédaction :

- `zero_window` (TCP) : `for p, n in r.zero_window.items(): if n > 0:
  ...` — sévérité fixe `"a_surveiller"`, pas de seuil, pas de
  `sample_size`, pas d'`evidence`.
- `dns_nxdomain_count` (DNS) : même forme, sévérité fixe `"info"`.
- `dns_servfail_count` (DNS) : même forme, sévérité fixe `"anomalie"`.
- `hop_delta_outliers` (Routage) : `for (a, b), n in
  r.hop_delta_outliers.items(): if n > 0: ...`, segment `f"{a} -> {b}"`
  — seule des quatre clée par une PAIRE de points adjacents plutôt
  qu'un point seul, mais la même forme sinon (sévérité fixe
  `"a_surveiller"`, aucune agrégation supplémentaire à faire côté
  évaluateur : le mode statistique nommé par `Rule.preconditions` de
  cette règle est déjà précalculé en amont, dans `netcross_core.analysis`,
  directement au moment où `Report.hop_delta_outliers` est peuplé).

Point commun important, différent de `loss_per_segment` : ces quatre
blocs itèrent **directement le dict du compteur** (`r.<compteur>.items()`),
pas `r.points` — à la différence du bloc « pertes » qui itère
explicitement `r.points`. Reproduire l'un ou l'autre schéma d'itération
à l'identique de son propre bloc source, plutôt qu'appliquer un patron
unique aux quatre, était nécessaire pour préserver l'équivalence
comportementale exacte.

Autre différence assumée avec `loss_per_segment` : aucune des quatre
règles ne porte de seuil dans `rule.thresholds` du catalogue (dict
vide, vérifié dans `expert_rules.py` avant rédaction) — la sévérité est
UNIQUE par règle, jamais calculée. Plutôt que de la recopier en dur une
seconde fois (une fois dans `expert_rules.py`, une fois dans
l'évaluateur), chaque évaluateur lit `rule.severity` directement : la
pièce PILOTÉE par le catalogue pour ce lot, au même titre que
`rule.thresholds["anomalie_rate_pct"]` pour `loss_per_segment`. Cette
égalité (`rule.severity` == constante procédurale hardcodée) n'est pas
seulement supposée : elle est vérifiée pour chaque règle par son propre
test d'équivalence avec `build_findings()`, qui aurait échoué si le
catalogue et le code procédural divergeaient.

## Implémentation

Quatre nouvelles fonctions ajoutées à `netcross_report/rule_engine.py`,
chacune avec sa propre docstring documentant précisément quel bloc
source elle reproduit et en quoi elle diffère de `_evaluate_loss_per_segment` :

- `_evaluate_tcp_zero_window`
- `_evaluate_dns_nxdomain`
- `_evaluate_dns_servfail`
- `_evaluate_hop_delta_outliers`

`_EVALUATORS` passe de une à cinq entrées (`loss_per_segment` +
les quatre ci-dessus). `evaluate()`/`available_rule_ids()` inchangées
dans leur logique — seul le dict qu'elles consultent s'est enrichi ;
leurs docstrings sont mises à jour pour refléter le nouveau compte
(36 des 41 règles encore sans évaluateur, contre 40 avant cette
session).

Le docstring de module de `rule_engine.py` reçoit un nouveau
paragraphe « Portée de la Session 56 », à la suite (et non en
remplacement) de celui de la Session 55 — même convention que
`expert_rules.py`, qui accumule un paragraphe daté par session l'ayant
étendu plutôt que de réécrire la narration précédente.

## Tests

`tests/test_rule_engine.py` reçoit douze nouveaux tests, trois par
règle, même granularité pour les quatre (aucune n'a de branchement de
sévérité à tester séparément, contrairement à `loss_per_segment`
anomalie/à_surveiller) :

1. déclenchement avec sévérité/catégorie/segment/`rule_id`/message
   corrects sur un point (ou une paire) en positif ;
2. silence quand le compteur est absent ou présent mais nul ;
3. équivalence stricte avec `build_findings()` sur un `Report` à
   plusieurs points (ou paires), l'un déclenchant, l'autre non.

Différence méthodologique notable avec le test d'équivalence de
`loss_per_segment` : celui-ci filtrait `build_findings()` par
`category == "Pertes"`, ce qui fonctionne uniquement parce que
« Pertes » ne contient qu'une seule règle dans tout le catalogue. Pour
TCP/DNS/Routage, plusieurs `rule_id` distincts partagent la même
catégorie (TCP porte aussi `tcp_rst_localized`/les trois sous-types de
retransmission ; DNS porte aussi `dns_timeout`/`dns_missing`/
`dns_slow_resolution`) — filtrer par seule catégorie aurait mélangé des
`Finding` d'autres règles et faussé la comparaison longueur-à-longueur
attendue par `zip(..., strict=True)`. Les quatre nouveaux tests
d'équivalence filtrent donc par `rule_id`, pas par `category`.

`test_available_rule_ids_ne_contient_que_les_regles_pilotees` mis à
jour pour attendre les cinq identifiants dans l'ordre d'insertion du
dict. `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
inchangé : `tcp_rst_localized` n'a toujours pas d'évaluateur à l'issue
de cette session, l'assertion reste vraie.

Résultat : `pytest` 968/968 → **980/980** (+12 net, exactement 3×4).

## Vérifications qualité

```
$ uv run pytest -q
980 passed

$ uv run ruff check .
All checks passed!

$ uv run ruff format --check .
123 files already formatted

$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 168 dependencies.
Contracts: 1 kept, 0 broken.
```

`lint-imports` inchangé par rapport à la Session 55 (66 fichiers, 168
dépendances) : aucun nouveau module créé, seules deux fonctions
existantes ont été étendues.

`mypy` sur les deux fichiers modifiés :

```
$ PYTHONPATH=src uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py tests/test_rule_engine.py
Success: no issues found in 2 source files
```

Puis reconfirmation sur l'intégralité de `src/` (méthode de référence
établie Session 50, plus rigoureuse que le seul scope des fichiers
modifiés) :

```
$ PYTHONPATH=src uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes 49 erreurs, mêmes 9 fichiers (`analysis.py`, `tls_diagnostics.py`,
`triage.py`, `quic_diagnostics.py`, `packet.py`, `history.py`,
`netcross_report/__init__.py`, `ek_source.py`, `parsing.py`) qu'aux
Sessions 50 et 55 — `rule_engine.py` n'en fait pas partie. Baseline
confirmée inchangée par les deux méthodes.

## Non traité dans cette passe

- **`dns_timeout`/`dns_missing`** : forme différente des deux compteurs
  DNS retraités (listes plutôt qu'entiers, passage par `_evidence()`
  côté procédural) — premiers candidats naturels si ce chantier
  continue, mais nécessitent de reproduire `_evidence()` dans
  l'évaluateur, jamais fait jusqu'ici.
- **Les ~31 autres règles sans évaluateur** : non auditées
  individuellement pour leur simplicité. Ne pas supposer qu'elles sont
  toutes aussi directes que les cinq déjà pilotées — chacune doit être
  vérifiée bloc par bloc dans `synthesis.py` avant d'y ajouter un
  évaluateur, comme fait ici et en Session 55.
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait d'abord (a) sur la quasi-totalité des 41 règles, et une
  décision explicite sur les cinq règles à `correlation_rule` non
  `None` (saturation, bufferbloat, remarquage QoS, fragmentation,
  PMTUD black hole).
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-55 (voir sessions précédentes pour le détail de ce choix).
- **Session 3** (corrélation et causalité) : toujours entièrement à
  faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — quatre évaluateurs, extension
  de `_EVALUATORS`, docstrings mises à jour.
- `tests/test_rule_engine.py` — douze nouveaux tests, docstring de
  module mise à jour.
- `CLAUDE.md` — État courant (nouvelle entrée Session 56, Session 55
  déplacée dans la séquence chronologique), Prochaine feature,
  Commandes qualité.
- `docs/features-backlog.md` — nouvelle entrée section 4.
- `docs/sessions/session-56.md` — ce fichier.
