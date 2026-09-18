# Session 58 — extension du moteur d'exécution à six règles TCP supplémentaires

## Contexte et choix de périmètre

CLAUDE.md « Prochaine feature », à l'issue de la Session 57, laissait un
chantier explicitement ouvert : le pilote du moteur d'**exécution**
(`netcross_report/rule_engine.py::evaluate()`) couvrait sept règles sur
41. Les deux candidats nommés explicitement depuis la Session 56
(`dns_timeout`, `dns_missing`) étaient désormais traités ; « le choix
précis reste à faire en début de session suivante », avec la mise en
garde explicite de ne pas supposer les ~31 règles restantes aussi
simples que les sept déjà pilotées sans les avoir vérifiées bloc par
bloc dans `synthesis.py`.

**Vérification préalable de l'état** : suite complète rejouée avant
tout nouveau code, comme demandé par CLAUDE.md.

```
$ uv run pytest -q
989 passed in 3.40s
```

989/989 confirmé, conforme à l'état courant documenté.

**Recherche du prochain candidat** : plutôt que d'auditer les 34 règles
restantes une par une au hasard, inspection systématique du catalogue
(`expert_rules.py`) pour repérer les règles sans `correlation_rule` et
sans `thresholds` (même profil que les sept règles déjà pilotées) :

```python
# thresholds=None et corr=None pour, entre autres :
# tcp_retransmission_fast, tcp_retransmission_rto,
# tcp_retransmission_spurious, tcp_rst_localized, tcp_syn_no_synack,
# syn_reply_missing, ttl_variation, pcp_change,
# icmp_fragmentation_needed, tcp_options_stripped, tcp_mss_clamped,
# dhcp_issues, sip_issues, http_client_error, ...
```

Puis repérage de leurs blocs sources dans `synthesis.py` :

```
$ grep -n 'rule_id="tcp_rst_localized"\|rule_id="syn_reply_missing"\|...' \
    src/netcross_report/synthesis.py
```

**Découverte** : les six règles `tcp_retransmission_rto`,
`tcp_retransmission_spurious`, `tcp_retransmission_fast`,
`tcp_rst_localized`, `tcp_syn_no_synack`, `syn_reply_missing`
appartiennent toutes au même bloc source `-- TCP avance --`
(`synthesis.py`, lignes ~608-722) déjà partiellement pilotée
(`tcp_zero_window`, Session 56) — même forme exacte : compteur
`dict[str, int]` sur `Report`, itération directe du dict (pas
`report.points`), `if n > 0`, sévérité unique lue depuis
`rule.severity` (aucune des six ne porte de seuil dans
`rule.thresholds` — dict vide, vérifié dans le catalogue avant
rédaction), aucune `evidence`. Vérification bloc par bloc effectuée
pour les six (pas supposée uniforme malgré la ressemblance visuelle) :
aucune ne cache de corrélation ou de seuil supplémentaire caché dans
une condition annexe.

**Choix retenu : traiter ces six candidats.** Justification : même
bloc source déjà entamé (continuité directe avec `tcp_zero_window`),
forme strictement identique aux sept règles déjà pilotées (aucune
nouvelle discipline à introduire, contrairement à `dns_timeout`/
`dns_missing` qui avaient nécessité `_evidence()`), lot borné et
vérifiable de bout en bout dans une seule session. Les deux dernières
règles du même bloc source (`tcp_options_stripped`, `tcp_mss_clamped`)
sont explicitement écartées — voir « Non traité dans cette passe ».

## Vérification préalable des types (ne pas supposer la forme uniforme)

```
$ grep -n "retrans_rto\|retrans_spurious\|retrans_fast\|rst_localized\|syn_no_synack\|syn_reply_missing" \
    src/netcross_core/models.py
retrans_fast: dict[str, int] = field(default_factory=lambda: defaultdict(int))
retrans_rto: dict[str, int] = field(default_factory=lambda: defaultdict(int))
retrans_spurious: dict[str, int] = field(default_factory=lambda: defaultdict(int))
rst_localized: dict[str, int] = field(default_factory=lambda: defaultdict(int))
syn_no_synack: dict[str, int] = field(default_factory=lambda: defaultdict(int))
syn_reply_missing: dict[str, int] = field(default_factory=lambda: defaultdict(int))
```

Confirmé : six `dict[str, int]`, clés par point (pas par paire), même
forme que `Report.zero_window` (`tcp_zero_window`, Session 56). Lecture
des six entrées `Rule` correspondantes (`expert_rules.py`) pour
confirmer la sévérité attendue et l'absence de seuil : `severity`
`"a_surveiller"` (`tcp_retransmission_rto`, `tcp_retransmission_spurious`),
`"info"` (`tcp_retransmission_fast` — seule sévérité `info` du lot),
`"anomalie"` (`tcp_rst_localized`, `tcp_syn_no_synack`,
`syn_reply_missing`), `domain="TCP"` pour les six, `thresholds={}` dans
les six cas.

Les trois règles de retransmission (`fast`/`rto`/`spurious`) partagent
une discipline de classement mutuellement exclusif documentée dans
`expert_rules.py` (priorité spurious > fast > simple, un paquet n'est
compté que dans une seule des trois catégories) : cela ne change rien
côté évaluateur, chacun lit son propre compteur déjà agrégé en amont
par `analysis.py` — aucune logique de classement à reproduire ici.

## Implémentation

Six nouveaux évaluateurs ajoutés à `rule_engine.py`, chacun reproduisant
EXACTEMENT son bloc source correspondant dans
`synthesis.py::build_findings()` (même message, même condition, sévérité
lue depuis `rule.severity` plutôt que recopiée en dur) :

- `_evaluate_tcp_retransmission_rto` — `report.retrans_rto.items()`
- `_evaluate_tcp_retransmission_spurious` — `report.retrans_spurious.items()`
- `_evaluate_tcp_retransmission_fast` — `report.retrans_fast.items()`
- `_evaluate_tcp_rst_localized` — `report.rst_localized.items()`
- `_evaluate_tcp_syn_no_synack` — `report.syn_no_synack.items()`
- `_evaluate_syn_reply_missing` — `report.syn_reply_missing.items()`

`_EVALUATORS` passe de sept à treize entrées. `evaluate()` inchangé
dans sa logique (seule la table s'étend, la docstring passe de « 34 des
41 » à « 28 des 41 » régles restantes).

## Tests

`tests/test_rule_engine.py` : dix-huit nouveaux tests, trois par règle
(même structure que les lots précédents) :

```python
def test_tcp_rst_localized_declenche_severite_du_catalogue():
    r = Report(points=["A"])
    r.rst_localized["A"] = 5
    findings = evaluate("tcp_rst_localized", r)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "anomalie"
    assert f.category == "TCP"
    assert f.segment == "A"
    assert f.rule_id == "tcp_rst_localized"
    assert "injection locale probable" in f.message
```

Le filtre d'équivalence par règle utilise `rule_id`, jamais `category`
seule : la catégorie « TCP » porte désormais NEUF `rule_id` distincts
dans ce pilote (`tcp_zero_window` + les six nouveaux + deux autres non
encore pilotés), même raison documentée depuis la Session 56.

**Deux tests préexistants mis à jour**, cassés par ce lot :
- `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  ciblait `tcp_rst_localized` comme exemple de règle connue mais non
  pilotée — désormais fausse depuis ce lot. Remplacée par
  `tcp_options_stripped`, toujours sans évaluateur (voir « Non traité
  dans cette passe »).
- `test_available_rule_ids_ne_contient_que_les_regles_pilotees` —
  liste étendue aux treize règles désormais pilotées, ordre
  d'enregistrement dans `_EVALUATORS` préservé (comparaison `==`, pas
  `set`, même discipline que les sessions précédentes).

```
$ uv run pytest -q
1008 passed in 1.00s
```

989/989 → **1008/1008** (+19 net : dix-huit nouveaux tests, le
remplacement de cible dans le test `NotImplementedError` ne change pas
le compte total).

## Contrôles qualité

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
unformatted: File would be reformatted
   --> tests/test_rule_engine.py:676:1
1 file would be reformatted, 124 files already formatted
```

Une ligne vide surnuméraire en fin de fichier après l'ajout des
nouveaux tests. Corrigée :

```
$ uv run ruff format .
1 file reformatted, 124 files left unchanged
$ uv run ruff format --check .
125 files already formatted
$ uv run pytest -q
1008 passed in 1.00s
```

Suite rejouée après reformatage : toujours 1008/1008 (le reformatage
n'a touché que du whitespace).

```
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

66 fichiers, **169** dépendances — inchangé par rapport à la Session
57 : aucun nouveau module créé, aucun nouvel import ajouté (les six
évaluateurs n'utilisent que `Rule`/`Report`/`Finding`, déjà importés
par ce module ; contrairement à la Session 57, pas besoin
d'`EvidenceLink`/`PacketEvidence` puisqu'aucune de ces six règles ne
construit d'`evidence`). Contrat toujours respecté.

`mypy` sur les deux fichiers modifiés :

```
$ uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)
```

Mêmes 27 erreurs préexistantes (mêmes 7 fichiers du graphe d'import
atteint depuis `rule_engine.py`) que la Session 57 — aucune dans
`rule_engine.py` ni `test_rule_engine.py` eux-mêmes : 0 erreur
imputable à cette session. Reconfirmation sur l'intégralité de `src/` :

```
$ uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes 49 erreurs, mêmes 9 fichiers qu'aux Sessions 50, 55, 56 et 57.
Baseline inchangée.

## Non traité dans cette passe

- **`tcp_options_stripped`/`tcp_mss_clamped`** : les deux dernières
  règles du même bloc source `-- TCP avance --`, écartées de ce lot
  pour forme différente — `tcp_options_stripped` correspond à DEUX
  sites de construction distincts dans `synthesis.py`
  (`wscale_stripped`/`sack_stripped`, deux compteurs `Report` séparés)
  fusionnés sous un seul `rule_id`, jamais fait jusqu'ici par ce
  pilote ; `tcp_mss_clamped` construit une `evidence` non vide et est
  clée par paire de points (`mss_clamped_examples`/
  `mss_clamped_frames`), plus proche en forme de `dns_timeout`
  (Session 57) que du reste de ce lot.
- **Les ~25 autres règles sans évaluateur** : non auditées
  individuellement pour leur simplicité, même réserve documentée
  depuis la Session 56.
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait d'abord (a) sur la quasi-totalité des 41 règles, et une
  décision explicite sur les cinq règles à `correlation_rule` non
  `None` (saturation, bufferbloat, remarquage QoS, fragmentation,
  PMTUD black hole).
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-57.
- **Les 49 erreurs `mypy` préexistantes** (Session 50) : nettoyage
  optionnel jamais priorisé, hors périmètre de cette session.
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — six évaluateurs
  (`_evaluate_tcp_retransmission_rto`,
  `_evaluate_tcp_retransmission_spurious`,
  `_evaluate_tcp_retransmission_fast`, `_evaluate_tcp_rst_localized`,
  `_evaluate_tcp_syn_no_synack`, `_evaluate_syn_reply_missing`),
  extension de `_EVALUATORS`, docstrings mises à jour.
- `tests/test_rule_engine.py` — dix-huit nouveaux tests, deux tests
  préexistants corrigés (cible `NotImplementedError`, liste
  `available_rule_ids`), docstring de module mise à jour.
- `CLAUDE.md` — État courant (nouvelle entrée Session 58), Prochaine
  feature, Commandes qualité (compteur pytest).
- `docs/features-backlog.md` — nouvelle entrée section 4.
- `docs/sessions/session-58.md` — ce fichier.
