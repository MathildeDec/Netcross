# Session 57 — uv/ruff redemandés (vérifiés, inchangés), extension du moteur d'exécution à `dns_timeout`/`dns_missing`

## Contexte et choix de périmètre

Consigne de session reprenant, mot pour mot, deux chantiers déjà traités
par des sessions antérieures : « passer sur uv pour remplacer poetry »
et « corriger toutes les erreurs ruff ». Avant toute chose, vérification
qu'il ne s'agit pas d'une régression à corriger, pas une ré-exécution
aveugle de commandes déjà jouées.

**`uv` / `poetry`** : la Session 55 avait déjà établi qu'aucune trace de
`poetry` n'a jamais existé dans ce projet (`pyproject.toml` ne portait
que `[tool.ruff]`/`[tool.importlinter]` avant elle, jamais de
`[tool.poetry]`, aucun `poetry.lock` livré) — la migration réelle,
effectuée Session 55, était `pip install -r requirements.txt(+ -dev.txt)`
→ `uv`. Revérifié cette session : `uv.lock` toujours présent (49 paquets
alors, cf Session 55), `pyproject.toml` porte toujours `[project]`/
`[project.optional-dependencies.dev]`/`[tool.uv] package = false`,
`uv sync --extra dev` toujours opérationnel (voir commande ci-dessous).
Rien à migrer une seconde fois.

**`ruff`** : déjà vérifié propre aux Sessions 50 et 55, avec la version
épinglée `ruff==0.16.4`. Revérifié cette session avant tout nouveau
code :

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
124 files already formatted
```

Aucune erreur, comme aux deux sessions précédentes qui avaient posé la
question. Rien à corriger de ce côté non plus.

**Feature suivante** : CLAUDE.md « Prochaine feature », à l'issue de la
Session 56, laissait un chantier explicitement ouvert : le pilote du
moteur d'**exécution** (`netcross_report/rule_engine.py::evaluate()`)
couvrait cinq règles sur 41. Deux candidats étaient nommés
explicitement comme « premiers candidats naturels si ce chantier
continue » : `dns_timeout` et `dns_missing`, écartés du lot précédent
pour forme différente (compteurs en listes, passage par `_evidence()`
côté procédural, jamais reproduit jusqu'ici par ce pilote).

**Choix retenu : traiter ces deux candidats.** Justification : nommés
explicitement par la session précédente (pas une hypothèse à vérifier
depuis zéro), suite directe et bornée du même module, vérifiable de
bout en bout dans une seule session. Un câblage CLI/GTK4 ou une bascule
de `build_findings()` n'ont de sens qu'une fois le pilote plus avancé
(toujours vrai, même arbitrage qu'aux Sessions 55/56).

## Vérification préalable (ne pas supposer la forme uniforme)

Avant d'écrire le moindre évaluateur, vérification du type exact des
deux compteurs dans `netcross_core/models.py` :

```
$ grep -n "dns_missing\|dns_timeout" src/netcross_core/models.py
dns_missing: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
dns_timeout: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
dns_timeout_frames: dict[str, list[int | None]] = field(default_factory=lambda: defaultdict(list))
```

Confirmé : `dns_timeout` par point, avec une liste parallèle
`dns_timeout_frames` (mécanisme `PacketEvidence`, Session 35) ;
`dns_missing` par paire de points adjacents, et — point vérifié
explicitement, pas supposé par symétrie avec `dns_timeout` — **aucun**
champ `dns_missing_frames` sur `Report`. Cette asymétrie est confirmée
côté procédural : le bloc source de `dns_missing` dans
`synthesis.py::build_findings()` appelle `_evidence(seg, missing)` à
deux arguments seulement, quand celui de `dns_timeout` appelle
`_evidence(p, timeouts, r.dns_timeout_frames.get(p, []))` à trois.

Lecture des deux blocs source (`synthesis.py`, lignes ~841-866) et des
deux entrées `Rule` correspondantes (`expert_rules.py`) : `severity`
`"anomalie"` (`dns_timeout`) et `"a_surveiller"` (`dns_missing`),
`domain="DNS"` pour les deux, `thresholds` vide dans les deux cas (pas
de seuil numérique) — même discipline de sévérité pilotée par le
catalogue que le lot de la Session 56.

## Implémentation

### `_evidence()` copiée localement dans `rule_engine.py`

`_evidence()` est une fonction **privée** de `synthesis.py`. Même
discipline déjà appliquée à `_pct()` depuis la Session 55 (jamais
importée telle quelle à travers une frontière de module, même au sein
du même paquet `netcross_report`) : copie locale, corps vérifié ligne à
ligne identique à l'original. Nécessite l'import de `EvidenceLink`/
`PacketEvidence` depuis `netcross_core.expert_model` — nouveau dans ce
module (les cinq évaluateurs précédents n'en avaient pas besoin,
aucune de leurs règles ne construisant d'`evidence`).

### `_evaluate_dns_timeout`

Reproduit le bloc `-- requetes DNS sans reponse --` : itère
`report.dns_timeout.items()`, `if timeouts` (troncation de liste, pas
`if n > 0`), message avec `len(timeouts)`, `evidence=_evidence(p,
timeouts, report.dns_timeout_frames.get(p, []))`, sévérité lue depuis
`rule.severity`.

### `_evaluate_dns_missing`

Reproduit le bloc `-- messages DNS perdus entre deux points --` : itère
`report.dns_missing.items()`, clé `(a, b)`, segment `f"{a} -> {b}"`
(même forme que `hop_delta_outliers`, Session 56), `if missing`,
message avec `len(missing)`, `evidence=_evidence(seg, missing)` — SANS
`frames`, conformément à la vérification préalable ci-dessus.

`_EVALUATORS` passe de cinq à sept entrées. `evaluate()`/
`available_rule_ids()` inchangés dans leur logique (seule la table
s'étend) ; le message `NotImplementedError` mis à jour de « 36 des 41 »
à « 34 des 41 » régles restantes.

## Tests

`tests/test_rule_engine.py` : neuf nouveaux tests, même structure par
règle que les lots précédents (déclenchement avec sévérité du
catalogue, silence si compteur absent, silence si liste présente mais
vide — équivalent du "présent mais nul" pour un compteur entier),
augmentée pour ce lot d'une vérification explicite du contenu
d'`evidence` (jamais fait jusqu'ici, aucune des sept règles précédentes
n'en produisant) et d'une comparaison terme à terme de `evidence` dans
le test d'équivalence avec `build_findings()` :

```python
def test_dns_timeout_evidence_reprend_les_textes_et_les_frames():
    r = Report(points=["A"])
    r.dns_timeout["A"] = ["requete vers example.invalid"]
    r.dns_timeout_frames["A"] = [42]
    findings = evaluate("dns_timeout", r)
    ev = findings[0].evidence[0]
    assert ev.point == "A"
    assert ev.text == "requete vers example.invalid"
    assert ev.packet is not None
    assert ev.packet.frame_number == 42
```

`test_available_rule_ids_ne_contient_que_les_regles_pilotees` étendu
aux deux nouvelles entrées.

```
$ uv run pytest -q
989 passed in 3.92s
```

980/980 → **989/989** (+9 net).

## Contrôles qualité

```
$ uv run ruff check .
All checks passed!
$ uv run ruff format --check .
124 files already formatted
```

Propres, comme constaté en préambule de session.

```
$ PYTHONPATH=src uv run lint-imports
Analyzed 66 files, 169 dependencies.
Pas de cycles internes KEPT
Contracts: 1 kept, 0 broken.
```

66 fichiers (inchangé — aucun nouveau module créé), **169** dépendances
(+1 par rapport aux 168 de la Session 56) : le nouvel import
`netcross_core.expert_model` dans `rule_engine.py` ajoute une arête,
dans le sens autorisé par le contrat de couches
(`netcross_report -> netcross_core`). Contrat toujours respecté.

`mypy` sur les deux fichiers modifiés :

```
$ uv run mypy --ignore-missing-imports \
    src/netcross_report/rule_engine.py tests/test_rule_engine.py
Found 27 errors in 7 files (checked 2 source files)
```

Les 27 erreurs relevées appartiennent toutes à des fichiers
préexistants du graphe d'import atteint depuis `rule_engine.py`
(`triage.py`, `packet.py`, `ek_source.py`, `history.py`, `parsing.py`,
`analysis.py`, `netcross_report/__init__.py`) — aucune dans
`rule_engine.py` ni `test_rule_engine.py` eux-mêmes : 0 erreur
imputable à cette session. Puis reconfirmation sur l'intégralité de
`src/` (méthode de référence établie Session 50) :

```
$ uv run mypy --ignore-missing-imports src/
Found 49 errors in 9 files (checked 36 source files)
```

Mêmes 49 erreurs, mêmes 9 fichiers qu'aux Sessions 50, 55 et 56
(`analysis.py`, `tls_diagnostics.py`, `triage.py`, `quic_diagnostics.py`,
`packet.py`, `history.py`, `netcross_report/__init__.py`,
`ek_source.py`, `parsing.py`) — `rule_engine.py` n'en fait toujours pas
partie. Baseline inchangée.

## Non traité dans cette passe

- **Les ~31 autres règles sans évaluateur** : les deux candidats
  nommément identifiés depuis la Session 56 sont désormais traités ;
  aucun nouveau candidat n'a été identifié ou audité cette session.
  Reste la même réserve que Sessions 55/56 : ne pas supposer qu'une
  règle non pilotée est aussi simple que les sept déjà couvertes sans
  l'avoir vérifiée bloc par bloc dans `synthesis.py`.
- **Câblage à un CLI ou au GTK4** : `evaluate()`/`available_rule_ids()`
  toujours appelées uniquement par les tests.
- **Bascule effective de `build_findings()` vers ce moteur** :
  nécessiterait d'abord (a) sur la quasi-totalité des 41 règles, et une
  décision explicite sur les cinq règles à `correlation_rule` non
  `None` (saturation, bufferbloat, remarquage QoS, fragmentation,
  PMTUD black hole).
- **`README.md`** : volontairement non modifié, même raison qu'aux
  Sessions 46-56.
- **Les 49 erreurs `mypy` préexistantes** (Session 50) : nettoyage
  optionnel jamais priorisé, hors périmètre de cette session (aucun des
  neuf fichiers concernés touché).
- **Session 3** (corrélation et causalité, difficulté 5/5) : toujours
  entièrement à faire, alternative de fond à ce chantier incrémental.

## Fichiers modifiés

- `src/netcross_report/rule_engine.py` — deux évaluateurs
  (`_evaluate_dns_timeout`, `_evaluate_dns_missing`), copie locale de
  `_evidence()`, nouvel import `netcross_core.expert_model`, extension
  de `_EVALUATORS`, docstrings mises à jour.
- `tests/test_rule_engine.py` — neuf nouveaux tests, docstring de
  module mise à jour.
- `CLAUDE.md` — État courant (nouvelle entrée Session 57), Prochaine
  feature, Commandes qualité (compteur pytest).
- `docs/features-backlog.md` — nouvelle entrée section 4.
- `docs/sessions/session-57.md` — ce fichier.
