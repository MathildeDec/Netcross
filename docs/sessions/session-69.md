# Session 69

## Contexte

À l'issue de la Session 68, `CLAUDE.md` « Prochaine feature » ne
listait plus, parmi les règles sans évaluateur, que SEPT règles : les
CINQ à `correlation_rule` non `None` du catalogue (`qos_dscp_remarking`,
`fragmentation_new`, `saturation`, `bufferbloat`, `pmtud_blackhole`),
toujours jamais auditées depuis l'ouverture du pilote (Session 55), et
DEUX règles sans corrélation déjà AUDITÉES par la Session 67 mais non
pilotées faute de forme directement reproductible (`rtp_quality_mos`,
`server_processing_dominant`). L'extension « (a) » nommée en premier
par « Prochaine feature » — la moins coûteuse des trois listées —
était d'auditer enfin les cinq règles à corrélation, jamais faites à
ce jour faute d'avoir jamais rouvert `synthesis.py` sur leurs blocs
respectifs. Choisie en conséquence : c'est le seul candidat dont le
coût réel restait entièrement inconnu (contrairement à
`rtp_quality_mos`/`server_processing_dominant`, déjà auditées et déjà
confirmées de forme nouvelle par la Session 67).

## Vérification avant rédaction

Même discipline que toutes les sessions précédentes de ce pilote :
chaque évaluateur doit reproduire EXACTEMENT son bloc source, jamais
une forme supposée par ressemblance. Contrairement aux audits
précédents (généralement `synthesis.py` + `models.py`), cet audit a
nécessité une troisième lecture systématique dans
`netcross_core/analysis.py` — seul moyen de trancher, pour chaque
règle, si son ou ses seuils déclarés au catalogue sont réellement
consommés au point de construction du `Finding` ou déjà entièrement
appliqués en amont (question soulevée mais jamais tranchée aussi
souvent d'un coup par un audit précédent).

- **`qos_dscp_remarking`** — `synthesis.py`, bloc `-- QoS --` : boucle
  `for (a, b), n in r.qos_change.items(): if n <= 0: continue`, lit
  ensuite `r.qos_l2_remark.get((a, b), 0)`/`r.qos_l3_remark.get((a, b),
  0)` pour le seul message, sévérité `"a_surveiller"` en dur (constante
  unique). `models.py` : les trois champs sont des
  `dict[tuple[str, str], int]` (`defaultdict(int)`). `analysis.py`
  (boucle principale, ~ligne 110-140) : `qos_l2_remark`/`qos_l3_remark`
  incrémentés au même moment que `qos_change`, selon le signe du delta
  de TTL — aucun seuil numérique nulle part dans cette règle (catalogue
  : `thresholds={}`, confirmé vide), la `correlation_rule` documente
  une attribution L2/L3, pas un palier.
- **`fragmentation_new`** — `synthesis.py`, bloc
  `-- fragmentation / MTU --` : boucle sur `r.frag_new.items()`, garde
  `n <= 0: continue`, lit `r.encap_frag_correlated.get((a, b), 0)`,
  DEUX branches (`if correlated: ... else: ...`) avec DEUX messages
  distincts et sévérités `"anomalie"`/`"a_surveiller"` en dur.
  `models.py` : mêmes types `dict[tuple[str, str], int]`. `analysis.py`
  (boucle fragmentation, ~ligne 188-232) : `encap_frag_correlated`
  incrémenté par datagramme corrélé, JAMAIS comparé à un seuil en
  amont — le test `if correlated:` du bloc source EST donc la
  comparaison au seuil catalogue (`correlated_encap_change_min_count`
  = 1.0, sur un entier jamais négatif, `correlated >= 1` ⟺
  `bool(correlated)`) : seuil réellement consommé ici, comme celui de
  `loss_per_segment` (Session 55).
- **`saturation`** — `synthesis.py`, bloc `-- saturation / policing /
  bufferbloat --` (première moitié) : boucle sur
  `r.saturation_verdict.items()`, garde par SOUS-CHAÎNE
  (`if "NON correlees" in verdict: continue`), sévérité déterminée par
  une seconde comparaison de sous-chaînes (`"saturation"`/`"policing"`/
  `"limitation"` → `"anomalie"`, sinon `"a_surveiller"`), message =
  `verdict` lui-même. `models.py` : `saturation_verdict` est un
  `dict[tuple[str, str], str]` (`dict` simple, pas `defaultdict`) —
  PREMIÈRE fois que ce pilote lit une valeur de dict qui est une
  chaîne déjà rédigée. `analysis.py::_analyse_saturation()` (~ligne
  924-963) : les CINQ seuils du catalogue (`frac_high_policing_min`
  0.7, `rel_stdev_policing_max` 0.15, `mean_loss_ratio_policing_min`
  0.85, `frac_high_saturation_min` 0.6,
  `frac_high_no_correlation_max` 0.3) y sont comparés et absorbés dans
  le texte de `verdict` AVANT toute écriture dans
  `Report.saturation_verdict` — aucun n'est donc consommé par le bloc
  de `synthesis.py` ni par l'évaluateur.
- **`bufferbloat`** — `synthesis.py`, bloc `-- saturation / policing /
  bufferbloat --` (seconde moitié) : boucle sur
  `r.bufferbloat_hint.items()`, valeur = tuple `(low_lat, high_lat)`,
  AUCUNE garde, sévérité `"a_surveiller"` en dur. `models.py` :
  `bufferbloat_hint` est un `dict[tuple[str, str], tuple[float,
  float]]` (`dict` simple). `analysis.py::_analyse_bufferbloat()`
  (~ligne 963-1010) : les TROIS seuils du catalogue
  (`high_over_low_ratio_min` 1.5, `min_absolute_delta_ms` 5.0,
  `min_common_buckets` 4.0) filtrent déjà les paires AVANT toute
  écriture dans `Report.bufferbloat_hint` — chaque entrée présente est
  déjà qualifiée, ce qui explique l'absence totale de garde côté
  source.
- **`pmtud_blackhole`** — `synthesis.py`, bloc `-- PMTUD (noir) --` :
  boucle sur `r.pmtud_blackhole.items()`, garde `n <= 0: continue`,
  `evidence` à TROIS arguments via `_evidence()`
  (`pmtud_blackhole_examples`/`pmtud_blackhole_frames`), sévérité
  `"anomalie"` en dur. `models.py` : `pmtud_blackhole` en
  `dict[tuple[str, str], int]`, les deux listes en
  `dict[tuple[str, str], list[...]]`.
  `analysis.py::_analyse_pmtud()` (~ligne 269-403) :
  `_PMTUD_MIN_SEGMENT_BYTES` (512, = `min_segment_bytes` du catalogue)
  et `len(data_pkts_a) < 2` (= `min_upstream_attempts`) filtrent déjà
  avant tout incrément de `report.pmtud_blackhole` — les deux seuils
  déclarés ne sont donc pas consommés par le bloc de `synthesis.py`.

Vérifié également, en marge de cet audit : `tests/test_expert_rules.py
::test_catalogue_cinq_regles_seulement_ont_une_correlation` confirme
que ce sont bien CINQ règles (pas quatre) qui portent une
`correlation_rule` non `None` — la docstring de la dataclass `Rule`
dans `expert_rules.py` affirmait à tort « quatre règles seulement »,
coquille sans rapport avec le travail de cette session, corrigée en
« cinq ».

## Ce qui a été livré

CINQ nouveaux évaluateurs d'un coup (`_EVALUATORS` passe de
trente-quatre à **trente-neuf** entrées sur 41) :
`_evaluate_qos_dscp_remarking`, `_evaluate_fragmentation_new`,
`_evaluate_saturation`, `_evaluate_bufferbloat`,
`_evaluate_pmtud_blackhole`. Contrairement à l'audit symétrique de la
Session 67 (portant sur les cinq dernières règles SANS corrélation,
dont quatre candidats sur cinq exigeaient une forme nouvelle), les
CINQ règles À corrélation se révèlent ici directement reproductibles à
partir de briques déjà en place dans ce pilote :

- `qos_dscp_remarking` et `pmtud_blackhole` reprennent la forme déjà
  pilotée « compteur par paire + sévérité UNIQUE lue depuis
  `rule.severity` » ; `pmtud_blackhole` avec `evidence` à trois
  arguments (forme de `nat_fw_silent_drop`/`arp_ip_conflict`),
  `qos_dscp_remarking` avec un message qui lit en plus DEUX compteurs
  `Report` compagnons (`qos_l2_remark`/`qos_l3_remark`) — simple détail
  de formatage, pas une nouvelle brique de logique.
- `bufferbloat` est la forme la PLUS SIMPLE rencontrée par ce pilote à
  ce jour : ses trois seuils catalogue étant déjà entièrement
  appliqués en amont (`_analyse_bufferbloat()`), la boucle ne porte
  AUCUNE garde — chaque entrée du dict produit un `Finding`, sans
  exception ni filtre local.
- `fragmentation_new` et `saturation` partagent le schéma à DEUX
  sévérités déjà introduit par `loss_per_segment` (Session 55, deux
  littéraux de sévérité codés en dur faute de `rule.severity` unique
  possible), mais sont les PREMIÈRES règles de ce pilote à produire
  deux MESSAGES distincts selon la branche (pas seulement une sévérité
  variable partageant un seul gabarit). `fragmentation_new` pilote
  réellement son seuil catalogue
  (`rule.thresholds["correlated_encap_change_min_count"]`, comparaison
  explicite `correlated >= <seuil>` plutôt que le test truthy en dur
  du bloc procédural — même discipline que `loss_per_segment` pour son
  propre seuil) ; `saturation` décide sa branche par comparaison de
  SOUS-CHAÎNE sur un verdict déjà entièrement rédigé en amont — forme
  jamais rencontrée par ce pilote jusqu'ici (tous les évaluateurs
  précédents testent un entier ou une liste, jamais le contenu d'une
  chaîne), ses cinq seuils catalogue n'étant pas consommés à cet
  endroit.

Docstrings de module mises à jour en conséquence (paragraphe « Portée
de la Session 69 ») dans `rule_engine.py` et `tests/
test_rule_engine.py`, avec le même niveau de détail que les paragraphes
des Sessions 56-68. `evaluate()` : compteur de règles sans évaluateur
mis à jour (« 7 des 41 » → « 2 des 41 »).

## Validation

- `tests/test_rule_engine.py` : 25 nouveaux tests, adaptés à la forme
  de chaque règle plutôt qu'un gabarit unique répété cinq fois —
  déclenche/absent/nul/équivalence pour `qos_dscp_remarking` (+ un test
  dédié aux compteurs compagnons absents par défaut) et
  `pmtud_blackhole` (+ un test d'`evidence` dédié, même forme que
  `nat_fw_silent_drop`/`arp_ip_conflict`) ; déclenche/absent/nul/seuil
  pilote/équivalence pour `fragmentation_new`, avec DEUX tests
  « déclenche » distincts (un par branche de sévérité, même discipline
  que `test_pertes_anomalie_au_dessus_de_5_pourcent`/`test_pertes_a_
  surveiller_en_dessous_de_5_pourcent` pour `loss_per_segment`) ;
  même schéma à deux branches pour `saturation`, plus un test dédié à
  la garde « NON correlees » ; déclenche/absent/équivalence pour
  `bufferbloat`, SANS test « nul » — aucune garde n'existe dans la
  boucle source, vérifié explicitement avant d'écrire les tests plutôt
  que constaté après coup. Mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue aux cinq nouveaux ids, insérés à leur position réelle dans
  `_EVALUATORS`) ; `test_regle_connue_sans_evaluateur_leve_not_
  implemented_error` passe de `saturation` (désormais pilotée, rôle
  inchangé depuis la Session 63) à `rtp_quality_mos` — dernier rôle
  disponible parmi les deux règles encore sans évaluateur.
- `pytest` : 1113/1113 → **1138/1138** (+25 net, suite complète
  rejouée, pas seulement `test_rule_engine.py`).
- `ruff check .` propre, `ruff format --check .` propre du premier
  coup (136 fichiers conformes).
- `PYTHONPATH=src lint-imports` : 66 fichiers (inchangé), 170
  dépendances (inchangé) — aucun nouvel import, ni inter-packages ni
  stdlib, contrat de couches `netcross_gtk4 -> netcross_report ->
  netcross_core -> pcap_parser` inchangé, 0 cycle.
- `mypy --ignore-missing-imports` sur les trois fichiers modifiés
  (`rule_engine.py`, `expert_rules.py`, `test_rule_engine.py`,
  invoqué SANS `PYTHONPATH=src` comme convenu depuis la Session 63) :
  0 erreur imputable à ces trois fichiers — 27 erreurs préexistantes
  remontées, même sous-ensemble de 7 fichiers hors périmètre que
  depuis la Session 50. Baseline complète re-décomptée par prudence
  (`PYTHONPATH=src uv run mypy --ignore-missing-imports src/`) malgré
  l'absence de modification des neuf fichiers concernés : inchangée,
  49 erreurs/9 fichiers.
- Pas de dépôt Git dans ce zip (`ls .git` : absent) — `pre-commit
  run --all-files` non exécutable dans cet environnement, comme pour
  toutes les sessions précédentes ; les 3 hooks qu'il orchestre
  (`ruff --fix`, `ruff-format`, `import-linter`) couverts
  individuellement par les commandes ci-dessus.

## Non traité dans cette passe

- **`rtp_quality_mos`** et **`server_processing_dominant`** — les DEUX
  seules règles du catalogue encore sans évaluateur (39/41 désormais
  couvertes). Toutes deux déjà auditées par la Session 67 et
  confirmées de forme entièrement nouvelle, sans brique réutilisable
  avec ce lot ni avec aucun évaluateur existant : `rtp_quality_mos`
  (source `r.rtp_streams`, liste de dicts, DEUX seuils, sévérité
  calculée dynamiquement) et `server_processing_dominant` (corrèle
  deux moyennes avec un ratio ET un seuil absolu — plus proche des
  cinq règles à corrélation que de la forme introduite en Session 68,
  mais sans être identique à aucune des cinq).
- Câblage de `evaluate()`/`available_rule_ids()` à un CLI ou au GTK4,
  bascule effective de `build_findings()` vers ce moteur (question de
  l'ORDONNANCEMENT des `Finding` toujours ouverte, Session 63),
  nettoyage des 49 erreurs `mypy` préexistantes, moteur de corrélation
  causale (Session 3) : toujours hors périmètre, comme depuis leur
  identification respective.
