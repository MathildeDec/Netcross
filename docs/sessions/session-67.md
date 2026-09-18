# Session 67

## Contexte

À l'issue de la Session 66, `CLAUDE.md` « Prochaine feature » ne
listait plus, parmi les règles sans évaluateur, que DIX règles jamais
auditées : les CINQ à `correlation_rule` non `None`
(`qos_dscp_remarking`, `fragmentation_new`, `saturation`, `bufferbloat`,
`pmtud_blackhole`) et CINQ règles sans corrélation (`rtp_quality_mos`,
`dns_slow_resolution`, `nat_fw_silent_drop`, `server_processing_dominant`,
`http_slow_response`) — ces cinq dernières nommées comme n'étant « a
priori mieux connue l'une que l'autre à ce stade », l'audit bloc par
bloc restant entièrement à faire avant toute rédaction (leçon des
Sessions 65/66 : ne jamais supposer une forme par ressemblance).

## Audit des cinq candidats sans corrélation

Chacun relu bloc par bloc dans `synthesis.py` (le bloc source réel) et
`netcross_core/models.py` (le champ `Report` source) avant toute
décision :

- **`rtp_quality_mos`** : source `r.rtp_streams`, une **liste de
  dicts** (pas un `dict[str, int]`/`dict[tuple, int]` comme toutes les
  règles déjà pilotées) — DEUX seuils (`mos < 3.0` → `anomalie`,
  `mos < 3.6` → `a_surveiller`), sévérité **calculée dynamiquement**
  selon le seuil franchi plutôt que lue uniformément depuis
  `rule.severity`, segment dérivé (`s["label"].split(" (SSRC=")[0]`).
  Forme entièrement nouvelle pour ce pilote — aucune brique
  réutilisable.
- **`dns_slow_resolution`** et **`http_slow_response`** : forme
  IDENTIQUE entre elles — `statistics.mean()` sur une liste plate
  (`r.dns_duration_ms`/`r.http_response_time_ms`), un seuil unique
  (200ms/500ms), segment fixe `"global"`, `sample_size=len(liste)`.
  Nouvelle forme (agrégation statistique sur une liste plate), mais
  partagée par les deux — candidat pour un lot futur une fois cette
  forme introduite une première fois.
- **`server_processing_dominant`** : compare deux moyennes
  (`r.server_think_time` vs `r.latency`, PREMIER et DERNIER point de
  `r.points`, pas une paire adjacente quelconque) avec un ratio ET un
  seuil absolu combinés (`avg_server > 3 * avg_net and avg_server > 20`)
  — corrélation de deux signaux distincts, forme la plus proche des
  cinq règles à `correlation_rule` non `None`, pas des candidats
  « simples » déjà pilotés.
- **`nat_fw_silent_drop`** : `report.idle_timeout_dropped`,
  `dict[tuple[str, str], int]` **PAR PAIRE** de points adjacents
  (vérifié dans `models.py`), condition `n <= 0: continue`, `evidence`
  à TROIS arguments via `_evidence()` (`idle_timeout_examples` +
  `idle_timeout_frames`, listes parallèles déjà présentes), sévérité
  UNIQUE lue depuis `rule.severity` (`anomalie`). **Forme EXACTEMENT
  identique** à celle déjà pilotée par `tcp_mss_clamped` (Session 59) —
  seul candidat des cinq directement reproductible sans brique
  nouvelle.

**Choix** : `nat_fw_silent_drop`, seule des cinq de forme directement
reproductible avec les briques existantes. Les quatre autres restent
non pilotées, chacune pour une raison de forme désormais documentée
(voir ci-dessus et « Prochaine feature »), pas par méconnaissance.

## Ce qui a été livré

Un nouvel évaluateur (`_EVALUATORS` passe de trente et une à
**trente-deux** entrées sur 41) : `_evaluate_nat_fw_silent_drop`,
copie du gabarit `_evaluate_tcp_mss_clamped` (boucle sur une paire de
points, `_evidence()` à trois arguments, `rule.severity`/`rule.domain`
lus depuis le catalogue plutôt que recopiés en dur).

**Point notable, troisième occurrence de ce constat** (après
`arp_ip_conflict` Session 65, confirmé par `stp_instability`
Session 66 sous une forme différente) : le seuil
`rule.thresholds["idle_timeout_seconds"]` (60.0) déclaré au catalogue
n'est PAS consommé par ce bloc — il documente un seuil déjà appliqué
en amont, côté `analysis.py::_analyse_idle_timeout` (paramètre
`idle_timeout_seconds`, jamais relu par `synthesis.py`), pas une
comparaison que l'évaluateur referait lui-même. Documenté explicitement
dans la docstring de fonction.

## Validation

- `tests/test_rule_engine.py` : 5 nouveaux tests
  (déclenche/absent/nul/evidence/équivalence, même discipline que
  `tcp_mss_clamped`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (nouvel id inséré à sa position réelle dans le dict `_EVALUATORS`) ;
  `test_regle_connue_sans_evaluateur_leve_not_implemented_error` reste
  sur `saturation` (rôle inchangé depuis la Session 63,
  `nat_fw_silent_drop` n'étant pas ce rôle).
- `pytest` : 1098/1098 → **1103/1103** (+5 net).
- `ruff check .` propre, `ruff format --check .` propre du premier
  coup (134 fichiers conformes).
- `lint-imports` inchangé en fichiers (66) ET en dépendances (169 —
  aucun nouvel import, cet évaluateur ne consomme que
  `Report.idle_timeout_dropped`/`idle_timeout_examples`/
  `idle_timeout_frames`, déjà exposés).
- `mypy --ignore-missing-imports` sur les deux fichiers modifiés
  (`rule_engine.py`/`test_rule_engine.py`) : 0 erreur imputable (27
  erreurs préexistantes visibles sur le même sous-ensemble de 7
  fichiers, reproduites uniquement SANS `PYTHONPATH=src` — même
  précision que les Sessions 63-66) ; baseline `src/` entier non
  re-décomptée cette session (aucun des deux fichiers modifiés n'en
  fait partie), reconfirmée inchangée par construction (49 erreurs/9
  fichiers, aucun des neuf fichiers concernés touché).

## Non traité dans cette passe

- Les QUATRE autres candidats sans corrélation, chacun pour une raison
  de forme désormais auditée et documentée : `rtp_quality_mos` (source
  liste de dicts, sévérité à deux seuils calculée dynamiquement —
  forme entièrement nouvelle) ; `dns_slow_resolution`/
  `http_slow_response` (agrégation `statistics.mean()` sur une liste
  plate avec un seuil unique — forme nouvelle mais partagée par les
  deux, candidat naturel pour un lot futur groupé) ;
  `server_processing_dominant` (corrélation de deux moyennes avec un
  ratio ET un seuil absolu — plus proche des règles à
  `correlation_rule` non `None`).
- Les CINQ règles à `correlation_rule` non `None`
  (`qos_dscp_remarking`, `fragmentation_new`, `saturation`,
  `bufferbloat`, `pmtud_blackhole`) — toujours les plus éloignées de ce
  pilote, aucune décision de conception prise sur leur fusion de deux
  signaux distincts.
- Câblage à un CLI/GTK4, bascule effective de `build_findings()` vers
  ce moteur, question d'ordonnancement (Session 63), nettoyage des 49
  erreurs `mypy` préexistantes : toujours hors périmètre.
