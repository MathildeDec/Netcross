# Session 70 — Alarmes et surveillance de seuils (§6.16, issue #26)

## Objectif

Première briquette du chantier « Alarmes et surveillance de seuils »
(§6.16 du features-backlog, issue GitHub #26) : implémenter le module
`src/netcross_core/alarms.py` avec fenêtre glissante, hystérésis,
durée minimale de persistance et notifications, sans déclencher
d'alarme sur une valeur ponctuelle isolée.

## Décisions de conception

### Placement dans `netcross_core`

Le module vit dans `netcross_core` (couche la plus basse du contrat
`netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser`),
ce qui interdit d'importer `Finding` depuis `netcross_report.synthesis`.
Solution : un type `AlarmSignal` (tuple `rule_id`/`segment`/`severity`/
`value`) défini dans le module, convertible depuis un `Finding` par
l'appelant — adaptateur léger côté `netcross_report` ou CLI, qui peut
importer les deux couches. Même discipline que le pilote `PacketEvidence`
(Session 35) qui définissait ses propres types dans `netcross_core` pour
ne pas dépendre de `netcross_report`.

### Pipeline implémenté

```
AlarmSignal (depuis Finding) → AlarmEngine.feed()
  → fenêtre glissante (élagage par window_seconds)
  → ratio d'échantillons positifs >= min_sample_ratio
  → durée de persistance >= min_persistence_seconds
  → AlarmEvent "raised" (ou "cleared" si hystérésis clear)
```

### Hystérésis

Deux modes :
- **Présence/absence pure** (sans `trigger_threshold`) : un signal
  présent = échantillon positif, un signal absent = négatif.
- **Numérique** (avec `trigger_threshold` + `clear_threshold`) :
  l'alarme se lève au-dessus du trigger, ne se clear qu'en dessous du
  clear — une valeur entre les deux ne clear PAS (hystérésis
  proprement dite, vérifié par
  `test_hysteresis_numerique_trigger_puis_clear`).

### Notifications

Les `AlarmEvent` sont accumulés dans `engine.events` — AUCUNE
livraison externe (email, syslog...) dans ce module. L'appelant branche
un callback sur `engine.events` ou `engine.active_alarms` pour router
vers le canal de son choix. `active_alarms` maintient l'état courant
(raised non encore cleared).

## Fichiers modifiés

- `src/netcross_core/alarms.py` (nouveau, 378 lignes) :
  `AlarmSignal`, `AlarmConfig`, `AlarmEvent`, `_SegmentState`,
  `AlarmEngine`
- `tests/test_alarms.py` (nouveau, 297 lignes) : 12 tests
- `CLAUDE.md` : état courant (Session 70, 1150/1150 tests)
- `docs/features-backlog.md` : §6.16 passé de 🔴 Manquant à 🟡 Partiel

## Tests

12 nouveaux tests (`tests/test_alarms.py`) :

1. `test_signal_isole_ne_leve_pas_alarme` — critère d'acceptation principal
2. `test_persistance_continue_leve_alarme`
3. `test_alarme_ne_se_redeclenche_pas_tant_que_non_clearée` — pas de flapping
4. `test_retour_a_la_normale_emet_cleared`
5. `test_hysteresis_numerique_trigger_puis_clear` — hystérésis
6. `test_ratio_minimal_echantillons_positifs`
7. `test_fenetre_glissante_elimine_anciens_echantillons`
8. `test_segment_none_surveille_tous_les_segments`
9. `test_signal_non_configure_est_ignore`
10. `test_value_none_avec_trigger_threshold_est_negatif`
11. `test_active_alarms_ne_garde_que_les_levees_non_clearées`
12. `test_relever_apres_clear_possible`

`pytest` : 1138/1138 → **1150/1150** (+12 net).

## Qualité

- `ruff check .` : propre
- `ruff format --check .` : propre
- `PYTHONPATH=src uv run lint-imports` : contrat de couches respecté
  (`alarms.py` n'importe que `dataclasses` stdlib, aucun nouvel import
  inter-packages)
- `uv run mypy --ignore-missing-imports src/netcross_core/alarms.py` :
  0 erreur imputable (14 erreurs préexistantes sur les autres fichiers
  du sous-graphe, inchangées depuis la Session 69)

## Limitations

Le cablage au moteur de règles (`rule_engine.evaluate()` → conversion
en `AlarmSignal`) et à la capture live (`iter_live` → cycles
d'évaluation périodiques) n'est pas fait dans cette session — c'est le
périmètre de l'issue #33 (capture en continu + diff en direct), qui
dépend de cette brique d'alarmes.
