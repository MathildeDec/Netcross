# Session 51 — extension du catalogue de règles à "Reseau/Serveur" (31 → 32)

### Demande initiale

Consigne récurrente habituelle : « Continue les features à faire de la
comparaison avec OmniPeek. Fais évoluer les fichiers de suivi, de tests
et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature suivante.

### Choix de la feature

`CLAUDE.md` laissait trois pistes ouvertes après la Session 50 (audit
qualité, hors feuille de route OmniPeek — la Session 49 restait la
dernière feature OmniPeek réelle) :

1. étendre le catalogue de règles (`netcross_core/expert_rules.py`) aux
   TROIS catégories entièrement sans règle : `"Reseau/Serveur"`,
   `"TLS"`, `"HTTP"` ;
2. « négociations TLS incomplètes » (§6.2) — décision architecturale
   préalable nécessaire (`Report`/`analysis.py` vs `tls_diagnostics.py`) ;
3. un début de moteur d'EXÉCUTION qui évaluerait une `Rule` contre un
   `Report` pour produire lui-même un Finding/ExpertEvent ;
4. cause probable/impact — bascule vers la Session 3 (difficulté 5/5).

Les pistes 2 à 4 supposent chacune une décision de conception plus
large ou un chantier hors calibre d'une session ponctuelle (mêmes
conclusions que les Sessions 47-49 pour des pistes similaires). Entre
les trois catégories de la piste 1, `"Reseau/Serveur"` a été retenue :

- un seul site de construction de `Finding` (`synthesis.py`, bloc
  « -- decomposition reseau / serveur -- »), contre cinq pour `"HTTP"`
  (chacun avec sa propre gradation de sévérité par classe de code de
  statut — extension mécanique plus large, mieux calibrée pour une
  session dédiée) ;
- aucun concept architectural non tranché, contrairement à `"TLS"` qui
  recoupe directement la décision en suspens sur « négociations TLS
  incomplètes » (le signal certificat déjà existant, Session 26, reste
  un concept différent et non nommé par §6.2 — le cataloguer aurait
  nécessité de trancher cette même question en creux).

`"TLS"` et `"HTTP"` restent donc entièrement sans règle après cette
session — décision explicitement reportée, comme après la Session 49.

### Ce qui a été livré

- **Une nouvelle règle** `server_processing_dominant` dans
  `_RULE_CATALOG` (`netcross_core/expert_rules.py`, 31 → 32) :
  domaine `"Reseau/Serveur"`, sévérité `a_surveiller`, confiance `0.7`
  (heuristique à seuil délibéré non calibré à un équipement précis —
  même palier que `nat_fw_silent_drop`/`arp_ip_conflict`), seuils
  `{"ratio_serveur_reseau": 3.0, "seuil_serveur_ms": 20.0}` recopiés
  directement du code de `synthesis.py` (`avg_server > 3 * avg_net and
  avg_server > 20`), `required_metrics` pointant `Report.
  server_think_time`/`Report.latency`/`Report.points` (la latence
  référence toujours le premier et le dernier point de `r.points`, pas
  une paire adjacente quelconque — précisé dans `required_context`).
- **Câblage `rule_id="server_processing_dominant"`** sur l'unique site
  de `Finding` de cette catégorie dans `build_findings()` — code
  procédural non modifié dans sa logique, seulement annoté, même
  discipline que les Sessions 48-49.
- Docstrings de module mises à jour (`expert_rules.py` : nouvelle
  section « Portée de la Session 51 » expliquant le choix parmi les
  trois catégories ; `synthesis.py` : section « Findings volontairement
  SANS `rule_id` » réduite à `"TLS"`/`"HTTP"` uniquement).

### Tests

- `tests/test_synthesis.py` : le test existant
  `test_reseau_serveur_rule_id_reste_none` converti EN PLACE en
  `test_reseau_serveur_rule_id_est_server_processing_dominant`
  (assertion et docstring mises à jour, même Report synthétique
  réutilisé) — aucun test net ajouté par cette conversion.
- `tests/test_expert_rules.py` :
  - `_EXPECTED_IDS` étendu avec `server_processing_dominant` ;
  - comptage catalogue `31` → `32` (`test_catalogue_trente_deux_regles`,
    renommé) ;
  - domaines attendus étendus à `"Reseau/Serveur"` (dix-sept familles
    au lieu de seize, test renommé) ;
  - le test d'agrégation `rule_id` (renommé
    `test_rule_id_couvre_les_trente_deux_regles_et_respecte_le_domaine`)
    peuple déjà `server_think_time`/`latency` dans son Report de test
    (repris de la section « signaux restés volontairement sans règle »)
    — désormais vérifié comme un signal CATALOGUÉ plutôt qu'orphelin,
    sans changer la construction du Report ;
  - **trois tests réellement nouveaux** : `test_http_non_cataloguee`
    (symétrique du test TLS existant, confirme que `"HTTP"` reste hors
    catalogue), `test_server_processing_dominant_domaine_et_severite`,
    `test_seuil_server_processing_dominant`.
- Total : **916 → 919** (+3 net).

### Validation

Suite complète rejouée avant tout nouveau code (916/916, hérités de la
Session 50, confirmés intacts) puis après (**919/919**, +3 net).

`ruff check .` et `ruff format --check .` propres, vérifiés avec la
version épinglée `ruff==0.16.4` (`requirements-dev.txt`/
`.pre-commit-config.yaml`), pas seulement la dernière disponible
(`0.16.7` au moment de la session). `PYTHONPATH=src lint-imports` : 65
fichiers, 164 dépendances, contrat respecté — inchangé, aucun nouveau
fichier source créé cette session (seuls `expert_rules.py`/
`synthesis.py` modifiés). `mypy --ignore-missing-imports` sur les deux
fichiers modifiés : 0 erreur imputable — les 49 erreurs préexistantes
documentées en Session 50 (fichiers non touchés par cette session, dont
`tls_diagnostics.py`/`quic_diagnostics.py`) restent hors périmètre,
inchangées.

Pas de validation bout en bout via un pcap réel : même raison qu'aux
Sessions 46-49 (détecteur déjà réel et déjà testé par ailleurs dans
`analysis.py`/`test_analysis.py`/`test_synthesis.py`, seule
l'annotation `rule_id` est nouvelle) — le test d'agrégation étendu
appelle néanmoins la vraie `build_findings()`.

`README.md` volontairement NON modifié, même raison qu'aux Sessions
46-49 : l'ajout d'une règle au catalogue et son câblage `rule_id` ne
change aucune capacité visible pour l'utilisateur final de l'outil
(CLI/PDF/GUI inchangés, seul le JSON gagne une valeur possible pour un
champ déjà exposé depuis la Session 48).

### Non traité dans cette passe

- Les deux catégories entières restant sans règle : `"TLS"` (recoupe la
  décision architecturale en suspens sur « négociations TLS
  incomplètes ») et `"HTTP"` (cinq sites de `Finding`, chacun avec sa
  propre gradation de sévérité par code de statut — extension jugée
  trop large pour cette même passe).
- « Négociations TLS incomplètes » (§6.2) — toujours aucun détecteur
  réel dans le pipeline `Report`/`Finding` ; la décision architecturale
  identifiée en Session 49 (faire vivre le signal dans
  `analysis.py`/`Report` vs l'enrichir dans `tls_diagnostics.py` sans
  jamais le rendre cataloguable) reste entièrement ouverte.
- Tout moteur d'EXÉCUTION qui évaluerait une `Rule` du catalogue contre
  un `Report` pour PRODUIRE lui-même un Finding/ExpertEvent — le sens
  reste inverse : `rule_id` annote un Finding déjà produit par le code
  procédural existant.
- Cause probable/impact — bascule en réalité vers la Session 3
  (corrélation et causalité, difficulté 5/5), hors périmètre d'un ajout
  ponctuel au catalogue de règles.
- Les 49 erreurs `mypy` documentées en Session 50 (nettoyage optionnel,
  jamais priorisé depuis la Session 38) — aucun des fichiers concernés
  n'a été retouché cette session.
