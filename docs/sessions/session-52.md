# Session 52 — extension du catalogue de règles à "HTTP" (32 → 37)

### Demande initiale

Consigne récurrente habituelle : « Continue les features à faire de la
comparaison avec OmniPeek. Fais évoluer les fichiers de suivi, de tests
et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature suivante.

### Choix de la feature

`CLAUDE.md` laissait trois pistes ouvertes après la Session 51 :

1. étendre le catalogue de règles aux DEUX catégories encore
   entièrement sans règle : `"TLS"` et `"HTTP"` ;
2. « négociations TLS incomplètes » (§6.2) — décision architecturale
   préalable nécessaire (`Report`/`analysis.py` vs `tls_diagnostics.py`) ;
3. un début de moteur d'EXÉCUTION qui évaluerait une `Rule` contre un
   `Report` pour produire lui-même un Finding/ExpertEvent ;
4. cause probable/impact — bascule vers la Session 3 (difficulté 5/5).

Les pistes 2 à 4 supposent chacune une décision de conception plus
large ou un chantier hors calibre d'une session ponctuelle (mêmes
conclusions que les Sessions 47-51 pour des pistes similaires). Entre
les deux catégories de la piste 1, `"HTTP"` a été retenue avant `"TLS"` :

- comme `"Reseau/Serveur"` en Session 51, elle ne nomme aucun concept
  architectural non tranché — les cinq signaux (4xx, 5xx, timeout,
  message manquant, latence moyenne) sont chacun un détecteur déjà
  réel et déjà nommé implicitement par la section 6.2 (« codes de
  statut HTTP », Session 17) ;
- `"TLS"` recoupe toujours la décision en suspens sur « négociations
  TLS incomplètes » identifiée en Session 49 (non revisitée ici) : le
  signal certificat déjà existant (Session 26) reste un concept
  différent et non nommé par §6.2, le cataloguer aurait nécessité de
  trancher cette même question en creux ;
- le seul coût de `"HTTP"`, déjà identifié en Session 51 comme raison
  de la reporter à l'époque, est son NOMBRE de sites (cinq, contre un
  pour `"Reseau/Serveur"`) — une différence d'ampleur, pas une
  difficulté de fond justifiant un report supplémentaire.

`"TLS"` reste donc seule catégorie entièrement sans règle après cette
session — décision explicitement reportée, comme après les Sessions 49
et 51.

### Choix de conception

Les cinq nouvelles règles sont calquées sur le même geste que les
quatre compteurs DNS bruts + `dns_slow_resolution` (Sessions 47/49,
même forme de détecteur), avec deux différences documentées dans la
docstring de module et dans chaque `Rule` :

- **Clé de transaction différente** pour `http_timeout`/`http_missing` :
  DNS suit un identifiant de transaction 16 bits (`Pkt.dns_txn_id`),
  HTTP n'en porte pas nativement en HTTP/1.x — `_analyse_http` (déjà
  existant, `analysis.py`) suit `(connexion TCP 5-tuple, URI, Nième
  occurrence de cette URI sur cette connexion)`, documentée comme
  choix délibéré (une position ordinale pure se désynchroniserait dès
  qu'une requête entière est perdue) avec sa limite assumée (polling
  répété de la même URI sur la même connexion). Repris tel quel dans
  `required_context` des deux règles, jamais reformulé de façon
  imprécise.
- **Source de la mesure différente** pour `http_slow_response` :
  `http.time`, calculé NATIVEMENT par le dissecteur HTTP de tshark par
  transaction (présent uniquement sur le paquet de réponse) — vérifié
  empiriquement en Session 17 (capture HTTP/1.1 réelle sur loopback),
  contrairement à DNS/DHCP/SIP qui recomposent la durée à la main via
  des timestamps minimaux. Documenté explicitement dans
  `required_context` pour ne pas laisser croire à une recomposition
  manuelle identique à DNS.

Sévérités et confiances reprennent le même registre que leurs analogues
DNS : `http_client_error` (4xx) → `info`/`0.9` comme `dns_nxdomain`,
`http_server_error` (5xx) → `anomalie`/`0.9` comme `dns_servfail`,
`http_timeout` → `anomalie`/`0.8` comme `dns_timeout`, `http_missing` →
`a_surveiller`/`0.8` comme `dns_missing`, `http_slow_response` →
`a_surveiller`/`0.8` comme `dns_slow_resolution` (seuil `mean_duration_ms_min:
500.0`, recopié de `synthesis.py` : `avg > 500`). Les cinq restent
AUTONOMES (`correlation_rule=None`), aucune ne partage de site de
`Finding` avec une autre (chacune des cinq boucles de `synthesis.py`
ne produit qu'une seule catégorie de signal, à la différence des
paires TCP options/MSS clamped de la Session 47).

### Ce qui a été livré

- **Cinq nouvelles règles** dans `_RULE_CATALOG`
  (`netcross_core/expert_rules.py`, 32 → 37) : `http_client_error`,
  `http_server_error`, `http_timeout`, `http_missing`,
  `http_slow_response` — domaine `"HTTP"`, chacune avec ses
  `required_metrics` pointant les champs `Report.http_*`/`Pkt.http_*`
  réellement lus par `_analyse_http` (`analysis.py`).
- **Câblage `rule_id`** sur les CINQ sites de construction de `Finding`
  de cette catégorie dans `synthesis.py::build_findings()` (bloc
  « -- HTTP -- ») — code procédural non modifié dans sa logique,
  seulement annoté, même discipline que les Sessions 48-51.
- Docstrings de module mises à jour (`expert_rules.py` : nouvelle
  section « Portée de la Session 52 » détaillant les cinq règles et
  les deux différences avec leurs analogues DNS ; `synthesis.py` :
  section « Findings volontairement SANS `rule_id` » réduite à
  `"TLS"` uniquement).

### Tests

- `tests/test_synthesis.py` : les trois tests existants
  `test_http_4xx_rule_id_reste_none`/`test_http_5xx_rule_id_reste_none`/
  `test_http_duree_moyenne_rule_id_reste_none` convertis EN PLACE en
  `test_http_4xx_rule_id_est_http_client_error`/
  `test_http_5xx_rule_id_est_http_server_error`/
  `test_http_duree_moyenne_rule_id_est_http_slow_response` (assertions
  mises à jour, mêmes Report synthétiques réutilisés) ; **deux tests
  réellement nouveaux** : `test_http_timeout_rule_id_est_http_timeout`,
  `test_http_missing_rule_id_est_http_missing` (les sites timeout/
  missing n'avaient jamais eu de test `rule_id` dédié jusqu'ici).
- `tests/test_expert_rules.py` :
  - `_EXPECTED_IDS` étendu avec les cinq nouveaux identifiants ;
  - comptage catalogue `32` → `37`
    (`test_catalogue_trente_sept_regles`, renommé) ;
  - domaines attendus étendus à `"HTTP"` (dix-huit familles au lieu de
    dix-sept, test renommé) ;
  - `test_http_non_cataloguee` supprimé (n'a plus lieu d'être, `"HTTP"`
    est désormais catalogué) ;
  - le test d'agrégation `rule_id` (renommé
    `test_rule_id_couvre_les_trente_sept_regles_et_respecte_le_domaine`)
    déplace les cinq champs `Report.http_*` de sa section « signaux
    restés volontairement sans règle » (qui ne garde plus que `"TLS"`)
    vers la section des signaux catalogués — aucun changement de
    construction du Report au-delà de ce déplacement ;
  - **cinq tests réellement nouveaux** : `test_catalogue_cinq_regles_http`,
    `test_http_client_error_est_info_http_server_error_est_anomalie`,
    `test_http_timeout_et_http_missing_severites`,
    `test_seuil_http_lent`, `test_regles_http_toutes_autonomes` ; les
    quatre règles sans palier numérique (`http_client_error`/
    `http_server_error`/`http_timeout`/`http_missing`) ajoutées au
    tuple `sans_seuil` de `test_regles_sans_palier_numerique_ont_des_
    thresholds_vides`.
- Total : **919 → 925** (+6 net : +4 dans `test_expert_rules.py`
  [+6 nouveaux, -1 `test_http_non_cataloguee` supprimé, converties
  neutres pour le reste], +2 dans `test_synthesis.py` [+5 nouveaux/
  convertis, dont 3 conversions neutres et 2 réellement nets]).

### Validation

Suite complète rejouée avant tout nouveau code (919/919, hérités de la
Session 51, confirmés intacts) puis après (**925/925**, +6 net).

`ruff check .` propre après correction de quatre lignes dépassant 120
caractères (chaînes `preconditions`/`required_metrics`/`time_window`
des nouvelles règles, reformulées sur plusieurs lignes) ; `ruff format
--check .` propre après `ruff format .` (1 fichier reformaté), vérifiés
avec la version épinglée `ruff==0.16.4` (`requirements-dev.txt`/
`.pre-commit-config.yaml`). `PYTHONPATH=src lint-imports` : 65
fichiers, 164 dépendances, contrat respecté — inchangé, aucun nouveau
fichier source créé cette session (seuls `expert_rules.py`/
`synthesis.py` modifiés côté source, plus les deux fichiers de test).
`mypy --ignore-missing-imports` sur les quatre fichiers modifiés
(source + tests) : 0 erreur imputable ; passage complet sur `src/`
confirmé inchangé à 49 erreurs préexistantes sur 9 fichiers (mêmes
fichiers que la Session 50, aucun retouché cette session).

**Validation bout en bout avec un vrai `tshark`/serveur HTTP réel**
(réseau disponible dans cet environnement, comme les Sessions 17/50/51) :
`tshark` 4.2.2 réinstallé via `apt-get` (même version que les sessions
précédentes) ; un serveur `http.server` Python réel lancé sur
`127.0.0.1:8099`, capturé en direct via `dumpcap` sur l'interface `lo`
pendant trois requêtes `curl` réelles (`/ok1` → 200, `/notfound` → 404,
`/err` → 500). Capture confirmée par `tshark -Y http` : trois
transactions avec `http.time` natif présent sur chaque réponse.
`cross_capture_analyzer_cli.py --json-report` rejoué sur cette capture
réelle (pas seulement les tests unitaires synthétiques) : la console
texte affiche bien le bloc « -- HTTP (codes de statut, HTTP/1.x
uniquement) -- » avec les deux exemples 404/500 ; le JSON produit
confirme `rule_id="http_client_error"` (sévérité `info`) et
`rule_id="http_server_error"` (sévérité `anomalie`) à la fois sur les
`findings` et sur les `expert_events` (source `"netcross"`) — aucune
requête HTTP n'ayant timeout ni été perdue sur ce trajet loopback à un
seul point, `http_timeout`/`http_missing`/`http_slow_response` ne se
déclenchent pas sur cette capture précise (comportement attendu, pas
un défaut de câblage — couverts par les tests unitaires synthétiques
ci-dessus).

`README.md` volontairement NON modifié, même raison qu'aux Sessions
46-51 : l'ajout de règles au catalogue et leur câblage `rule_id` ne
change aucune capacité visible pour l'utilisateur final de l'outil
(CLI/PDF/GUI inchangés, seul le JSON gagne une valeur possible pour un
champ déjà exposé depuis la Session 48 — le bloc console HTTP
lui-même, déjà documenté en Session 17, n'a pas changé de forme).

### Non traité dans cette passe

- La dernière catégorie entière restant sans règle : `"TLS"` (recoupe
  la décision architecturale en suspens sur « négociations TLS
  incomplètes »).
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
