# Session 48 — câblage du catalogue de règles à un consommateur réel (`rule_id`)

### Demande initiale

Consigne récurrente habituelle : « Continue les features à faire de la
comparaison avec OmniPeek. Fais évoluer les fichiers de suivi, de tests
et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature suivante.

### Choix de la feature

`CLAUDE.md` laissait trois pistes après la Session 47 : câbler le
catalogue de règles (`netcross_core/expert_rules.py`, 23 règles) à un
vrai consommateur, construire un détecteur réel pour « négociations TLS
incomplètes » avant de pouvoir le cataloguer, ou basculer vers la
Session 3 (cause probable/impact, corrélation causale, difficulté
5/5). La troisième est manifestement hors calibre pour une session
ponctuelle. Entre les deux premières, le câblage a été retenu : la
Session 47 le décrivait déjà comme la suite naturelle une fois le
catalogue complet (23/23 règles), et c'est un chantier d'annotation d'un
pipeline déjà réel — plus proche en nature du reste de ce chantier de
bibliothèque de règles (Sessions 46-47) qu'une détection TLS entièrement
nouvelle à écrire dans `analysis.py`.

### Ce que « câbler » signifie ici, et ce que ça ne signifie pas

`CLAUDE.md` citait deux formes possibles : un champ `rule_id` sur
`ExpertEvent`, ou un début de moteur d'EXÉCUTION qui évaluerait une
`Rule` contre un `Report` pour produire lui-même un Finding/ExpertEvent.
La première a été retenue explicitement — la seconde est un chantier
bien plus large (première brique réelle de la Session 3) qui n'a pas sa
place dans une session d'annotation. Le sens reste donc toujours
ANNOTATION : `rule_id` documente un Finding déjà produit par le code
procédural existant (`analysis.py`/`synthesis.py`, non modifiés dans
leur logique cette session), il ne pilote ni ne remplace rien.

### Où poser le champ : `Finding` (synthesis.py), pas seulement `ExpertEvent`

`CLAUDE.md` ne mentionnait que `ExpertEvent`, mais `Finding` porte déjà
`sample_size`/`evidence`/`event` avec exactement la même convention
(champ optionnel, `None`/liste vide par défaut, recopié vers
`ExpertEvent` par `build_expert_events()`). Poser `rule_id` uniquement
sur `ExpertEvent` aurait cassé cette convention et rendu le champ
invisible pour tout consommateur qui n'appelle jamais
`build_expert_events()` (le CLI `--triage`, par exemple, ne construit
que des `Finding`). `rule_id` est donc ajouté aux deux, avec la même
recopie `getattr` défensive déjà utilisée pour `evidence`
(`DiffFinding` ne déclare ni l'un ni l'autre).

### Audit préalable : pourquoi `category` seule ne suffit pas

Avant d'écrire le moindre `rule_id="..."`, la question centrale était :
un `Finding.category` identifie-t-il sans ambiguïté une règle du
catalogue ? Vérification directe : `list_rules(domain="TCP")` retourne
HUIT règles distinctes (zero-window, RST localisé, SYN sans réponse,
trois types de retransmission, options retirées, MSS clamped) — la
réponse est non. Il fallait donc auditer, un par un, chacun des **~44
sites de construction de `Finding`** dans `build_findings()`
(`synthesis.py`), pas seulement les 23 déjà couverts par le catalogue,
et comparer chaque site au `required_metrics` exact de la règle
candidate (jamais une simple coïncidence de nom de catégorie).

Cet audit a mis au jour des paires de signaux voisins, même catégorie,
un seul couvert par le catalogue :

- **Routage** : `hop_delta_outliers` (ECMP/re-routage) à côté de
  `ttl_unstable` — seule cette dernière est catalogué (`ttl_variation`,
  qui ne lit que `Report.ttl_unstable`).
- **QoS** : `pcp_change` (802.1p) à côté de `qos_change` (DSCP) — seul
  ce dernier est catalogué (`qos_dscp_remarking`).
- **Fragmentation** : `icmp_frag_needed`/`icmpv6_too_big` (compteurs
  ICMP(v6) bruts) à côté de `frag_new` — seul ce dernier est catalogué
  (`fragmentation_new`).
- **TCP** : `syn_reply_missing` à côté de `syn_no_synack` — seul ce
  dernier est catalogué (`tcp_syn_no_synack`, qui ne lit que
  `Report.syn_no_synack`, vérifié dans son `required_metrics`).
- **DNS** : les quatre compteurs bruts `dns_nxdomain_count`/
  `dns_servfail_count`/`dns_timeout`/`dns_missing` à côté de
  `dns_duration_ms` — seul ce dernier est catalogué
  (`dns_slow_resolution`, qui ne lit que `Report.dns_duration_ms`).

Et trois catégories **entières** sans aucune règle au catalogue :
`"Reseau/Serveur"` (décomposition applicatif/réseau), `"TLS"` (signal
certificat existant, Session 26 — concept différent de « négociations
incomplètes », déjà explicitement laissé de côté en Session 47),
`"HTTP"` (codes de statut, Session 17).

Dans chacun de ces cas, `rule_id` reste `None` — jamais absorbé par la
règle voisine de la même catégorie par extension implicite, même
discipline que « ne jamais inventer une règle sans détecteur réel
derrière » (Sessions 46-47), appliquée ici côté annotation plutôt que
côté catalogue.

### Résultat de l'audit : couverture exacte

Une fois les ~26 sites restants (sur ~44) rattachés à leur règle, une
vérification programmatique (différence d'ensembles, avant même
d'écrire les tests) a confirmé une propriété qui n'était pas garantie a
priori : l'ensemble des `rule_id` effectivement utilisés dans
`synthesis.py` est **exactement identique** à l'ensemble des 23 `id` du
catalogue — aucune règle n'a été oubliée côté annotation, et aucun
identifiant inventé ou mal orthographié ne s'est glissé dans
`synthesis.py`. Cette propriété est maintenant figée par le test
d'agrégation ajouté à `test_expert_rules.py` (voir plus bas), qui
échouerait immédiatement si un futur ajout de règle oubliait de la
relier à un site réel, ou inversement.

Quatre identifiants sont partagés par deux sites distincts (même règle,
deux signaux du même détecteur qui produisent chacun leur `Finding`) :
`tcp_options_stripped` (Window Scale + SACK retirés), `dhcp_issues`
(DHCPNAK + message manquant), `sip_issues` (appel échoué + message
manquant), `stp_instability` (changement de topologie + réélection du
pont racine) — cohérent avec la Session 47, qui avait déjà noté ces
regroupements côté catalogue.

### Exposition : JSON seulement, pas CLI/PDF/GUI

`netcross_report/json_report.py` expose `rule_id` : côté `_finding_dict`
avec la même convention que `sample_size`/`evidence` (clé absente
plutôt que `None` explicite sur un `Finding` orphelin) ; côté
`_expert_event_dict` toujours présente, exposée telle quelle comme
`cause`/`impact`/`confidence` (y compris `None` côté source `"tshark"`,
où le catalogue ne s'applique jamais — voir plus bas).

Le CLI `--triage`, le PDF et la GUI GTK4 n'ont pas été modifiés :
`rule_id` est un identifiant technique destiné à un consommateur
programmatique (dashboard, pipeline CI), les trois affichent déjà une
table lisible par un humain (severity/category/segment/message) où cet
identifiant n'a pas sa place — même raisonnement que l'absence de
`sample_size`/`evidence` dans le PDF aujourd'hui, documenté
explicitement plutôt que laissé comme un oubli silencieux.

### `rule_id` est un miroir exact de `remediation`, mais dans l'autre sens

`ExpertEvent.remediation` (Session 45) est un texte rédigé, disponible
UNIQUEMENT côté source `"tshark"` et toujours `None` côté `"netcross"`.
`rule_id` (Session 48) est un identifiant LU (jamais rédigé ni deviné),
disponible UNIQUEMENT côté source `"netcross"` et toujours `None` côté
`"tshark"` : le catalogue de `expert_rules.py` décrit des détecteurs
Netcross (`analysis.py`/`synthesis.py`), pas les signaux d'expertise
bruts du dissecteur tshark lui-même — les deux mondes restent
distincts, comme documenté depuis la Session 1. Cette symétrie est
vérifiée par un test dédié
(`test_generate_json_report_wireshark_expert_events_rule_id_toujours_none`).

### Ce qui a été livré

- `netcross_report/synthesis.py` (modifié) : champ `rule_id: str | None
  = None` sur `Finding` ; `rule_id="..."` posé sur les ~26 sites de
  construction de `Finding` qui correspondent exactement à une règle du
  catalogue (28 occurrences au total, certains identifiants réutilisés
  sur deux sites). Docstring de module étendue : politique de couverture
  complète, liste exhaustive des signaux volontairement laissés
  orphelins et des trois catégories encore sans règle, portée exacte de
  l'exposition JSON (pas CLI/PDF/GUI).
- `netcross_core/expert_model.py` (modifié) : champ `rule_id: str | None
  = None` sur `ExpertEvent`, docstring de classe étendue (miroir exact
  de `remediation`, section dédiée).
- `netcross_report/expert_events.py` (modifié) : `build_expert_events()`
  recopie `getattr(f, "rule_id", None)` de `Finding` vers `ExpertEvent`
  ; docstring de module étendue (`rule_id` est la seule exception au
  paragraphe « tous ces champs restent `None` côté netcross »).
- `netcross_report/json_report.py` (modifié) : `_finding_dict` expose
  `"rule_id"` si non `None` (même convention que `sample_size`) ;
  `_expert_event_dict` l'expose toujours (même convention que
  `cause`/`impact`). Docstrings des deux fonctions étendues.
- `netcross_core/expert_rules.py` (modifié, docstring seulement, aucune
  entrée de catalogue ajoutée) : la portée « Session 48 » documentée en
  tête de module, remplace le bullet « câblage rule_id non traité » de
  la liste « volontairement non traité ».
- `tests/test_synthesis.py` (modifié) : 42 nouveaux tests, un par site
  de construction de `Finding` — 27 vérifiant l'identifiant exact posé,
  distinguant explicitement les paires partageant une même règle
  (`tcp_options_stripped`, `dhcp_issues`, `sip_issues`,
  `stp_instability`), et 15 vérifiant qu'un signal volontairement laissé
  orphelin garde bien `rule_id is None`, chacun mis en regard explicite
  du signal voisin couvert par une règle dans la même catégorie.
- `tests/test_expert_rules.py` (modifié) : un test d'agrégation
  (`test_rule_id_couvre_les_vingt_trois_regles_et_respecte_le_domaine`)
  qui construit un `Report` déclenchant l'ensemble des signaux
  catalogués et plusieurs signaux orphelins à la fois, puis vérifie pour
  chaque `Finding` produit que `rule_id` est soit `None` soit un
  identifiant qui résout réellement via `get_rule()` avec le bon
  `domain`, et que les 23 règles sont chacune utilisée au moins une
  fois.
- `tests/test_expert_events.py` (modifié) : 3 nouveaux tests — recopie
  depuis `Finding.rule_id`, `None` par défaut pour un Finding orphelin,
  comportement avec `DiffFinding` (ne déclare pas ce champ, ne doit pas
  lever d'exception).
- `tests/test_json_report.py` (modifié) : 4 nouveaux tests — `rule_id`
  exposé/absent côté `_finding_dict`, exposé côté `_expert_event_dict`
  source `"netcross"`, toujours `None` côté source `"tshark"`.

### Changement d'environnement

Environnement de travail neuf pour cette session (pas de suite directe
d'une session précédente encore active) : `pytest`, `ruff==0.16.4`,
`import-linter`, `mypy`, `cryptography`, `reportlab`, `matplotlib`,
`networkx` installés via `pip install --break-system-packages` (réseau
disponible, `pypi.org`/`files.pythonhosted.org` accessibles). `tshark`
absent de cet environnement — sans incidence : aucun test de la suite
n'invoque un vrai sous-processus `tshark` (fixtures/objets construits à
la main, comme documenté depuis les sessions précédentes). Aucun dépôt
`.git` dans le zip livré : `pre-commit run --all-files` non exécutable,
contourné par `ruff check`/`ruff format --check`/`lint-imports`
séparément, comme documenté depuis plusieurs sessions.

### Validation

- `pytest` réel, suite complète rejouée avant tout nouveau code
  (**862/862**, hérités de la Session 47) puis après (**912/912** final,
  +50 net — 42 dans `test_synthesis.py`, 1 dans `test_expert_rules.py`,
  3 dans `test_expert_events.py`, 4 dans `test_json_report.py`).
- `ruff check .` propre. `ruff format --check .` : 113 fichiers déjà
  conformes, aucun ajustement manuel nécessaire cette fois.
- `lint-imports` : 65 fichiers, 164 dépendances, contrat de couches
  respecté — inchangé par rapport à la Session 47 (aucun nouveau fichier
  source, seulement des ajouts dans des fichiers déjà comptabilisés).
- `mypy --ignore-missing-imports` sur les cinq fichiers source modifiés
  (`synthesis.py`, `expert_model.py`, `expert_events.py`,
  `json_report.py`, `expert_rules.py`) : 0 erreur imputable, aucune
  régression introduite par les nouveaux champs optionnels `str | None`.
- `python -m compileall` propre sur tout `src/`.
- Pas de validation bout en bout via un pcap réel : `rule_id` est un
  champ d'annotation posé sur un pipeline déjà entièrement testé par
  ailleurs (`Report` → `build_findings()` → JSON), rien de nouveau à
  observer sur une capture réelle que les tests unitaires et le test
  d'agrégation ne couvrent déjà. Le test d'agrégation appelle
  néanmoins la vraie `build_findings()` sur un `Report` construit pour
  déclencher l'ensemble des 23 signaux catalogués et 17 signaux
  orphelins à la fois.
- Diff complet contre le zip fourni en entrée de session vérifié
  (`diff -rq`, hors caches d'outils) : exactement les 5 fichiers source
  et les 4 fichiers de test attendus modifiés, plus `CLAUDE.md` et
  `docs/features-backlog.md` pour cette passe de documentation — aucun
  effet de bord, aucun fichier source oublié.

### Fichiers de suivi/documentation mis à jour

- `docs/features-backlog.md` : nouvelle entrée en tête de la section 4,
  au-dessus de celle de la Session 47. Section 13.3 (Session 2) :
  nouveau paragraphe « État (Session 48, câblage du catalogue à un
  consommateur réel) » après celui de la Session 47 (non modifié,
  conservé comme instantané historique).
- `CLAUDE.md` : état courant (912/912, câblage `rule_id` décrit avec
  son périmètre exact) et prochaine feature (étendre la couverture aux
  signaux orphelins/catégories non couvertes, construire un détecteur
  TLS réel, un moteur d'exécution, ou basculer Session 3). Commandes
  qualité : compteur de tests et référence de session mis à jour.
- `docs/sessions/session-48.md` : ce fichier.
- **`README.md` à nouveau volontairement NON modifié**, même raison
  qu'aux Sessions 46-47 : un champ JSON supplémentaire pour un
  consommateur programmatique n'est pas une capacité visible pour
  l'utilisateur final de l'outil.

### Non traité dans cette passe

- Extension de la couverture du catalogue aux signaux restés
  volontairement `rule_id=None` (trois catégories entières et cinq
  paires de signaux voisins identifiées ci-dessus) — décision explicite
  reportée à une session future, pas une extension mécanique du même
  geste : certains sont de simples formalisations dans l'esprit des
  Sessions 46-47, d'autres nommeraient un concept que §6.2 n'a jamais
  cité.
- « Négociations TLS incomplètes » (§6.2) — toujours aucun détecteur
  réel derrière (inchangé depuis la Session 47).
- Tout moteur d'EXÉCUTION qui évaluerait une `Rule` contre un `Report`
  pour PRODUIRE lui-même un Finding/ExpertEvent — le sens reste
  ANNOTATION cette session, pas EXÉCUTION.
- Cause probable/impact — reste la matière de la Session 3, inchangé
  depuis la Session 36.
- Sessions 3 à 11 de la section 13.3 — entièrement à faire, inchangé.
