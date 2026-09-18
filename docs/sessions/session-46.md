# Session 46 — premier jalon de la bibliothèque de règles déclarative (§6.2, dernier chantier ouvert de la Session 2, §13.3)

### Demande initiale

Consigne récurrente habituelle : « Continue les features à faire de la
comparaison avec OmniPeek. Fais évoluer les fichiers de suivi, de tests
et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature suivante.

### Choix de la feature

`CLAUDE.md` ne laissait plus que deux pistes après la Session 45 :

- **bibliothèque de règles déclarative au sens strict (§6.2)** —
  préconditions, fenêtre temporelle, corrélation, un moteur à part
  entière — explicitement qualifiée de « probablement la dernière
  feature de la Session 2, ou le premier jalon substantiel s'il s'avère
  trop large pour une seule session » ;
- **cause probable/impact** — signalée depuis la Session 36 comme
  basculant en réalité vers la Session 3 (corrélation et causalité,
  difficulté 5/5), donc hors périmètre d'un ajout ponctuel à
  `ExpertEvent`.

Le choix s'est porté sur §6.2 : c'est le seul point qui reste
véritablement dans le périmètre de la Session 2, et `CLAUDE.md`
anticipait déjà explicitement qu'un seul jalon pourrait ne pas suffire
à le couvrir en entier — ce qui s'est confirmé (voir ci-dessous).

### Cadrage du périmètre : contrat + catalogue, pas un moteur complet

§6.2 décrit une `Rule` à douze champs (id, domaine, préconditions,
métriques requises, fenêtre temporelle, seuils/percentiles, contexte
requis, règle de corrélation, sévérité, confiance, explication, pistes
de vérification) et suggère de commencer par formaliser les règles
« déjà présentes » (pertes par segment, retransmissions TCP, fenêtres à
zéro, RST, SYN sans réponse, variation de TTL, remarking QoS,
fragmentation, saturation, bufferbloat, RTP, DHCP et SIP) avant les
règles « nouvelles » (DNS lent, PMTUD noir, NAT/FW silencieux, anomalies
L2, options TCP incompatibles, négociations TLS incomplètes).

Construire un vrai MOTEUR — qui évaluerait des préconditions contre un
`Report` et déciderait lui-même de produire un `ExpertEvent` — aurait
supposé soit réimplémenter la détection déjà écrite et déjà testée dans
`analysis.py`/`synthesis.py` (risque élevé de régression sur les 830
tests existants pour un gain incertain), soit une réarchitecture des
deux fichiers pour les faire déléguer à ce moteur (chantier bien plus
vaste qu'une session, non cadré). Cette session livre donc le CONTRAT
(`Rule`) et un CATALOGUE de métadonnées qui DÉCRIT les règles déjà
codées, sans toucher à `analysis.py`/`synthesis.py` ni réimplémenter la
moindre détection — même discipline que `netcross_core.wireshark_expert`
(`_KNOWN_FLAGS`/`_REMEDIATION` formalisent des flags déjà produits par
tshark, ils n'inventent pas de nouvelle détection) et même précédent que
`PacketEvidence` en Session 35 (« un câblage réel et testé de bout en
bout sur un périmètre serré, plutôt qu'une esquisse partout sans
consommateur vérifié »).

### Pourquoi quinze entrées de catalogue pour treize concepts nommés

Les « retransmissions TCP » nommées par §6.2 recouvrent en réalité trois
signatures déjà distinguées nativement par tshark et déjà comptées
séparément côté `Report` (`retrans_fast`/`retrans_rto`/
`retrans_spurious`, voir `analysis.py::_analyse_retransmission_types`),
avec trois sévérités DIFFÉRENTES (`info`/`a_surveiller`/`a_surveiller`).
Une seule règle « retransmissions TCP » aurait dû choisir UNE sévérité
et masquer les deux autres, ou inventer un champ sévérité composite hors
du contrat à douze champs de §6.2 — les trois sous-types sont donc
devenus trois entrées distinctes (`tcp_retransmission_fast`/`_rto`/
`_spurious`). À l'inverse, DHCP et SIP recouvrent chacun deux signatures
internes (DHCPNAK + message manquant ; appel en échec + message
manquant) mais qui partagent déjà la MÊME sévérité (`"anomalie"`) dans
`synthesis.py` — les regrouper en une seule règle (`dhcp_issues`/
`sip_issues`) ne perd donc aucune information. Les onze autres concepts
nommés correspondent chacun à une seule entrée sans ambiguïté.

### Conception du contrat `Rule`

**Ordre des champs** : Python impose que tout champ de dataclass avec
une valeur par défaut soit suivi uniquement de champs avec défaut. Pour
garder dix des douze champs obligatoires (aucune règle du catalogue ne
devait pouvoir « oublier » un champ), `thresholds` (dict, `{}` par
défaut — toutes les règles n'ont pas de palier numérique, ex: RST
localisé se déclenche sur toute occurrence) et `correlation_rule` (`str
| None`, `None` par défaut — la majorité des règles restent autonomes)
ont été placés en dernier, seuls à porter une valeur par défaut.

**`severity`** : documenté comme la sévérité la PLUS ÉLEVÉE que la règle
peut produire (le pire cas), jamais masquée — la gradation réelle (ex:
pertes ≥ 5% → anomalie, sinon à surveiller) reste explicite dans
`thresholds`/`explanation`. Alternative écartée : un champ liste de
sévérités possibles, hors du schéma à douze champs exact de §6.2.

**`confidence`** : échelle à CINQ paliers discrets (0.9 lecture directe
d'une classification déterministe native ; 0.8 correspondance
déterministe multi-points par identifiant exact ; 0.75 corrélation
déterministe de deux signaux avec une hypothèse structurelle assumée ;
0.7 heuristique dépendant d'une hypothèse de topologie/ordre ; 0.6
estimation statistique), documentée en tête de module et justifiée règle
par règle. Volontairement DISTINCTE de l'échelle 1.0/0.7/0.4 déjà
utilisée par `ExpertEvent.confidence` (Session 40) : les deux mesurent
des choses différentes (confiance dans une RÈGLE de détection ici,
confiance dans une OCCURRENCE de signal là-bas) et utiliser les mêmes
trois valeurs aurait suggéré à tort qu'elles sont interchangeables.

**`correlation_rule`** : `None` pour onze des quinze règles (un seul
compteur/une seule classification suffit à les produire). Quatre règles
croisent déjà réellement DEUX signaux bruts distincts dans le code
existant — saturation (pertes + débit, `_analyse_saturation`),
bufferbloat (latence + débit, `_analyse_bufferbloat`), remarquage QoS
(DSCP + delta de TTL, boucle principale d'`analyse()`), fragmentation
(fragmentation + encapsulation, boucle fragmentation/MTU) — mais via un
code FIGÉ entre deux compteurs précis, explicitement documenté comme
n'étant PAS le moteur générique de corrélation de la Session 3.

### Vérification de chaque champ contre le code source

Avant rédaction, chaque nom de champ `Report.<x>`/`Pkt.<x>` cité dans
`required_metrics` a été confirmé par `grep` direct dans `models.py`
(vingt-quatre champs `Report`, seize champs `Pkt`, tous existants
exactement sous ce nom). Chaque seuil numérique dans `thresholds`
(5.0% pour les pertes, 0.7/0.15/0.85/0.6/0.3 pour la saturation,
1.5/5.0/4 pour le bufferbloat, 3.0/3.6 pour le MOS RTP,
1 pour la corrélation fragmentation/encapsulation) a été relu
directement dans le code source de `analysis.py`/`synthesis.py` au
moment de la rédaction — jamais estimé de mémoire. La seule règle
exposée en Finding pour « RST » a nécessité de vérifier que
`Report.rst_localized` (pas `rst_count`, qui reste un compteur brut
affiché en texte/PDF mais jamais transformé en `Finding`) était la
bonne métrique — confirmé par une recherche des deux noms dans
`synthesis.py`.

### Ce qui a été livré

- `netcross_core/expert_rules.py` (nouveau fichier) : dataclass `Rule`
  (douze champs, voir ci-dessus), catalogue `_RULE_CATALOG` (quinze
  `Rule`, un commentaire par entrée citant la fonction source exacte),
  `get_rule(rule_id) -> Rule | None`, `list_rules(domain=None) ->
  list[Rule]`. Docstring de module complète (portée de cette passe,
  échelle de confiance, règles corrélées, ce qui reste hors périmètre).
- `tests/test_expert_rules.py` (nouveau fichier, 26 tests) : forme du
  contrat `Rule` (égalité par valeur, défauts), structure du catalogue
  (quinze entrées, ids uniques et attendus, sévérités/confiances
  valides, six règles TCP, quatre règles corrélées exactement, dix
  domaines attendus), `get_rule`/`list_rules` (id connu/inconnu,
  filtre par domaine, ordre stable), seuils numériques pinnés
  (pertes/MOS/bufferbloat/saturation/fragmentation), et un test de
  traçabilité qui construit un `Report` minimal (même méthode que
  `test_synthesis.py`), appelle la VRAIE `build_findings()` et confirme
  que les catégories produites correspondent aux domaines du catalogue.

### Changement d'environnement

Comme aux Sessions 39/40/44/45, réseau disponible dans cet
environnement : `pytest`/`ruff==0.16.4`/`import-linter`/`mypy`/`scapy`
installés via `pip install --break-system-packages`, `tshark` 4.2.2
réinstallé via `apt-get` (même version que les sessions précédentes
disposant du réseau). Aucun dépôt `.git` dans le zip livré :
`pre-commit run --all-files` échoue (« FatalError: git failed »),
contourné en rejouant directement les trois hooks qu'il configure
(`ruff check`, `ruff format`, `lint-imports`) — voir ci-dessous.

### Validation

- `pytest` réel, suite complète rejouée avant tout nouveau code
  (**830/830**, hérités de la Session 45, confirmés intacts) puis après
  (**856/856**, +26 net, dont les 26 nouveaux tests de
  `test_expert_rules.py`).
- `ruff check .` : propre. `ruff format --check .` : `111 files already
  formatted`, aucun reformatage nécessaire (deux ajustements manuels de
  largeur de ligne faits pendant la rédaction, avant validation finale).
- `lint-imports` (contrat de couches `netcross_gtk4 -> netcross_report
  -> netcross_core -> pcap_parser`) : 65 fichiers analysés (+1),
  164 dépendances (+2, les deux imports de `expert_rules.py` lui-même —
  `dataclasses`/`__future__` — comptés comme dépendances externes),
  contrat respecté, aucun cycle interne.
- `mypy --ignore-missing-imports` sur le fichier source modifié
  (`expert_rules.py`) : 0 erreur imputable à ce fichier. mypy résout la
  totalité du paquet `netcross_core` via `netcross_core/__init__.py`
  (qui importe `analysis`/`parsing`/...), donc les 14 erreurs
  préexistantes accessibles depuis `netcross_core` (sous-ensemble des
  27 déjà documentées, dans `packet.py`/`ek_source.py`/`parsing.py`/
  `analysis.py`) restent affichées mais inchangées — même
  comportement déjà documenté en Session 45.
- `python -m compileall` propre sur tout `src/`.
- `pre-commit run --all-files` : `FatalError: git failed` (pas de dépôt
  git dans le zip livré) — les trois hooks configurés
  (`ruff`/`ruff-format`/`import-linter`) ont été rejoués directement
  ci-dessus, tous verts.
- **Pas de validation bout en bout via un pcap réel cette fois** :
  contrairement aux Sessions 40 à 45, qui ajoutaient chacune un champ
  exposé dans `--json-report` (donc vérifiable sur une sortie CLI
  réelle avec un vrai `tshark`), ce catalogue n'est câblé nulle part
  dans le pipeline CLI/JSON/GUI cette session (voir « Non traité »
  ci-dessous) — il n'y a rien de plus à observer sur une sortie réelle
  que ce que les tests unitaires couvrent déjà. Le test de traçabilité
  domaine ↔ `Finding.category` appelle néanmoins la vraie
  `build_findings()` (pas un double/mock), même profondeur de
  validation que l'intégralité de `test_synthesis.py` (qui ne rejoue
  pas non plus tshark, mais construit directement des `Report` cibles).

### Fichiers de suivi/documentation mis à jour

- `docs/features-backlog.md` : nouvelle entrée en tête de la section 4
  (dette identifiée), au-dessus de celle de la Session 45. Section 13.3
  (Session 2) : nouveau paragraphe « État (Session 46, premier jalon de
  la bibliothèque de règles déclarative, §6.2) ».
- `CLAUDE.md` : état courant (856/856, module `expert_rules.py`
  mentionné, portée du catalogue précisée) et prochaine feature (trois
  pistes : règles nouvelles de §6.2, câblage du catalogue à un vrai
  consommateur, ou bascule vers la Session 3). Commandes qualité :
  compteur de tests mis à jour, note mypy reformulée.
- `docs/sessions/session-46.md` : ce fichier.
- **`README.md` volontairement NON modifié cette session** : le
  catalogue est un module interne (`netcross_core/expert_rules.py`),
  purement descriptif, non câblé dans `--json-report` ni ailleurs — il
  n'ajoute aucune capacité visible pour l'utilisateur final de l'outil,
  à la différence de chaque session précédente de cette série (36 à
  45) qui touchait toutes au moins un paragraphe de la section
  `--json-report` du README. La section « Architecture du dépôt » du
  README reste également inchangée : elle ne liste que les paquets
  (`netcross_core/`, `netcross_report/`...), pas les fichiers
  individuels qui les composent.

### Non traité dans cette passe

- Les règles « nouvelles » de §6.2 (DNS lent, PMTUD noir, NAT/FW
  silencieux, anomalies L2, options TCP incompatibles, négociations TLS
  incomplètes) — §6.2 les place explicitement APRÈS les règles « déjà
  présentes » traitées dans cette session.
- Tout moteur d'EXÉCUTION qui évaluerait une `Rule` contre un `Report`
  pour PRODUIRE un `ExpertEvent`/`Finding` — ce catalogue reste
  DESCRIPTIF, l'évaluation réelle continue de se faire dans le code
  procédural existant (`analysis.py`/`synthesis.py`), non modifié ici.
- Le câblage d'un `rule_id` sur `ExpertEvent` (permettrait de relier un
  `ExpertEvent` déjà produit à la règle qui le décrit) — envisagé comme
  piste pour une session future dans `CLAUDE.md`, non fait ici.
- L'exposition du catalogue via `--json-report`/GUI — catalogue statique
  consommé uniquement par du code Python (et les tests) à ce stade.
- Cause probable/impact — reste la matière de la Session 3 (corrélation
  et causalité, difficulté 5/5), hors périmètre d'un ajout ponctuel au
  catalogue de règles, inchangé depuis la Session 36.
- Sessions 3 à 11 de la section 13.3 — entièrement à faire, inchangé
  depuis la Session 45.
