# Session 31 — mesure empirique du gain `--parallel`

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" -- même consigne que
les Sessions 8 à 30.

### Contrainte d'environnement de cette session

`tshark` (4.2.2), `pytest`/`ruff`/`import-linter`, `scapy`, accès réseau
tous disponibles -- même situation que les Sessions 29/30. Constat fait
au moment de concevoir le benchmark, pas en tout début de session :
**`os.cpu_count()` renvoie 1** dans ce conteneur. Fait déterminant pour
le choix et l'interprétation de la mesure -- voir "Choix de la feature
suivante" et "Démarche".

### Choix de la feature suivante

`FEATURES.md` section 5.2 après Session 30 : le seul candidat 🟠 restant
(CAPWAP vendeur réel) toujours hors d'atteinte sans matériel. Côté 🟢 :
CAPWAP Fortinet, NetFlow/sFlow, capture continue et pistes GitHub
écartés pour les mêmes raisons qu'aux Sessions 29/30 (respectivement
hors d'atteinte sans trafic vendeur réel, chantier à architecture
propre, explicitement "à cadrer avant de coder", exploratoire sans
engagement). Reste "Validations admin (.rpm Rocky, gain `--parallel`,
FIXME/licence)" -- jusqu'ici jamais retenue, écartée à chaque session
précédente au profit d'un candidat de code plus substantiel. Cette fois,
plus aucun autre candidat de code n'est disponible : décomposée en ses
trois sous-points pour vérifier ce qui est réellement actionnable.
`.rpm Rocky` : nécessite une vraie Rocky Linux, absente ; `rpmbuild`
lui-même déjà confirmé absent en Session 30. `FIXME/licence` : les
placeholders (`FIXME-mettre-votre-email@example.com`, URL GitHub)
appellent les vraies coordonnées du mainteneur, qu'aucune session
automatisée ne peut deviner sans inventer une fausse information --
vérifié que `LICENSE` elle-même n'a en réalité aucun FIXME (MIT ne
requiert qu'un nom et une année, déjà présents), seuls
`debian/control`/`changelog` et `netcross.spec` en portent encore.
Reste "gain `--parallel`" : seul sous-point réellement mesurable dans
cet environnement. Retenu.

### Démarche : mesurer avant de conclure

Même discipline que PMTUD/retransmissions/options TCP (Sessions 9-11) et
mémoire (Session 19) en leur temps : avant d'écrire quoi que ce soit,
6 captures synthétiques `scapy` de 8000 paquets TCP chacune générées,
lues par le vrai `cross_capture_analyzer_cli.py` (vrai `tshark`),
`time.time()` autour du process complet (temps réel écoulé, pas le temps
cumulé déjà affiché par le CLI), 2 répétitions par scénario -- première
tentative à 20 000 paquets/fichier abandonnée : dépassait la limite de
temps d'exécution d'une seule invocation d'outil, réduite à 8000/fichier
pour tenir dans des appels séparés par scénario.

**Avant même de lancer la mesure** : `os.cpu_count()` renvoie 1 dans cet
environnement -- `--parallel` sans `--parallel-workers` explicite
(défaut = `os.cpu_count()`, voir `pcap_parser.capture.
parse_captures_parallel`, `ProcessPoolExecutor(max_workers=None)`) ne
crée donc qu'un seul worker effectif. Aucune concurrence réelle possible
par construction, quel que soit le résultat -- mais la mesure a quand
même été menée jusqu'au bout plutôt que de s'arrêter à ce constat
théorique, pour vérifier concrètement le coût (ou l'absence de coût) du
mécanisme lui-même (mise en place du pool de processus) par rapport à un
simple appel séquentiel.

### Résultat mesuré

| Scénario | Temps réel écoulé (moyenne/2 runs) | Écart |
|---|---|---|
| Séquentiel | 13.66s | -- |
| `--parallel` (défaut, 1 worker effectif) | 14.20s | +4% |
| `--parallel --parallel-workers 6` (sur-souscription) | 14.96s | +9.5% |

Confirmé : aucun gain sur cet environnement, léger surcoût mesurable
(mise en place du `ProcessPoolExecutor`), aggravé par la sur-souscription
explicite (workers > cœurs disponibles) -- confirmé une deuxième fois en
observant les temps *individuels* par fichier pendant la validation
(`--parallel-workers 4` sur seulement 2 fichiers, analyzer) : ~2.3s par
fichier en mode 1-worker-effectif contre ~4.4s en 4-workers-forcés sur le
même unique cœur -- les processus `tshark` se disputent bien le CPU au
lieu de s'exécuter réellement en parallèle. Spécifique à cet
environnement à 1 seul cœur : le mécanisme (`ProcessPoolExecutor`, un
processus `tshark` indépendant par fichier) reste architecturalement
sain et devrait apporter un gain réel sur un hôte multi-cœurs, mais cette
hypothèse n'a pas pu être vérifiée ici faute d'un tel hôte -- signalé
comme non confirmé, pas supposé vrai par analogie.

### Décision de conception

Plutôt que de s'arrêter à documenter la mesure sans toucher au code
(lecture stricte de "tests/ménage, pas de code"), décidé d'ajouter un
diagnostic minimal sur les deux CLI : au lancement de `--parallel`,
afficher les workers effectifs et `os.cpu_count()` détecté, puis avertir
si un seul worker effectif (aucun gain à attendre) ou si
`--parallel-workers` dépasse explicitement le nombre de cœurs détectés
(sur-souscription, risque de ralentissement plutôt que d'accélération).
Justifié par le fait que la mesure a révélé une information directement
actionnable pour quiconque lance `--parallel` sur un hôte contraint
(conteneur/VM à 1-2 vCPU, de plus en plus courant) -- le message
existant ("temps réel écoulé inférieur SI le parallélisme a effectivement
joué") ne suffisait pas à la faire comprendre. Reste volontairement
minimal : pas de garde-fou qui désactiverait `--parallel-workers`
au-delà du nombre de cœurs détectés -- seulement informatif, l'utilisateur
reste libre de l'ignorer (ex. s'il sait son I/O plus contraignant que
son CPU).

### Ce qui a été livré

- **`cross_capture_analyzer_cli.py`**/**`cross_capture_diff_cli.py`** :
  `import os` ajouté (absent jusqu'ici) ; au lancement de `--parallel`,
  affichage des workers effectifs/`os.cpu_count()`, puis l'un des deux
  avertissements selon le cas (aucun si plusieurs workers effectifs sans
  sur-souscription). Comportement sans `--parallel` strictement
  inchangé.
- **Aucune modification** dans `pcap_parser.capture`
  (`parse_captures_parallel`) : le mécanisme n'a pas changé, seul le
  message affiché avant de l'appeler.

### Validation

596/596 tests hérités toujours verts -- aucun test dédié à ce diagnostic
(imprime sur stdout selon `os.cpu_count()`/`args.parallel_workers`, déjà
à la limite de ce que ce projet couvre par `pytest` pour les CLI
eux-mêmes, voir section 5.2). `ruff check`/`ruff format --check`/
`PYTHONPATH=src lint-imports` réexécutés, tout passe (59 fichiers, 146
dépendances, aucun cycle).

Les trois cas rejoués réellement sur les deux CLI (vrai `tshark`, vrais
pcap `scapy`) : `--parallel` seul (avertissement "aucun gain" affiché,
1 worker effectif confirmé) ; `--parallel --parallel-workers 4`
(analyzer) et `--parallel-workers 3` (diff) en sur-souscription
(avertissement "se disputent le CPU" affiché, temps individuels par
fichier confirmés dégradés dans la sortie du CLI lui-même) ; cas normal
sans avertissement non retesté séparément (couvert par construction, les
deux branches ne se déclenchant que sur les deux conditions ci-dessus).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : nouvelle entrée en tête de section 4
  ("Session 31", tableau des résultats mesurés inclus) ; section 5.2,
  ligne "Validations admin" scindée en deux -- "gain `--parallel`"
  barrée et marquée mesurée, nouvelle ligne pour les deux sous-points
  restants (.rpm Rocky, FIXME/licence).
- **`claude.md`** (ce fichier) : cette section, ajoutée en fin de
  fichier (même remarque qu'aux Sessions 27-30 : ordre déjà non
  strictement chronologique depuis la Session 26).
- **`README.md`** : note sur `--parallel` mise à jour avec le résultat
  mesuré (voir section correspondante).

### Non traité dans cette passe

- **`.rpm Rocky`** -- nécessite une vraie Rocky Linux, indisponible ;
  `rpmbuild` lui-même absent depuis la Session 30.
- **`FIXME`/licence** -- placeholders nécessitant les vraies coordonnées
  du mainteneur, non renseignables sans inventer une fausse information.
- **Mesure du gain `--parallel` sur un hôte multi-cœurs réel** --
  mécanisme jugé sain architecturalement mais non confirmé
  empiriquement, faute d'un tel hôte dans cet environnement.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** -- seul
  candidat 🟠 restant, toujours hors d'atteinte sans matériel/trafic
  vendeur réel.
- **Plus aucun candidat de code substantiel dans `FEATURES.md` section
  5.2** à l'issue de cette session -- tous les candidats 🟢 restants sont
  soit hors d'atteinte sans matériel/trafic réel (CAPWAP Fortinet),
  explicitement qualifiés de chantier à architecture propre (NetFlow/
  sFlow) ou "à cadrer avant de coder" (capture continue), soit
  exploratoires sans engagement (pistes GitHub). Une session future
  devra probablement soit cadrer l'une de ces pistes plus large avant de
  coder, soit attendre qu'un environnement différent lève l'une des
  limites matérielles actuelles.

