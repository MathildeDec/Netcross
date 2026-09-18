# Session 16 — `--live-current` sur `cross_capture_diff_cli.py`

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 15.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark` absent (`which tshark`
vide), `pytest` non installé (`ModuleNotFoundError`), pas d'accès
réseau (`pip install pytest` échoue : `No matching distribution
found`). Même contrainte que la grande majorité des sessions
précédentes (1-8, 12-15) ; toujours différente des Sessions 9/10/11 qui
avaient eu accès à un vrai `tshark`.

### Choix de la feature suivante

`FEATURES.md` section 5.2 : plus aucun candidat ⚠️ urgence haute
n'était ouvert (les 5 items de cette catégorie ont tous été traités
Sessions 6 à 11). En 🟠 urgence moyenne, trois candidats restaient
après la Session 15 :

1. `--live` sur `cross_capture_diff_cli.py`
2. Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)
3. Gestion mémoire des grosses captures

(2) et (3) nécessitent explicitement du vrai trafic/matériel ou des
captures de plusieurs Go pour être ne serait-ce qu'évalués — signalés
comme tels dans `FEATURES.md` depuis leur création, jamais retenus par
aucune session précédente pour cette raison, toujours hors d'atteinte
ici (pas de `tshark`, pas de réseau, pas de gros fichiers). Seul (1)
est réalisable dans cet environnement : c'est une question de
conception et de câblage Python pur, aucune des deux options
n'implique de faire tourner `tshark` pour être *conçue* (seule
l'exécution réelle d'une capture live en dépendrait, comme pour
`--live` sur l'autre CLI en Session 5 — validée alors par simulation).
Retenue par élimination, comme la Session 13 (DNS) et la Session 15
(score de confiance) l'avaient été en leur temps pour la même raison.

Ce point était resté ouvert et sans réponse depuis la Session 5 (`--live`
avait été livré sur `cross_capture_analyzer_cli.py` cette session-là,
mais la session avait été interrompue par l'utilisateur avant de
l'étendre au diff CLI), puis explicitement requalifié et documenté comme
nécessitant une vraie décision de conception (pas un simple câblage) en
Session 8 — voir `FEATURES.md` section 4 point 14, historique complet.

### Décision de conception assumée

Deux lectures possibles avaient été identifiées sans être tranchées :

1. Capturer les DEUX scénarios (baseline et courant) en direct
   simultanément, sur des interfaces différentes.
2. Capturer uniquement le run **courant** en direct, et le comparer à
   un baseline déjà enregistré sur fichier.

Choix : la lecture 2. Raisonnement : un baseline est par construction
une référence **déjà établie** — un état de fonctionnement connu,
enregistré à l'avance (souvent avant un correctif ou un changement de
configuration), pas un second flux réseau qui existerait au même
instant que le run courant. Capturer le baseline en direct en parallèle
du courant n'aurait de sens que si les deux réseaux à comparer
coexistaient réellement au même instant sur le terrain — ce n'est pas
le scénario que ce CLI sert (comparer un AVANT et un APRÈS, pas deux
sites simultanés ; ce dernier cas, deux populations de trafic
coexistant dans une même capture, est déjà couvert par la comparaison
client vs client de la Session 14). `--baseline` reste donc **toujours**
un ou plusieurs fichiers ; seul `--current` gagne un équivalent live.

Cette dissymétrie règle au passage la question du format laissée
ouverte en Session 8 ("lequel de `--baseline`/`--current` devient live,
et comment le signaler sans casser le format `NOM=chemin` existant ?") :
`--baseline`/`--current` gardent inchangé leur format `NOM=chemin` (rien
ne change côté baseline), et le nouveau flag `--live-current` a son
propre format dédié `LABEL:INTERFACE[:FILTRE_BPF]` — identique à celui
de `--live` sur `cross_capture_analyzer_cli.py`, pas de nouveau format à
apprendre.

### Ce qui a été livré

- **`src/cross_capture_diff_cli.py`** :
  - `--live-current LABEL:INTERFACE[:FILTRE_BPF]` (répétable) : capture
    en direct le run courant au lieu de le lire depuis des fichiers.
    Mutuellement exclusif avec `--current` ; l'un des deux est requis
    (`--current` n'est donc plus `required=True` au niveau argparse, la
    validation "l'un des deux" est manuelle, comme pour `--capture`/
    `--live` sur l'autre CLI).
  - `--live-duration` : durée max optionnelle en secondes (défaut :
    illimitée, arrêt sur Ctrl+C uniquement) — même sémantique que sur
    `cross_capture_analyzer_cli.py`.
  - `_parse_live_spec` et `_run_live_captures` : copiés (pas
    factorisés dans un module partagé — chaque CLI reste volontairement
    indépendante, voir docstring du module) depuis
    `cross_capture_analyzer_cli.py`, adaptés pour ne piloter que le run
    courant (préfixe de log `[courant/LABEL]` au lieu de `[LABEL]`, pas
    de paramètre `scenario_name` puisqu'il n'y a qu'un seul scénario
    concerné). Même mécanique : un thread par point, arrêt sur
    `SIGINT` ou `threading.Timer`, un point en échec ne bloque pas les
    autres.
  - `_run_scenario` refactorée : la partie corrélation+analyse en est
    extraite dans `_analyse_packets(all_packets, points_order, args)`,
    réutilisée telle quelle pour le chemin live (qui a déjà ses
    paquets, pas de fichiers à charger) et pour le chemin fichier
    existant (`_run_scenario` = `_load_packets` puis
    `_analyse_packets`).
  - Validations ajoutées, toutes avec message d'erreur dédié et
    `sys.exit(1)` (même style que les validations `--capture`/`--live`
    existantes sur l'autre CLI) :
    - ni `--current` ni `--live-current` fourni → refusé.
    - `--current` et `--live-current` fournis ensemble → refusé.
    - `--live-current` + `--parallel` → refusé (déjà un thread par
      point ; et `--parallel` s'appliquerait aussi au chargement du
      baseline, ce qui mélangerait les deux mécaniques pour un gain
      marginal — choix volontairement plus strict que nécessaire, par
      cohérence avec `--live` sur l'autre CLI plutôt que pour une
      contrainte technique réelle côté baseline).
    - `--live-current` + `--tls`/`--quic` → refusé (ces diagnostics
      relisent les fichiers passés à `--current` avec un pipeline
      indépendant ; un run courant capturé en direct n'a pas de
      fichier à relire).
  - Bannière console adaptée : "CAPTURE EN DIRECT DU RUN COURANT" à la
    place de "CHARGEMENT DU RUN COURANT" quand `--live-current` est
    utilisé.
  - Docstring du module mise à jour (prérequis capacités réseau pour
    `--live-current`, nouvel exemple d'utilisation).

### Validation

Pas d'accès réseau ni `tshark` (voir "Contrainte d'environnement"
ci-dessus) :
- `python -m compileall` propre sur tout `src/` et `tests/`.
- Aucune ligne de plus de 120 caractères introduite (`awk` sur les deux
  fichiers touchés, cohérent avec `line-length = 120` de `ruff` même
  sans pouvoir lancer `ruff` lui-même ici).
- **`pytest` toujours indisponible dans cet environnement** (confirmé
  en tout début de session, voir ci-dessus) : suite rejouée via un
  petit harnais de secours maison (mêmes principes que les Sessions
  8/12/13 — `pytest.raises`/`monkeypatch`/`capsys` réimplémentés a
  minima, hors de l'arbre livré) : **12 nouveaux tests** dans le
  nouveau fichier `tests/test_diff_cli_live.py`, tous verts. **362/362
  au total** (350 hérités de la Session 15 + 12 nouveaux), aucune
  régression sur les tests hérités (aucun d'eux ne touche
  `cross_capture_diff_cli.py`, qui n'avait jamais été testé
  directement jusqu'ici — voir "Fichiers de suivi/documentation mis à
  jour" ci-dessous).
- Les 12 nouveaux tests couvrent : `_parse_live_spec` (format valide
  avec/sans filtre BPF, filtre BPF contenant lui-même des `:`, formats
  invalides) ; les 4 validations d'arguments (ni l'un ni l'autre, les
  deux à la fois, `--live-current`+`--parallel`, `--live-current`+
  `--tls`/`--quic`) ; deux scénarios bout-en-bout avec
  `parse_capture`/`parse_live` monkeypatchés (paquets synthétiques via
  `make_pkt`, pas de vrai thread réseau ni `tshark`) — un point unique,
  puis deux points simultanés (`LAN`/`WAN`) pour vérifier que le
  préfixe de log et le filtre BPF affiché sont corrects pour chacun.
- Vérification manuelle supplémentaire (script ad hoc, pas dans
  `tests/`) : combinaison `--baseline`+`--live-current` avec un
  baseline à 2 paquets et un courant live à 1 paquet (asymétrique
  volontairement, pour confirmer que `_analyse_packets` ne suppose pas
  des volumes égaux des deux côtés) — le rapport de diff s'est généré
  sans erreur, `sys.exit(1)` n'est pas déclenché en l'absence de
  régression détectée entre les deux (comportement attendu, cohérent
  avec le code de sortie existant du CLI).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** :
  - Section 2 "CLIs" : entrée `cross_capture_diff_cli.py` mise à jour
    avec `--live-current`/`--live-duration` ; la ligne ⚠️ signalant
    l'absence de `--live` dédié supprimée (résolue).
  - Section 4 point 14 : passé de "signalé sans réponse" à "✅ Fait en
    Session 16", avec le détail complet de la décision de conception
    (voir "Décision de conception assumée" ci-dessus, dupliqué en plus
    court dans `FEATURES.md` par cohérence avec le style des autres
    points ✅ de cette section).
  - Section 5.2 : ligne "`--live` sur `cross_capture_diff_cli.py`"
    déplacée en "✅ Fait en Session 16" dans le tableau 🟠 urgence
    moyenne, avec renvoi vers `claude.md` pour le raisonnement complet.
    Ne restent en 🟠 que les deux candidats non réalisables ici
    (validation CAPWAP sur vraie capture, gestion mémoire des grosses
    captures) — tout le reste de la dette encore ouverte est en 🟢
    urgence faible.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** :
  - Section "Comparer deux captures (avant/après)" : nouveau paragraphe
    `--live-current` dans la liste des options, avec exemple d'usage
    dédié.
  - Section "Interface graphique" : paragraphe "Parité restante avec
    le CLI" mis à jour (les deux CLI ont désormais chacun leur variante
    `--live`/`--live-current` ; seule la GUI n'expose pas encore la
    capture en direct en mode comparaison).
  - Section "Tests" : décompte corrigé de 221 à 362 tests — ce chiffre
    n'avait plus été mis à jour depuis la Session 6 alors que la suite
    avait continué de grandir à chaque session suivante (écart constaté
    au passage lors de cette session, corrigé ici ; les occurrences de
    "221" dans `FEATURES.md`/`claude.md` elles-mêmes ne sont pas
    touchées, ce sont des instantanés historiques propres à la Session
    6/7/8, pas une prétention d'état courant).

### Non traité dans cette passe

- **Validation CAPWAP sur vraie capture, gestion mémoire grosses
  captures** — seuls candidats 🟠 restants, toujours hors d'atteinte
  sans `tshark` ni matériel/gros fichiers réels, aucun traité ici, une
  feature à la fois.
- **`--live-current` combiné à `--tls`/`--quic`** — refusé
  explicitement (voir "Ce qui a été livré"), pas une extension
  envisagée dans cette passe : donnerait un diagnostic TLS/QUIC "en
  direct" qui n'a pas d'équivalent conçu ailleurs dans le projet (ni
  sur l'autre CLI, ni sur la GUI) ; resterait à concevoir spécifiquement
  si demandé, comme pour `--live-current` lui-même avant cette session.

