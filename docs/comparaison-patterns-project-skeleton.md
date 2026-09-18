# Comparaison PATTERNS.md (project-skeleton) vs netcross

> **Note (Session 42)** : cette analyse (Session 34) cite `claude.md` et
> `FEATURES.md` comme fichiers uniques à la racine, y compris par numéro de
> ligne (ex. « lignes 409, 492, 537, 2500 »). Depuis la Session 42, `claude.md`
> a été éclaté en `docs/sessions/session-NN.md` et `FEATURES.md` déplacé vers
> `docs/features-backlog.md` — le contenu cité reste exact, mais les chemins
> et numéros de ligne littéraux ci-dessous ne le sont plus. Non réécrit ligne
> par ligne faute de pouvoir revérifier chaque référence sans risque d'erreur ;
> à garder en tête en lisant ce document plutôt qu'à prendre au pied de la
> lettre.

Analyse ponctuelle demandée hors cycle de session « feature » habituel : pour
chaque règle de `PATTERNS.md` (catalogue de motifs non métier portés depuis le
`CLAUDE.md` de `switch-capture` vers `project-skeleton`), vérification dans le
code source réel de netcross (`grep`/lecture, pas supposition) de son
implémentation et de sa documentation dans ce dépôt (`FEATURES.md`,
`claude.md`, `README.md`, ou à défaut docstring de module).

Méthode : chaque affirmation ci-dessous est appuyée par une commande
effectivement exécutée sur le code de ce dépôt (pas une relecture visuelle
seule). Quand un motif voisin existe mais diffère dans son mécanisme, je le
signale explicitement plutôt que de compter la règle comme respectée par
ressemblance.

---

## 1. Architecture générale

### Un seul exécutable, un seul fichier source

**Ne s'applique pas à netcross tel quel.** `project-skeleton` a un seul
binaire (`src/app`) qui arbitre CLI/GTK selon les arguments. netcross a une
architecture différente et assumée : **quatre points d'entrée séparés**,
chacun avec un rôle fixe — `cross_capture_analyzer_cli.py`,
`cross_capture_diff_cli.py`, `cross_history_cli.py`, `netcross_gtk4/app.py`
(confirmé : `ls src/*.py` + `build-deb/wrappers/` contient 4 scripts
wrapper : `netcross`, `netcross-diff`, `netcross-gui`, `netcross-history`).
Pas de bascule CLI/GUI automatique sur un même exécutable. Différence
d'architecture assumée, pas un oubli : netcross a trois usages CLI
distincts (analyse simple / comparaison / historique) qui n'ont pas de sens
à fusionner dans un seul point d'entrée à bascule.

### Séparation core / cli / gtk

**S'applique et est implémentée.** `netcross_core` (moteur d'analyse) ne
dépend jamais de GTK ni des CLIs ; `netcross_report` (synthèse/PDF/JSON) et
`netcross_gtk4` sont des consommateurs séparés. Contrairement au
squelette (séparation *conventionnelle*, non outillée), netcross **impose**
cette séparation via un contrat `import-linter` de type `layers` :
`netcross_gtk4 → netcross_report → netcross_core → pcap_parser` (vérifié :
`pyproject.toml`, section `[tool.importlinter]` ; confirmé en exécutant
`PYTHONPATH=src lint-imports` → « Pas de cycles internes KEPT », « 1 kept, 0
broken »).
**Documenté** : `FEATURES.md` section 1 (tableau des packages + ligne
`import-linter`), section « Outillage qualité ».

### GUI : plusieurs pages plutôt qu'un formulaire à rallonge

**S'applique et est implémentée.** `netcross_gtk4/app.py` utilise
`Gtk.Stack` + `Gtk.StackSwitcher`, 3 pages (Configuration / Travail /
Résultats) — vérifié par grep (`Gtk.Stack`, `Gtk.StackSwitcher`, ligne 394 et
docstring de module ligne 5).
**Documenté** : `FEATURES.md` ligne 1015 (« ✅ 3 pages
(Configuration/Travail/Résultats)... »), et docstring de module
`netcross_gtk4/app.py`.

---

## 2. Concurrence

### `prepare()` / étape bloquante séparés (même objet `Thread`)

**S'applique partiellement, mécanisme différent.** netcross a bien un
flux à deux temps pour la capture en direct côté GUI (démarrer la capture
→ bouton « Arrêter et analyser » → `_end_live_capture()` →
`_join_live_and_analyze()`), mais **n'utilise pas** un objet réutilisable
avec deux méthodes (`prepare()`/`run_blocking()`) sur le même
`threading.Thread` : chaque phase instancie un **nouveau**
`threading.Thread(...)` (vérifié : `app.py` lignes ~763, 784, 850, 908 —
quatre appels indépendants à `threading.Thread(...).start()`). Le principe
sous-jacent (« un `Thread` ne démarre qu'une fois dans sa vie ») est
respecté de fait, par un idiome plus simple (thread neuf à chaque phase)
plutôt que par la classe `BackgroundJob` du squelette.
**Non documenté** comme motif explicite (aucune mention dans
`FEATURES.md`/`claude.md` de ce choix d'architecture ; seul le code lui-même
en témoigne).

### Ctrl+C (SIGINT) propre — CLI

**S'applique et est implémentée**, sur les deux CLIs qui font de la
capture en direct : `signal.signal(signal.SIGINT, _on_sigint)` +
`threading.Event` coopératif (`stop_event`), restauration du handler
précédent en `finally` (vérifié :
`grep -n "signal\." src/cross_capture_analyzer_cli.py
src/cross_capture_diff_cli.py` → lignes 216/239 et 239/262 respectivement).
`cross_history_cli.py` n'en a pas besoin (pas de thread bloquant).
**Documenté** : `FEATURES.md` section 4 (point « Capture en direct absente
des deux CLIs — fait pour `cross_capture_analyzer_cli.py` »：« arrêt sur
`SIGINT`... ») et plusieurs sessions de `claude.md` (ex. lignes 409, 492,
537, 2500 — recherche `grep -n "SIGINT" claude.md`).

### Ctrl+C (SIGINT) propre — GTK4

**S'applique et n'est PAS implémentée.** Aucune occurrence de
`signal.signal`, `SIGINT`, ni `GLib.unix_signal_add` dans
`netcross_gtk4/app.py` (vérifié par grep, aucun résultat). La capture en
direct côté GUI ne s'arrête que par clic sur le bouton dédié
(`work_stop_btn`) ou par la durée max (`GLib.timeout_add_seconds`) — un
Ctrl+C dans le terminal qui a lancé `netcross-gui` produirait très
probablement le même symptôme que celui diagnostiqué dans le squelette
(`KeyboardInterrupt` brut dans un callback GLib, jamais de fermeture
propre), mais rien ne le corrige ni ne le documente ici.
**Non documenté.**

### Point de fermeture unique

**Ne s'applique pas vraiment ici, faute d'état à fermer proprement.**
Il n'y a ni préférences persistantes ni ressource à libérer explicitement à
la fermeture (pas de fichier de config à sauvegarder, voir section 3
ci-dessous) : aucun gestionnaire `close-request`/`destroy` personnalisé
n'existe dans `app.py` (vérifié : `grep -n "close\|destroy" app.py`, aucun
résultat pertinent). Le risque que ce motif adresse dans le squelette
(dupliquer la logique de fermeture entre plusieurs déclencheurs) ne se
matérialise pas ici puisqu'il n'y a qu'un seul déclencheur de sortie (le
bouton de fermeture natif GTK) et rien à synchroniser dessus.

---

## 3. GTK4 — motifs d'interface

### Champs conditionnels (`ConditionalRow`)

**S'applique, mais n'est pas repris comme abstraction générique.**
netcross a bien des champs dont la visibilité dépend d'un autre
(`single_options_box.set_visible(not diff_mode)`, TLS/QUIC masqués en mode
comparaison — voir `FEATURES.md` ligne ~1037), mais c'est câblé au cas par
cas dans `MainWindow`, pas via une classe réutilisable façon
`ConditionalRow` du squelette (vérifié : `grep -n "ConditionalRow"
app.py` → rien). Fonctionnellement équivalent au cas par cas, mais pas le
même niveau de factorisation.
**Non documenté** comme motif nommé.

### Scrollbars classiques, jamais de défilement horizontal

**S'applique et est implémentée**, avec exactement le même appel que le
squelette : `set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)` +
`set_overlay_scrolling(False)` (vérifié : `app.py::_visible_scroller`,
lignes 61-67).
**Documenté, mais seulement dans le docstring du code** (module
`netcross_gtk4/app.py`, lignes 8-9 : « Les zones de défilement utilisent des
scrollbars classiques toujours visibles... »). **Aucune** mention dans
`FEATURES.md`/`claude.md`/`README.md` (vérifié par grep, aucun résultat) —
la règle est documentée, mais pas dans les fichiers de suivi du projet.

### Menu hamburger + page Préférences

**S'applique, n'est pas implémentée.** Aucune trace de `Gio.Menu`,
`Popover`, `MenuButton` ni de page Préférences dans `app.py` (grep sans
résultat). netcross n'a pas de notion de préférences GUI persistantes du
tout (voir point suivant).
**Non documenté** (aucune mention dans les 3 fichiers de suivi).

### Préférences persistantes : fusion à l'écriture

**S'applique, n'est pas implémentée.** Aucun `load_settings`/
`save_settings`, aucun fichier de config utilisateur écrit par la GUI
(vérifié par grep, rien). Tous les réglages (fenêtre temporelle, cadence
RTP, mode NAT-tolérant, top-N triage...) sont ré-saisis à chaque lancement,
rien n'est mémorisé entre deux sessions de l'interface.
**Non documenté** — et il n'y a d'ailleurs rien à documenter comme choix
délibéré : c'est une fonctionnalité absente, pas une décision tranchée par
écrit quelque part.

### Icône de l'application

**S'applique partiellement, non implémentée.** `NetcrossApp` déclare un
`application_id="org.netcross.analyzer"` (vérifié, ligne 1325) mais rien
d'équivalent à `_register_app_icon()`/`APP_ID` en constante partagée, pas de
fichier `.desktop`, pas de répertoire `icons/hicolor/...` dans le dépôt
(vérifié : `find . -iname "*.desktop"` → aucun résultat).
**Non documenté** comme choix explicite (contrairement au squelette qui
documente précisément pourquoi l'icône est posée sans fichiers réels).

---

## 4. Sudo, affichage graphique, session distante

### Diagnostic actionnable sudo + GUI + RDP

**S'applique, n'est pas implémentée.** Aucune capture du `RuntimeError`
PyGObject de connexion à l'affichage, aucun message de diagnostic
(`XAUTHORITY`, `xhost`...), et le bug connexe (`do_activate` qui avale les
exceptions, `Gtk.Application.run()` renvoyant 0 malgré un échec) n'est pas
traité non plus : `NetcrossApp.do_activate`/`main()` (lignes 1323-1339) ne
capturent rien, ne suivent aucun `exit_code` (vérifié par lecture directe du
code, reproduit ci-dessus).
**Non documenté.**

### Contournement GVFS/GOA dans le sélecteur de fichiers

**Ne s'applique pas de la même façon — API différente.** netcross utilise
`Gtk.FileDialog` (API GTK4 récente, portée par xdg-desktop-portal), pas
`Gtk.FileChooserNative` comme le squelette (vérifié :
`grep -n "FileDialog\|FileChooserNative" app.py` → seulement `FileDialog`,
3 occurrences, lignes 255/1243/1268). Le risque exact décrit dans
`PATTERNS.md` (sollicitation des moniteurs de volumes GVFS) est spécifique à
`FileChooserNative` ; il pourrait exister un risque analogue côté portail
D-Bus avec `FileDialog`, mais **rien ne le vérifie ni ne le corrige ici**
(`GIO_USE_VFS`/`GIO_USE_VOLUME_MONITOR` absents, vérifié par grep sur tout
`src/`, aucun résultat). Différence d'architecture réelle, mais absence de
vérification équivalente malgré tout.
**Non documenté.**

---

## 5. Secrets

**Section entière non applicable à netcross**, pour une raison
architecturale claire et vérifiée : netcross n'accède à **aucun système
distant nécessitant une authentification**. Il lit des fichiers `.pcap`/
`.pcapng` déjà capturés, ou capture en direct sur une interface réseau
locale (`tshark -i <interface>`) — contrairement à `switch-capture` qui se
connecte en SSH à des équipements HPE Comware et a donc besoin d'un mot de
passe. Vérifié : `grep -rln "keyring\|keepass\|credentials\|password\|secret"
src/` ne retourne que `netcross_core/quic_diagnostics.py`, où « secret »
désigne exclusivement les clés cryptographiques QUIC (RFC 9001, dérivation
HKDF), un sens totalement différent, sans rapport avec la gestion
d'identifiants.

Concrètement, pour chaque sous-règle de la section 5 :
- **Chaîne de résolution explicite > env > trousseau > repli KeePass** :
  non applicable (rien à résoudre).
- **Aucun secret écrit sur disque** : non applicable (netcross ne
  manipule aucun secret).
- **Confirmation avant action destructrice (retaper une valeur)** : non
  applicable — netcross n'a **aucune action destructrice/irréversible**
  dans son périmètre (pas de suppression d'historique — `history.py`
  n'expose que `record_run`/`record_diff_run`/`list_history`, vérifié par
  grep des définitions de fonctions, aucun `delete`/`drop`/`purge` —, pas
  de modification de configuration d'équipement).
- **Journalisation d'audit des commandes envoyées à un système externe** :
  non applicable — netcross n'envoie de commande à aucun système externe
  (tshark tourne en local, jamais via un canal distant type SSH).
- **Principe du moindre privilège / binaire helper `setcap`** : non
  applicable — netcross n'a pas de mode nécessitant `CAP_NET_ADMIN` isolé
  dans un binaire C séparé ; la capture live utilise directement `tshark`
  avec les droits de l'utilisateur qui le lance (root ou capacités déjà
  accordées au binaire système `tshark`/`dumpcap`, pas un helper propre au
  projet). Cohérent avec `Architecture: all` dans
  `build-deb/debian/control` (vérifié) : aucun binaire compilé spécifique
  à netcross.

---

## 6. Internationalisation (gettext)

**S'applique en principe (CLI + GUI avec libellés utilisateur), n'est pas
implémentée.** Aucun `import gettext`, aucun appel `_("...")`, aucun
répertoire `locale/`, aucun fichier `.po`/`.pot` dans tout le dépôt
(vérifié : `grep -rln "gettext\|_(\"" src/` → aucun résultat ;
`find . -iname "*.po" -o -iname "*.pot" -o -iname "locale"` → aucun
résultat). Tous les libellés (aide CLI `argparse`, labels GTK, messages
imprimés) sont en français en dur, sans mécanisme d'extraction/traduction.
**Non documenté** comme choix délibéré — aucune mention du sujet dans
`README.md`/`FEATURES.md`/`claude.md` (vérifié par grep sur les 3
fichiers, aucun résultat). Ce n'est donc pas une décision tranchée par
écrit quelque part (à la différence, par exemple, du choix documenté de ne
pas traiter le `.rpm` Rocky faute d'environnement) : c'est une absence
jamais discutée.

---

## 7. Tests

### `gi.require_version()` sans filet bloque toute la collecte pytest

**Le risque décrit ne se matérialise pas ici, par contournement complet
du problème plutôt que par un garde-fou.** Aucun fichier de `tests/`
n'importe `netcross_gtk4` ni `gi` (vérifié :
`grep -rln "gtk4\|Gtk\|PyGObject" tests/` → aucun résultat). La suite
pytest ne couvre donc **jamais** `netcross_gtk4/app.py`, contrairement au
squelette qui teste réellement son code GTK4 via un garde `require_gtk4()`
dans `conftest.py`. netcross n'a pas d'équivalent — ni la fonction de garde,
ni une seule ligne de test sur `app.py`.
**Documenté explicitement comme choix assumé** : docstring de
`tests/conftest.py` (« Aucun test de ce dépôt ne dépend de tshark, scapy ou
GTK4... »). C'est donc un choix de périmètre documenté, mais **plus
restrictif** que celui du squelette : le squelette teste son GTK4 (via
Xvfb réel), netcross ne le teste pas du tout.

### Suite pytest hermétique, validation réelle documentée à part

**S'applique et est partiellement respectée, avec une différence
notable.** La suite pytest est bien hermétique (paquets/couches EK
synthétiques, aucune dépendance à `tshark`/`scapy`/GTK4 pour la tourner —
confirmé par le docstring de `conftest.py` cité ci-dessus et par l'exécution
réelle : `PYTHONPATH=src python3 -m pytest -q` passe sans `tshark`
installé). La **validation réelle documentée à part** existe bien, mais
uniquement côté CLI/moteur d'analyse : chaque session de `claude.md` décrit
des validations de bout en bout avec un vrai `tshark` et de vrais pcap
(ex. Session 33, ce dépôt-ci). **Il n'existe en revanche aucune validation
réelle équivalente pour `netcross_gtk4/app.py`** (aucune mention de `Xvfb`
dans `claude.md`, vérifié par grep — zéro résultat) : contrairement au
squelette qui documente ses vérifications GTK4 sous Xvfb comme complément
à la suite hermétique, netcross ne semble jamais avoir vérifié son
interface graphique autrement que par lecture de code et
`python -m compileall` (voir `FEATURES.md` ligne ~1024 : « GTK4 lui-même
n'étant pas disponible dans l'environnement où cette vérification a été
faite, un test d'interface réel n'a pas pu être rejoué »).
**Documenté** (le principe hermétique dans `conftest.py`, la limite GTK4
dans `FEATURES.md`), mais la validation réelle GTK4 promise par le motif du
squelette n'a, à ma connaissance d'après ces fichiers, jamais eu lieu ici.

### Fakes conçus pour échouer bruyamment sur un appel illégal

**Non applicable** — netcross n'a pas de module `credentials.py`/
équivalent, donc pas de backend à bouchonner de cette façon. Aucun
`Fake*` de ce type trouvé dans `tests/` (cohérent avec la section 5,
entièrement non applicable).

### Isolation `sys.modules` lors du mock de `gi`

**Non applicable** — aucun test de netcross ne mock `gi`/`gi.repository`
(cohérent avec l'absence totale de test GTK4, voir plus haut).

### Piège de capture d'écran sous Xvfb sans gestionnaire de fenêtres

**Non applicable** — aucun test de capture d'écran dans ce dépôt (même
statut que dans `PATTERNS.md`, où cette règle est déjà notée « non
applicable » côté squelette).

---

## 8. Packaging

**S'applique et est largement implémentée**, avec une différence de
maturité (netcross a un vrai produit packagé, pas un squelette générique) :

- **Source unique, 3 méthodes de build** : confirmé.
  `install.sh` (générique, détecte la distro via `/etc/os-release`),
  `build-deb/` (`.deb`), `build-rpm/` (`.rpm`). Vérifié concrètement que
  `build-deb/build.sh` ne duplique pas le code : il fait
  `cp -r "$REPO_ROOT/src" "$BUILD_DIR/src"` **au moment du build** dans un
  répertoire temporaire, exactement le principe décrit par `PATTERNS.md`
  (« lisent `src/` au moment du build plutôt que de dupliquer »).
- **`Architecture: all`/`noarch`** : confirmé cohérent (`Architecture: all`
  dans `build-deb/debian/control`), et c'est un choix correct ici — netcross
  n'a, contrairement au cas extrême décrit en section 5 de `PATTERNS.md`,
  **aucun binaire C compilé** à isoler (pas d'équivalent
  `switch-capture-taphelper`).
- **GUI en dépendance recommandée, jamais obligatoire** : confirmé
  explicitement — `build-deb/debian/control` : `Depends:` ne liste que les
  paquets CLI (`python3`, `tshark`, `python3-cryptography`,
  `python3-reportlab`, `python3-matplotlib`, `python3-networkx`) ;
  `Recommends: python3-gi, gir1.2-gtk-4.0` porte GTK4 séparément. Cohérent
  avec `install.sh --cli-only` qui installe explicitement sans GTK4.
**Documenté** : `README.md` (section installation), commentaires en tête de
`build-deb/build.sh`, et de nombreuses sessions de `claude.md`/`FEATURES.md`
sur le packaging (`.rpm` Rocky, FIXME de licence, etc., déjà discutés dans
la mémoire de conversation de ce projet).

---

## 9. Pratique de journalisation de session (méta)

**S'applique et est implémentée à l'identique, voire de façon plus
poussée.** netcross tient `claude.md` exactement sur le même principe que
`switch-capture` : un journal chronologique de sessions datées/numérotées
(33 sessions à ce jour), documentant systématiquement demande initiale,
décision de conception, ce qui a été livré, **validation** (avec la même
discipline « vérifié réellement, pas seulement écrit » — voir par exemple
la Session 33 de ce dépôt, qui inclut une validation de bout en bout avec
un vrai `tshark` et de vrais pcap `scapy`), et ce qui reste ouvert.
netcross va même plus loin que le squelette sur un point : `FEATURES.md`
sert de second document de suivi complémentaire (état fonctionnel module
par module, dette identifiée, priorisation), en plus de `claude.md` — le
squelette n'a qu'un seul fichier de ce type.
**Documenté par construction** : c'est `claude.md`/`FEATURES.md`
eux-mêmes.

---

## 10. Traçabilité systématique des fonctions (entrée/sortie)

**S'applique en principe à tout projet Python, n'est pas implémentée.**
Aucun décorateur de tracing, aucun usage de `loguru` ni du module
`logging` de la stdlib nulle part dans `src/` (vérifié :
`grep -rln "loguru\|logger\.\|logging\." src/` → aucun résultat). netcross
utilise exclusivement `print()` vers stdout/stderr, y compris pour ce qui
relèverait d'un log applicatif (progression de capture, erreurs de
thread...) — cohérent avec le fait que la sortie texte EST le produit
principal d'un outil CLI d'analyse (contrairement à `switch-capture`, où le
tracing sert un besoin de diagnostic distinct de la sortie utilisateur),
mais cette distinction n'est **nulle part explicitée** dans les fichiers de
suivi.
**Non implémenté et non documenté** — aucune mention de `logging`/
`loguru`/tracing dans `README.md`/`FEATURES.md`/`claude.md` (vérifié par
grep sur les 3 fichiers, aucun résultat), donc pas même une justification
écrite du choix `print()` par rapport à un framework de logs.

---

## 11. Absence de dépendances circulaires entre modules

**S'applique et est implémentée, par un mécanisme différent mais
équivalent en rigueur.** Là où `project-skeleton` détecte les cycles via
un test `pytest` dédié qui construit le graphe par analyse `ast` et le
valide par un parcours en profondeur (`tests/test_no_cross_imports.py`),
netcross utilise l'outil tiers **`import-linter`**, avec un contrat
`layers` explicite dans `pyproject.toml` (`netcross_gtk4 → netcross_report
→ netcross_core → pcap_parser`), exécuté à la fois manuellement
(`lint-imports`) et via le hook `pre-commit` local (`.pre-commit-config.yaml`,
hook `import-linter`). Vérifié en exécutant réellement
`PYTHONPATH=src lint-imports` sur ce dépôt : « Analyzed 60 files, 150
dependencies... Pas de cycles internes KEPT... Contracts: 1 kept, 0
broken. » Le résultat recherché (graphe acyclique, vérifié automatiquement,
pas seulement par discipline manuelle) est donc bien atteint, mais via un
outil externe dédié plutôt qu'un test `ast` maison — netcross n'a pas
besoin de réinventer ce détecteur puisqu'un outil mature (`import-linter`)
fait déjà le travail, et le fait de façon arguably plus robuste (contrat
déclaratif versionné, pas une heuristique maison à maintenir).
**Documenté** : `FEATURES.md` section 1 (tableau, ligne `import-linter`),
`pyproject.toml` (`[tool.importlinter]`), `.pre-commit-config.yaml`, et
mentionné dans la quasi-totalité des sessions de `FEATURES.md`/`claude.md`
(ex. Session 33 : « import-linter sans cycle (60 fichiers, 150
dépendances)... »).

---

## 12. Tests automatisés sur chaque changement

**S'applique, n'est PAS implémentée telle que décrite.** `PATTERNS.md`
décrit un hook `pre-commit` qui fait tourner **`pytest`** à chaque commit.
Le `.pre-commit-config.yaml` de netcross contient exactement **3 hooks** :
`ruff --fix`, `ruff-format`, `import-linter` — **`pytest` n'y figure pas**
(vérifié par lecture directe du fichier). La suite `pytest` complète
(639 tests à ce jour) est bien rejouée à **chaque session** de
développement, avec la même rigueur documentée que le squelette (« vérifié
réellement, pas juste écrit »), mais **manuellement/par discipline de
session**, jamais automatiquement via un hook Git qui bloquerait un commit
en cas d'échec.
**Documenté sans ambiguïté comme tel** : `FEATURES.md` ligne 32 et
`README.md` ligne 619 énoncent explicitement « 3 hooks : `ruff --fix`,
`ruff-format`, `import-linter` » — la composition exacte du hook est
publique et cohérente partout, donc ce n'est pas un oubli caché, mais la
règle précise de `PATTERNS.md` (tests inclus dans le hook) n'est
effectivement pas suivie ici, et aucune justification écrite n'explique
pourquoi (temps d'exécution, dépendance à `tshark`/`scapy` pas toujours
disponibles localement — hypothèse plausible vu les sessions qui doivent
réinstaller ces outils à chaque fois, mais jamais formulée comme raison
explicite dans les fichiers de suivi).

---

## Récapitulatif

### Implémenté et documenté (dans les fichiers de suivi du projet)

- Séparation core / cli / gtk, imposée par contrat `import-linter`
  (`FEATURES.md` section 1 ; `pyproject.toml`).
- GUI en plusieurs pages navigables (`Gtk.Stack`/`Gtk.StackSwitcher`,
  3 pages) — `FEATURES.md` ligne 1015.
- Ctrl+C (SIGINT) propre côté CLI, avec `threading.Event` coopératif —
  `FEATURES.md` section 4 point 10 ; `claude.md` (plusieurs sessions).
- Packaging : source unique + 3 méthodes de build, `Architecture: all`
  cohérent, GTK4 en `Recommends` jamais `Depends` — `README.md`,
  `build-deb/build.sh`, `build-deb/debian/control`.
- Pratique de journalisation de session (`claude.md`/`FEATURES.md`
  eux-mêmes).
- Absence de dépendances circulaires, vérifiée par `import-linter`
  (mécanisme différent du squelette, rigueur équivalente) —
  `FEATURES.md` section 1 ; `pyproject.toml` ; `.pre-commit-config.yaml`.

### Implémenté mais non documenté (dans les fichiers de suivi)

- Scrollbars classiques sans overlay (`_visible_scroller`) — documenté
  seulement dans le docstring de `netcross_gtk4/app.py`, absent de
  `FEATURES.md`/`claude.md`/`README.md`.
- Thread neuf à chaque phase plutôt qu'un objet `Thread` réutilisé
  (principe respecté, idiome différent de `BackgroundJob`) — visible
  uniquement dans le code (`app.py`).
- Champs conditionnels (visibilité TLS/QUIC selon le mode) — câblés au
  cas par cas, mentionnés dans `FEATURES.md` comme fonctionnalité mais
  pas comme motif d'architecture nommé.

### Non implémenté (documenté comme tel, choix ou limite explicite)

- Tests GTK4 absents de la suite pytest — documenté explicitement dans
  `tests/conftest.py`.
- Validation réelle de `netcross_gtk4/app.py` jamais rejouée (GTK4
  indisponible dans l'environnement de vérification) — documenté dans
  `FEATURES.md` (section `netcross_gtk4.app`).
- `pytest` absent du hook `pre-commit` (3 hooks seulement, composition
  publique et cohérente partout) — documenté dans `FEATURES.md`/
  `README.md`, sans toutefois que la raison de l'exclusion soit
  explicitée.

### Non implémenté et non documenté

- Ctrl+C (SIGINT) propre côté GTK4 (`GLib.unix_signal_add`) — absent du
  code, jamais mentionné.
- Menu hamburger + page Préférences, préférences persistantes — absents,
  jamais mentionnés.
- Icône de l'application (constante `APP_ID` partagée, fichier
  `.desktop`, répertoire `icons/`) — absent, jamais mentionné.
- Diagnostic sudo + GUI + RDP (et le bug connexe `do_activate` qui avale
  les exceptions) — absent, jamais mentionné.
- Contournement GVFS/GOA (ou équivalent pour `Gtk.FileDialog`) — absent,
  jamais mentionné.
- Internationalisation (gettext) — absente, jamais mentionnée comme sujet
  du tout.
- Traçabilité systématique entrée/sortie des fonctions (décorateur de
  tracing, `loguru`/`logging`) — absente ; le choix `print()` plutôt
  qu'un framework de logs n'est justifié nulle part par écrit.

### Non applicable (différence d'architecture/de portée assumée)

- Un seul exécutable à bascule CLI/GTK — netcross a 4 points d'entrée
  spécialisés, un choix cohérent avec 3 usages CLI distincts.
- Toute la section 5 (Secrets) — netcross ne gère aucun accès à un système
  distant nécessitant une authentification (contrairement à
  `switch-capture`, qui SSH vers des équipements HPE Comware) ; les seules
  occurrences de « secret » dans le code concernent la cryptographie QUIC
  (RFC 9001), sans rapport.
- Confirmation avant action destructrice, journalisation d'audit de
  commandes sortantes, principe du moindre privilège via binaire `setcap` —
  netcross n'a aucune action destructrice ni aucun accès privilégié de ce
  type dans son périmètre.
- Fakes échouant bruyamment sur un backend de secrets, isolation
  `sys.modules` lors d'un mock de `gi` — sans objet, faute respectivement
  de module de secrets et de tout test mockant `gi`.
- Piège de capture d'écran Xvfb sans gestionnaire de fenêtres — sans objet,
  netcross n'a aucun test de capture d'écran (déjà noté « non applicable »
  côté squelette lui-même).
