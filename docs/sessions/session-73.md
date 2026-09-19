# Session 73 — CaptureRingBuffer (Job 37, issue #157)

**Date :** 19 septembre 2026
**Dépôt :** github.com/MathildeDec/Netcross
**Branche :** job37-capture-ring-buffer (PR vers main)

## Objectif

Implémenter l'issue #157 (Job 37 — « Rotation de capture (ring buffer pour
captures longues) ») : en capture continue (Job 33), le fichier de capture
grandit indéfiniment faute de mécanisme de rotation. Ajouter un ring buffer
qui écrit dans des fichiers de durée fixe, en supprimant automatiquement le
plus ancien au-delà d'un nombre maximal de fichiers.

## Analyse préalable

`RawPacket`/`Pkt` ne portent pas les octets bruts de la trame (le projet ne
dépend plus de scapy depuis le passage à tshark en sous-processus — voir
`requirements.txt`) : il n'existe donc, nulle part dans le pipeline Python,
de quoi ré-sérialiser un `.pcapng` valide à partir des objets déjà
disséqués. Décision d'architecture prise pour cette session : implémenter
`CaptureRingBuffer` comme un **gestionnaire de fichiers pur**, ignorant
volontairement tshark et le contenu des fichiers — il décide QUAND ouvrir
un nouveau fichier et QUELS fichiers garder sur disque, pas comment les
remplir. C'est le choix qui rend les deux tests demandés par l'issue
réellement rapides et déterministes (pas de sous-processus tshark, même
convention que `tests/test_capture.py` : « on monkeypatch iter_ek_records,
jamais tshark lui-même »). L'écriture réelle des paquets (typiquement un
`tshark -w <current_path> -b duration:N -b files:M`, en réutilisant le
paramètre `extra_args` déjà présent dans `ek_source._build_args`) est
laissée à un futur appelant CLI/GUI — hors périmètre du texte de l'issue,
qui ne demande que la classe, son paramétrage, la suppression automatique,
l'intégration à `LiveDiffEngine` et l'option GUI.

## Implémentation

### `src/pcap_parser/capture.py` — `CaptureRingBuffer`

- `__init__(directory, prefix="capture", max_files=10, max_duration_per_file=60.0, extension=".pcapng")`
  — valide `max_files >= 1` et `max_duration_per_file > 0` (`ValueError`
  sinon).
- `rotate(now=None) -> str` — crée immédiatement un nouveau fichier
  (`touch`), le rend courant, purge le plus ancien si `max_files` est
  dépassé (suppression réelle sur disque, `contextlib.suppress
  (FileNotFoundError)` en défense).
- `maybe_rotate(now=None) -> str | None` — ne tourne que si
  `max_duration_per_file` secondes se sont écoulées depuis la dernière
  rotation (ou si aucune rotation n'a encore eu lieu) ; pensée pour être
  appelée à chaque paquet/tick d'une boucle déjà existante sans jamais la
  ralentir.
- `current_path` / `files` — introspection (GUI, tests).

Exportée dans `src/pcap_parser/__init__.py` (`__all__` + docstring couche
`capture`).

### `src/netcross_core/live_diff.py` — intégration `LiveDiffEngine`

Nouveau paramètre optionnel `ring_buffer: CaptureRingBuffer | None = None`
(défaut `None`, comportement inchangé sans lui). `_add_packet()` appelle
`self.ring_buffer.maybe_rotate(pkt.ts)` après la mise à jour de la fenêtre
glissante — même convention « temps de capture, pas temps réel » que le
reste de la méthode. Import `pcap_parser.capture.CaptureRingBuffer` en tête
de fichier (sens autorisé par le contrat de couches : `netcross_core` →
`pcap_parser`, déjà utilisé par `parsing.py`/`tls_diagnostics.py`/
`quic_diagnostics.py`).

### `src/netcross_gtk4/app.py` — page Configuration

Nouveau bloc `self.ring_buffer_box` (case à cocher « Rotation de capture
(ring buffer) » + 2 `Gtk.SpinButton` fichiers max/durée max par fichier),
inséré juste après `live_extra_box` et suivant exactement le même
principe de visibilité : masqué hors mode capture live
(`_sync_panel_visibility`), les 2 `SpinButton` inactifs tant que la case
n'est pas cochée (`_on_ring_buffer_toggled`, même schéma que
`_on_redact_toggled`). Purement une option de configuration à ce stade :
ni la capture live de cette page ni `LiveDiffEngine` ne s'appellent l'un
l'autre aujourd'hui (`LiveDiffEngine` reste « sans dépendance GUI/CLI »,
comme documenté dans son propre module) — câbler réellement un
`CaptureRingBuffer` depuis cette page est laissé à une session qui
raccorderait les deux, hors périmètre du texte de l'issue #157.

Validation manuelle (ce dépôt n'a pas de suite de tests GTK4 automatisée,
voir `tests/conftest.py`) : `gir1.2-gtk-4.0` installé dans ce
bac à sable + smoke test headless sous Xvfb — construction de
`MainWindow`, présence des 3 nouveaux attributs, visibilité du bloc liée
au mode live, sensibilité des `SpinButton` liée à la case à cocher. Script
non versionné (outil de vérification ponctuel, pas un test du dépôt).

## Tests

- `tests/test_capture.py` (+8) : paramètres invalides (`max_files=0`,
  `max_duration_per_file=0`) ; `current_path`/`files` avant la première
  rotation ; une rotation simple crée bien le fichier et le rend courant ;
  **rotation avec de petits fichiers + comptage** (critère de test explicite
  de l'issue) ; **suppression du plus ancien fichier, vérifiée sur disque**
  (second critère explicite) ; `maybe_rotate` avant la durée max (no-op) ;
  `maybe_rotate` à la durée max exacte (tourne) ; première rotation
  automatique via `maybe_rotate` seul.
- `tests/test_live_diff.py` (+2) : `_add_packet` sans `ring_buffer` ne fait
  rien de spécial (contrôle négatif) ; rotations successives pilotées par
  `pkt.ts` sur plusieurs `_add_packet`, avec purge du plus ancien fichier
  une fois `max_files` dépassé.

`pytest` (`PYTHONPATH=src`) : **1606/1608 → 1616/1618** (+10 nets, sans
compter les 5 tests GTK4 par ailleurs sujets à skip qui passent aussi dans
ce bac à sable une fois `gir1.2-gtk-4.0` installé pour la validation
manuelle ci-dessus — observé ici : 1621/1623, 0 skip).

## Qualité

- `ruff check .` / `ruff format --check .` : verts.
- `PYTHONPATH=src lint-imports` : contrat de couches respecté (1 kept, 0
  broken) — `CaptureRingBuffer` vit dans `pcap_parser`, importée par
  `netcross_core.live_diff` (sens autorisé, aucun nouvel import
  inter-packages illégal).
- `mypy --ignore-missing-imports` sur les 4 fichiers modifiés : 0 erreur
  imputable.

## Observations annexes (hors périmètre de l'issue #157, non corrigées ici)

1. **2 échecs de test préexistants sur `main`**, dans
   `tests/test_live_diff.py` :
   `test_evaluate_diff_produces_findings_and_raises_alarm` et
   `test_evaluate_diff_sans_divergence_ne_leve_aucune_alarme`.
   `monkeypatch.setattr("netcross_core.correlate.correlate", ...)` échoue
   (`AttributeError: 'function' object has no attribute 'correlate'`) car
   `netcross_core.correlate` résout vers la FONCTION `correlate`
   (réexportée quelque part dans `netcross_core`), pas vers le sous-module
   du même nom — la chaîne `monkeypatch.setattr` à 3 segments interprète le
   dernier segment comme un attribut à poser sur ce qui précède, qui n'est
   pas un module ici. Semble dater du lot de tests Job 33 (PR #173,
   `job33-live-diff-tests`). Ni introduit ni corrigé par cette session ;
   signalé pour une session dédiée (probable correctif : cibler
   `netcross_core.analysis.correlate` ou passer par `monkeypatch.setattr`
   sur le module importé directement plutôt que par chemin de chaîne).
2. **6 erreurs mypy préexistantes**, sur 3 fichiers jamais touchés par
   cette session : `netcross_core/application/http.py` (x3),
   `netcross_core/application/dns.py` (x2), `netcross_core/analysis.py`
   (x1) — `PYTHONPATH=src mypy --ignore-missing-imports src/` (75 fichiers
   source désormais, contre 36 lors du grand nettoyage de la Session 71).
   Le `Success: no issues found in 36 source files` annoncé par la Session
   71 est donc devenu stale entre-temps (la Session 72 en avait déjà
   corrigé 7 réapparues sur d'autres fichiers — celles-ci sont
   différentes). Aucune n'est imputable à ce chantier.
