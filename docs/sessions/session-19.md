# Session 19 — gestion mémoire des grosses captures

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 18.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark`, `pytest` et un accès réseau
étaient **tous les trois disponibles simultanément** (`apt-get install
tshark` et `pip install pytest ruff import-linter pre-commit reportlab
matplotlib networkx pypdf Pillow scapy cryptography pdf2image` ont tous
réussi) — situation identique aux Sessions 9/10/11/14/17/18, différente
de la majorité des sessions précédentes.

### Choix de la feature suivante

`FEATURES.md` section 5.2, 🟠 urgence moyenne : deux candidats
restaient après la Session 18 — validation CAPWAP sur vraie capture
(nécessite du vrai trafic vendeur Aruba/Cisco/Fortinet, absent de cet
environnement quel que soit l'outillage disponible) et gestion mémoire
des grosses captures (nécessite un vrai `tshark` pour profiler le
pipeline réel — disponible cette session, contrairement à la majorité
des précédentes). Seule la seconde était réalisable ici, retenue sans
ambiguïté — même raisonnement "par élimination" que les Sessions 13/15
en leur temps.

### Démarche : mesurer avant de coder

Même discipline que PMTUD/retransmissions/options TCP (Sessions 9-11) :
avant d'écrire une ligne de correctif, une capture synthétique de
200 000 paquets TCP (`scapy`) a été décodée par le vrai `tshark -T ek`
et profilée avec `tracemalloc` (bibliothèque standard). Résultat de
référence : **~1971 octets par paquet** en régime établi
(`RawPacket`/`Pkt`), et un pic mémoire transitoire pendant la conversion
`RawPacket → Pkt` de 722 Mo pour 200 000 paquets — supérieur à la seule
liste `RawPacket` (394 Mo), confirmant que les deux listes complètes
étaient gardées en mémoire simultanément par la compréhension de liste
de `netcross_core.parsing.parse_capture()`.

Cause isolée en reconstruisant la dataclass `RawPacket` à l'identique,
en dehors de tout code tshark, avec puis sans `__slots__` : le
`__dict__` par instance (présent par défaut sur toute dataclass sans
`__slots__`) représente à lui seul environ les deux tiers du coût par
paquet (1696 → 528 octets/objet, mêmes ~55 champs). Le tiers restant :
chaque ligne NDJSON `tshark -T ek` est décodée indépendamment par
`json.loads()` — deux paquets qui portent la même valeur textuelle (même
IP, même User-Agent SIP, même URI HTTP...) obtiennent chacun leur propre
objet `str`, vérifié empiriquement (`json.loads('{"v": "10.0.0.1"}')`
appelé deux fois ne renvoie jamais le même objet — piège rencontré en
écrivant le premier jet du test d'interning, qui utilisait une
concaténation de littéraux que CPython replie à la compilation en un
seul objet partagé, masquant le comportement réel).

### Ce qui a été livré

Voir `FEATURES.md` section 2 (`pcap_parser`/`netcross_core.parsing`) et
section 4 (nouvelle sous-section "Gestion mémoire des grosses captures —
Session 19") pour le détail technique complet. En résumé :

- `RawPacket` (`pcap_parser/packet.py`) et `Pkt`
  (`netcross_core/models.py`) déclarent `__slots__` — possible sans
  conflit car aucun champ n'a de valeur par défaut dans les deux
  dataclasses (vérifié avant d'appliquer le changement).
- Nouveau helper `packet._intern()` (tolérant à `None`) appliqué aux
  champs catégoriels à forte duplication attendue (`src`/`dst`, `flags`
  TCP, `dhcp_msg_type`/`server_id`/`vendor_class`, `sip_msg_type`/
  `user_agent`/`server`, `dns_qry_name`, `http_method`/`http_uri`) —
  volontairement pas appliqué à `sip_call_id`/`sip_cseq`/`payload_hash`
  (généralement uniques, aucun gain attendu) ni à `encap_tags` (cas
  secondaire, rendement décroissant).
- `netcross_core/parsing.py::parse_capture()` : conversion
  `RawPacket → Pkt` désormais incrémentale (`raw_packets[i] = None`
  après chaque conversion) au lieu d'une compréhension de liste qui
  gardait les deux listes entièrement matérialisées simultanément.

### Validation

Suite `pytest` complète rejouée avant tout nouveau code (411/411
hérités de la Session 18, aucune régression préalable). 8 nouveaux tests
(`test_packet.py` : absence de `__dict__`/`AttributeError` sur un champ
hors `__slots__`, `_intern()` tolérant à `None`, partage du même objet
`str` entre deux paquets de même IP source/destination une fois passés
par `build_packet()`, cohérence entre les noms de champs de la
dataclass et `__slots__` ; `test_parsing_adapter.py` : mêmes garanties
côté `Pkt`, libération incrémentale de `raw_packets` pendant
`parse_capture()`) — **419/419** au total.

`ruff check`, `ruff format --check`, `PYTHONPATH=src lint-imports` et
`pre-commit run --all-files` réellement exécutés, tout passe.
`ruff --fix` a trié `Pkt.__slots__` par ordre alphabétique (règle
`RUF023`, déjà active dans `pyproject.toml` depuis la Session 7 mais
jamais déclenchée jusqu'ici faute d'un tuple `__slots__` dans le projet)
— appliqué sans discussion, l'ordre du tuple `__slots__` n'a aucun effet
fonctionnel (l'ordre qui compte, celui du `__init__` généré, vient des
annotations de la dataclass, pas de `__slots__`). Deux occurrences
`C416` (compréhension d'ensemble superflue) corrigées à la main dans les
nouveaux tests.

**Validation empirique de bout en bout avec du vrai `tshark`, avant et
après, sur le même scénario** — au-delà de la suite `tests/` (petits
volumes synthétiques par construction) :
- Mémoire par paquet (`tracemalloc`, pipeline réel `pcap_parser.parse_
  capture`/`netcross_core.parsing.parse_capture`, capture 200 000
  paquets) : 1971 → 636 octets/paquet (-68%) ; pic transitoire pendant
  la conversion `RawPacket → Pkt` : 722 → 129 Mo (-82%).
- **Pic RSS réel du process CLI complet**, pas une estimation à partir
  des seuls objets Python : mesuré via `/proc/<pid>/status` (`VmHWM`)
  depuis un thread de supervision pendant l'exécution, sur un scénario
  réaliste à 2 points de capture de 200 000 paquets chacun
  (`cross_capture_analyzer_cli.py --order A,B`, sans `--parallel`).
  Le code de la Session 18 (livré tel quel, re-décompressé depuis
  l'archive reçue en entrée de cette session, sans aucune modification)
  a d'abord été rejoué sur ce scénario pour établir la référence AVANT :
  **1,3 Go**. Rejoué ensuite avec le code de cette session : **~500
  Mo**, soit environ **-61%** sur le pic mémoire réel observé — pas une
  extrapolation depuis les mesures `tracemalloc` ci-dessus, une mesure
  indépendante sur le process complet (import, corrélation, analyse,
  affichage compris).
- Rejeu du **vrai CLI** sur ce même scénario avec
  `--triage --parallel --pdf-report --json-report` : 400 paquets
  manquants détectés côté B (perte intentionnelle de 1 paquet sur 500
  injectée dans la capture synthétique de validation), score de santé
  72/100 "À surveiller", PDF (122 Ko) et JSON générés sans erreur —
  confirme l'absence de régression fonctionnelle sur un volume réaliste.

Piège rencontré en construisant le scénario de validation par perte
(deux fichiers "point A"/"point B") : un premier jet utilisait
`random.choice()` pour assigner une IP source à chaque paquet
séparément dans les deux boucles de génération scapy, avec un `continue`
dans la boucle B qui sautait l'appel `random.choice()` pour les paquets
retirés — décalant la séquence aléatoire entre A et B à partir du
premier paquet retiré, et faisant apparaître un désaccord massif
(98% de "paquets manquants") entre les deux captures alors qu'une seule
perte réelle de 0,2% avait été injectée. Diagnostiqué en relisant le
générateur (pas en doutant du pipeline d'analyse) : corrigé en
pré-calculant la liste des IP assignées une fois pour les 200 000
indices, puis en réutilisant cette même liste (indexée par `i`, pas par
ordre d'appel) pour construire A et B — la perte mesurée par l'outil
correspond alors exactement à la perte injectée (400 paquets sur
200 000, 0,2%).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 (`pcap_parser`, `netcross_core.parsing`)
  — `__slots__`/interning/conversion incrémentale documentés à l'endroit
  des modules concernés ; section 4, nouvelle sous-section "Gestion
  mémoire des grosses captures (Session 19)" avec le détail complet de
  la démarche et de la validation ; section 5.2 — ligne déplacée vers
  "fait", avec les chiffres mesurés en résumé. Ne reste en 🟠 urgence
  moyenne que la validation CAPWAP sur vraie capture vendeur, toujours
  hors d'atteinte sans matériel/trafic réel.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouvelle entrée "Gestion mémoire des grosses
  captures" dans "Limites connues" (chiffres mesurés, extrapolation
  approximative pour de très gros volumes) ; compteur de tests corrigé
  (411 → 419).

### Non traité dans cette passe

- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  candidat 🟠 restant, toujours hors d'atteinte sans matériel/trafic
  vendeur réel, quel que soit l'outillage logiciel disponible.
- **Vrai mode streaming multi-passes** — le pipeline reste entièrement
  en RAM ; réduire le coût par paquet (ce qui a été fait ici) n'élimine
  pas le besoin de garder tous les paquets en mémoire pour la
  corrélation multi-points. Changement d'architecture de
  `correlate()`/`analyse()`, pas un câblage rapide — hors périmètre
  assumé de cette piste depuis son ouverture en Session 1
  (`idées.md` §3), toujours vrai après cette session.
- **`encap_tags`** non interné (tags d'encapsulation construits par
  `f"VLAN{vid}"` etc.) — cas secondaire à rendement décroissant, laissé
  de côté pour rester dans le périmètre "rapide, isolé" de cette
  session.

