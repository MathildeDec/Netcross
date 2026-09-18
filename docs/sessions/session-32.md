# Session 32 — Preuves attachées aux constats (première brique de la "Session 0", `EvidenceLink`)

### Demande initiale

"Continue les features à faire de la comparaison avec omnipeek. Fait
évoluer les fichiers de suivi, de tests et de documentation. Tu livres
juste après le `netcross{YYYYMMDD-HHMMSS}.zip` sans passer à la suite" —
même consigne que les Sessions 8 à 31.

### Contrainte d'environnement de cette session

`tshark` n'était **pas** préinstallé dans ce conteneur (à la différence
de ce que la Session 31 rapportait pour le sien) : `apt-get install
tshark` nécessaire en tout début de session, a réussi (`tshark 4.2.2`,
même version que d'habitude). `pip install -r requirements.txt
-r requirements-dev.txt scapy` également nécessaire (aucun des deux
préinstallé). Bonne nouvelle méthodologique : ceci confirme que
l'environnement d'exécution varie d'une session à l'autre malgré la
stabilité apparente des versions obtenues une fois installées — vérifier
systématiquement plutôt que supposer, comme déjà pratiqué mais
utile à re-noter ici.

### Choix de la feature suivante

La Session 31 concluait qu'il ne restait plus aucun candidat de code
substantiel en section 5.2 de `FEATURES.md`, et renvoyait vers les
chantiers plus larges de la section 6 (comparaison OmniPeek/Wireshark).
La section 13.3 y recommande d'entrer par la **Session 0 — contrats et
architecture d'intégration** (priorité maximale, explicitement posée
comme préalable à tout le reste) : neuf objets communs à stabiliser
(`PacketEvidence`, `Flow`, `Conversation`, `ExpertEvent`, `Finding`,
`Diagnosis`, `Reference`, `ComplianceResult`, `EvidenceLink`) avant de
bâtir le moteur d'expertise visé par la section 6.

Construire les neuf d'un coup dépasserait largement le format d'une
session, et plusieurs (`PacketEvidence` en tête) supposent une donnée
source qui n'existe pas encore : les champs `*_examples` actuels de
`Report` (`netcross_core/models.py`) sont déjà de simples chaînes mises
en forme au moment de la collecte, plafonnées à 5 par clé -- pas des
références vers un paquet précis (index/offset/pcap). Retenu pour cette
passe : un seul objet, `EvidenceLink`, et son câblage réel de bout en
bout sur tout ce qui pouvait déjà l'être sans nouvelle collecte de
données -- plutôt qu'une esquisse des neuf objets sans aucun
consommateur, qui n'aurait rien apporté de mesurable. Choix explicite de
continuer le style des Sessions 8-31 (une fonctionnalité au périmètre
serré, entièrement câblée et testée) plutôt que de traiter la Session 0
comme un exercice d'architecture isolé de tout usage concret.

Point de départ concret identifié en lisant le code (pas seulement
`FEATURES.md`) : plusieurs champs `Report` collectent déjà des chaînes
d'exemple concrètes par catégorie de constat (PMTUD, NAT/pare-feu, ARP,
STP, TLS x2, MSS clamped, HTTP), ou portent eux-mêmes la preuve sous
forme de liste (DNS/HTTP timeout et messages manquants, DHCP/SIP
messages manquants) -- mais seul `netcross_core/report_text.py` (le
texte humain par catégorie) les affichait. `Finding`
(`netcross_report/synthesis.py`), donc JSON/GUI/triage/PDF, n'en voyait
jamais rien : la preuve existait déjà, elle n'était simplement pas
accessible depuis le même objet que le constat qu'elle justifie.

### Décisions de conception assumées

- **Placement de `EvidenceLink` dans `netcross_core` (et non
  `netcross_report`, qui héberge `Finding`)** : pour rester disponible à
  `netcross_core.baseline_diff` (`DiffFinding`) le jour où ses propres
  constats gagneront la même preuve -- l'inverse casserait la couche
  imposée par `import-linter` (`netcross_report` → `netcross_core`,
  jamais l'inverse, voir `pyproject.toml`).
- **`sip_failed_calls` non câblé délibérément** : le message du finding
  EST déjà la preuve (un appel échoué = une ligne), l'attacher aussi en
  `evidence` serait un pur doublon -- même raisonnement documenté dans
  ce fichier pour l'absence de `sample_size` sur un compteur brut.
- **`http_error_examples` mélange 4xx et 5xx à la collecte** (un seul
  champ, alimenté quel que soit le statut ≥ 400) alors que les deux
  compteurs (`http_client_error_count`/`http_server_error_count`) et
  donc les deux `Finding` restent séparés. Plutôt que de dupliquer la
  collecte côté `analysis.py` pour deux listes distinctes, nouveau
  helper `_http_error_evidence(examples, status_class)` dans
  `synthesis.py` qui filtre sur le suffixe `-> NNN` de chaque exemple --
  vérifié explicitement par un test qu'un exemple 404 ne se retrouve
  jamais attaché au constat 5xx et inversement.
- **`stp_topology_change` reste sans evidence** : `Report` ne collecte
  d'exemples que pour `stp_root_change` (asymétrie déjà présente dans le
  code, pas une omission de cette session) -- couvert par un test dédié
  qui verrouille ce comportement plutôt que de le laisser comme un trou
  silencieux.
- **`DiffFinding` non touché** : une comparaison avant/après n'a pas la
  même relation 1:1 à un exemple brut qu'un constat simple (faudrait
  déjà décider si l'evidence viendrait du rapport "avant", "après", ou
  les deux) -- décision de conception à part entière, pas un simple
  câblage, remise à une session dédiée.

### Ce qui a été livré

- `netcross_core/expert_model.py` (nouveau fichier) : `EvidenceLink`
  (`point`, `text`) -- premier des neuf objets de contrat visés par la
  Session 0, docstring de module explicite sur ce qui reste à faire et
  pourquoi (les huit autres objets, et ce qui leur manque comme donnée
  source).
- `netcross_report/synthesis.py` : `Finding.evidence:
  list[EvidenceLink] = field(default_factory=list)` (rétrocompatible,
  défaut `[]`). Nouveaux helpers `_evidence(point, texts)` et
  `_http_error_evidence(examples, status_class)`. Câblé sur 13
  catégories de constats déjà existantes : PMTUD, NAT/Pare-feu, ARP,
  STP (`stp_root_change` seulement), TLS dates invalides, TLS mismatch,
  TCP MSS clamped, DHCP messages manquants, SIP messages manquants, DNS
  timeout, DNS messages manquants, HTTP 4xx, HTTP 5xx, HTTP timeout,
  HTTP messages manquants.
- `netcross_report/json_report.py` : `_finding_dict` expose `evidence`
  (liste de `{"point", "text"}`) quand elle est non vide -- même
  convention que `before`/`after`/`sample_size` (clé absente sinon,
  lecture `getattr` défensive pour rester duck-type avec `DiffFinding`).
- `netcross_report/triage.py` : `print_triage` affiche les lignes de
  preuve indentées sous chaque finding qui en porte (même prudence
  `getattr(f, "evidence", None) or ()` que pour `sample_size`) --
  matérialise concrètement le principe n°8 de `FEATURES.md` section 10
  ("la présentation doit toujours permettre de redescendre du verdict
  vers la preuve").
- `README.md` : mention d'`evidence` dans les descriptions de
  `--triage` et `--json-report`, décompte de tests mis à jour (622).
- `FEATURES.md` : nouvelle entrée en tête de section 4 ("Session 32"),
  note de progression ajoutée sous la description de la "Session 0" en
  section 13.3.

### Validation

596/596 tests hérités rejoués **avant** tout nouveau code, confirmant
l'absence de régression préalable.

26 nouveaux tests, tous `pytest` réels sur des `Report` construits à la
main (même méthode que le reste de la suite, voir `tests/conftest.py`) :
`test_expert_model.py` (2, forme du contrat -- champs et égalité par
valeur) ; `test_synthesis.py` (18, une catégorie par test, y compris les
deux cas négatifs documentés ci-dessus -- `stp_topology_change` et
`sip_failed_calls` -- et le filtrage 4xx/5xx) ; `test_json_report.py`
(3, présence/absence de la clé JSON, et confirmation que `DiffFinding`
n'en expose pas) ; `test_triage.py` (3, affichage réel des lignes de
preuve via `capsys`, absence de régression sur un namedtuple sans champ
`evidence`) -- **622/622** au total.

Validation de bout en bout sur une **vraie capture**, au-delà des tests
synthétiques ci-dessus : petit serveur `http.server` Python sur
`127.0.0.1:8080`, capturé avec le vrai `tshark -i lo -a duration:6`
pendant qu'un `curl` réel interroge une route inexistante (404), rejoué
avec le vrai `cross_capture_analyzer_cli.py --json-report --triage`. Le
JSON produit contient bien
`"evidence": [{"point": "A", "text": "GET http://127.0.0.1:8080/
notfound-page -> 404"}]` sur le constat HTTP 4xx correspondant --
confirmant que la chaîne complète (tshark réel → `Report` → `Finding` →
JSON) fonctionne, pas seulement le câblage unitaire. Vérifié séparément,
sur un scénario PMTUD synthétique en `severity="anomalie"`, que
`print_triage` affiche bien la ligne de preuve indentée sous le constat
classé -- un 4xx étant en `severity="info"`, il n'est jamais retenu par
`rank_segments`, ce qui explique que la capture HTTP réelle ci-dessus ne
remonte pas dans le triage textuel bien que son JSON porte la preuve.

`ruff check`/`ruff format --check` propres, `import-linter` sans cycle
(60 fichiers, 149 dépendances contre 59/146 en Session 31 -- un fichier
et quelques dépendances de plus, cohérent avec l'ajout d'un seul
module).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : nouvelle entrée en tête de section 4 ("Session
  32", avec sous-sections "Ce qui a été livré"/"Validation"/"Non traité
  dans cette passe") ; note de progression sous la "Session 0" en
  section 13.3.
- **`claude.md`** (ce fichier) : cette section, ajoutée en fin de
  fichier (ordre non strictement chronologique depuis la Session 26,
  déjà noté dans les sessions précédentes).
- **`README.md`** : mentions d'`evidence` sous `--triage` et
  `--json-report`, décompte de tests mis à jour (622).

### Non traité dans cette passe

- Les huit autres objets de la "Session 0" (`PacketEvidence`, `Flow`,
  `Conversation`, `ExpertEvent`, `Finding` enrichi au sens plein du
  terme, `Diagnosis`, `Reference`, `ComplianceResult`) -- voir la
  docstring de `expert_model.py` pour ce qui bloque chacun.
- `DiffFinding` (`netcross_core/baseline_diff.py`) sans `evidence` --
  décision de conception à part entière (voir ci-dessus), pas un simple
  câblage.
- `encap_change_examples` existe dans `Report` mais n'a pas de `Finding`
  dédié (seule sa corrélation avec `frag_new` est utilisée aujourd'hui) :
  rien à câbler sans créer une nouvelle catégorie de constat, hors
  périmètre de cette passe.
- Pas de rendu PDF/GUI des preuves -- conforme au principe même de la
  Session 0 (section 13.6 : "la GUI et le PDF ne doivent pas être des
  prérequis du moteur analytique"), CLI/JSON suffisent pour valider le
  contrat.
- La suite des Sessions 1 à 11 de la section 13.3 (exploitation
  Wireshark/TShark avancée, moteur de règles, corrélation événement →
  flux → paquet, référentiels/SLO, etc.) reste entièrement à faire --
  cette passe ne fait que poser la première pierre explicitement
  identifiée comme préalable en section 13.3.

