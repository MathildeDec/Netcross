# Session 28 — anonymisation des adresses (`--redact`)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 27.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `tshark` (4.2.2), `pytest`/`ruff`/
`import-linter`, `scapy` et un accès réseau étaient **tous disponibles
simultanément** — même situation que les Sessions 9/10/11/14/17/18/19/
20/21/22/24/25/26/27. `editcap`/`mergecap` installés au passage avec le
paquet `tshark`. `reportlab`/`matplotlib`/`networkx` (pour
`--pdf-report`) et `cryptography` (pour `--quic`) installés en plus,
ainsi que `pdftotext` (`poppler-utils`) pour relire le PDF généré.
Suite `pytest` rejouée avant toute modification : 554/554 verts (aucune
régression héritée de la Session 27).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : le seul candidat 🟠 urgence moyenne restant
(validation CAPWAP sur vraie capture vendeur) reste hors d'atteinte sans
matériel/trafic réel. Côté 🟢, `--redact` était le candidat resté ouvert
depuis la scission de la Session 27 ("Anonymisation / fusion de captures
segmentées") — la fusion avait été traitée, l'anonymisation restait
seule et sans dépendance sur les autres candidats 🟢 restants
(historique SQLite, CAPWAP Fortinet, NetFlow/sFlow, capture continue,
pistes GitHub). Retenue sans hésitation : seul candidat véritablement
isolé et cadrable en une seule passe.

### Périmètre décidé avant d'écrire le code

"Adresses" au sens strict (IP + MAC), pas "tout ce qui identifie" :
noms DNS (`dns_qry_name`), URI/host HTTP (`http_uri`), SAN de certificat
TLS (`tls_cert_san`), identifiants SIP (`sip_call_id`/`sip_user_agent`/
`sip_server`) volontairement laissés inchangés. Décision prise par
lecture attentive du nom retenu dans `FEATURES.md`
("Anonymisation (`--redact`)") plutôt que d'étendre implicitement le
périmètre à tout ce qui pourrait identifier un poste — une couverture
partielle non signalée aurait été pire que pas de fonctionnalité du
tout (fausse impression de sécurité). Documenté explicitement en tête
de `netcross_core/redact.py`, dans `FEATURES.md` et dans `README.md`
("Limites connues").

### Piège trouvé en lisant le code avant d'écrire quoi que ce soit

En parcourant `pcap_parser/packet.py` pour lister tous les champs
"adresse" à traiter (`src`, `dst`, `arp_sender_mac`, `stp_root_id`,
`dhcp_server_id`) : sur un paquet **STP**, `src`/`dst` sont peuplés
depuis `eth.src`/`eth.dst` — une adresse **MAC**, pas une IP — alors
que pour tous les autres protocoles (`IP`/`TCP`/`UDP`/`ICMP`/`ICMPv6`/
`ARP`) ces deux mêmes champs portent une adresse IP. Une implémentation
naïve qui aurait traité `src`/`dst` uniformément comme des IP aurait
soit levé une exception sur un paquet STP (adresse non parseable en IP),
soit — pire, en cas de `try/except` trop large avalant l'erreur —
laissé les vraies adresses MAC intactes en silence sur tout le trafic
STP d'une capture, sans que rien ne le signale. Vérifié en cherchant
`proto = "STP"` dans `packet.py` avant d'écrire la moindre ligne de
`redact.py` : `_redact_one` teste explicitement `pk.proto == "STP"` et
bascule sur le traitement MAC dans ce cas précis.

### Décisions de conception

- **Mapping partagé, pas par-flux ni par-liste** : `AddressRedactor`
  conserve son état (mapping + compteurs) entre plusieurs appels à
  `.redact()`. Nécessaire pour `cross_capture_diff_cli.py` : baseline et
  courant sont deux listes de paquets chargées et redigées séparément,
  mais doivent produire le même pseudonyme pour une même adresse réelle
  présente des deux côtés — sans quoi le diff perdrait tout son sens
  (une IP commune aux deux runs semblerait être deux IP différentes).
  Un seul `AddressRedactor` créé dans `main()`, passé à `_run_scenario`
  pour le baseline puis pour le courant (ou redact appliqué directement
  sur `current_packets` côté `--live-current`).
- **Refus explicite plutôt que redaction partielle silencieuse** :
  `--tls`/`--quic` relisent les fichiers d'origine avec leur propre
  pipeline (`tls_diagnostics.parse_tls_capture`/
  `quic_diagnostics.parse_quic_capture`, indépendants de
  `netcross_core.parsing`) — les événements qu'ils produisent
  (`TlsHandshakeEvent` et équivalent QUIC) ne passent jamais par la
  liste `all_packets` anonymisée, et leurs messages de diagnostic
  embarquent des adresses réelles en texte formaté. `--client-group`
  reçoit des adresses IP réelles **directement en argument de ligne de
  commande** et les réaffiche telles quelles dans
  `client_diff.print_client_comparison` (`IP(s) : {ips}`), sans lien
  avec les paquets. Dans les deux cas, redonner ces adresses réelles
  après coup aurait demandé soit de retravailler ces pipelines
  indépendants pour qu'ils passent par le même mapping (chantier
  distinct), soit une substitution texte a posteriori sur des messages
  libres (fragile, garantie plus faible qu'une redaction structurelle).
  Choix : refuser la combinaison avec un message explicite plutôt que
  de livrer une garantie bancale — même discipline que le refus déjà
  existant de `--live` avec `--tls`/`--quic`/`--parallel` (Sessions
  5/10/16).
- **Pseudonymes format-préservants et non routables**, pas des
  placeholders opaques (`REDACTED-1`) : IPv4 → RFC 5737 (`TEST-NET-1/2/
  3`, jamais assignées sur le vrai Internet), IPv6 → RFC 3849
  (`2001:db8::/32`), MAC → OUI localement administré
  (`02:00:00:xx:xx:xx`). Choisi pour que le paquet redigé reste
  syntaxiquement valide (IPv4/IPv6 restent distinguables, ce qui compte
  pour certaines analyses) et pour que le caractère anonymisé soit
  reconnaissable sans ambiguïté par quiconque relit un rapport partagé
  — convention déjà répandue chez d'autres outils de redaction de
  capture. Débordement du pool IPv4 (762 adresses RFC 5737) documenté
  sur `240.0.0.0/4` (RFC 1112, jamais assigné) — jamais atteint en
  pratique par une capture de dépannage réseau, mais testé aux bornes
  exactes (indices 253/254/507/508/761/762) plutôt que supposé correct.
- **Mutation en place, pas de copie** : cohérent avec la description
  retenue en Session 27 pour cette piste ("réécrit des adresses dans des
  paquets déjà chargés") et avec le travail de gestion mémoire de la
  Session 19 — copier `all_packets` aurait doublé transitoirement la
  mémoire d'une grosse capture pour un bénéfice nul.
- **Fonctionne indifféremment sur `Pkt` et `RawPacket`** (duck typing,
  aucun `isinstance`) : les deux dataclasses partagent exactement les
  mêmes noms de champs pour tout ce qui est redigé. Pas exploité pour
  étendre la couverture à `--tls`/`--quic` dans cette passe (voir
  ci-dessus, refusés explicitement) mais garde la porte ouverte pour une
  session future qui voudrait retravailler ces pipelines.

### Ce qui a été livré

- **`src/netcross_core/redact.py`** (nouveau module) : `AddressRedactor`
  (mapping + compteurs par type, `.redact(packets)` mutation en place,
  `.entries()` tuples triés, propriété `.mapping`), `redact_packets()`
  (raccourci un seul appel), `write_redaction_map_csv()` (export CSV
  local `adresse_reelle,pseudonyme,type`). Exporté depuis
  `netcross_core/__init__.py` (`AddressRedactor`, `redact_packets`,
  `write_redaction_map_csv` ajoutés à `__all__`).
- **`cross_capture_analyzer_cli.py`** : `--redact` (booléen) et
  `--redact-map CHEMIN`. Validation : `--redact-map` sans `--redact`
  refusé ; `--redact` avec `--tls`/`--quic`/`--client-group` refusé.
  Appliqué juste après le chargement de `all_packets`, avant
  `correlate`/`analyse`. `meta={"Anonymisation": ...}` ajouté aux appels
  `generate_pdf`/`generate_json_report` existants quand `--redact` est
  actif (paramètre `meta` déjà présent sur ces deux fonctions, jamais
  utilisé par cette CLI jusqu'ici — récupéré sans aucune modification
  côté `netcross_report`).
- **`cross_capture_diff_cli.py`** : mêmes flags, même validation (sans
  `--client-group`, qui n'existe pas sur ce CLI). `_run_scenario` prend
  un paramètre `redactor` optionnel, appliqué après `_load_packets` et
  avant `_analyse_packets` — un seul `AddressRedactor` créé dans
  `main()`, partagé entre l'appel baseline et l'appel courant (y compris
  la branche `--live-current`). `meta` ajouté à `generate_diff_pdf`/
  `generate_json_diff` de la même façon.
- **Docstrings de module** (les deux CLI) : nouvel exemple d'utilisation
  `--redact --redact-map ... --pdf-report ...` ajouté à la suite des
  exemples existants.
- **Aucune modification** dans `analysis.py`, `report_text.py`,
  `synthesis.py`, `triage.py`, `charts.py`, `pdf.py`, `json_report.py`,
  `baseline_diff.py`, `client_diff.py`, `correlate.py` : la redaction se
  place en amont de `correlate`/`analyse`, tout le reste du pipeline ne
  voit que des `Pkt` déjà pseudonymisés — y compris les chaînes
  d'exemples formatées construites par `analysis.py`
  (`pmtud_blackhole_examples` et similaires), puisqu'elles sont
  construites à partir des champs déjà réécrits au moment où
  `analyse()` s'exécute.

### Validation

581/581 tests verts (554 hérités + 27 nouveaux dans
`tests/test_redact.py` : générateurs de pseudonymes purs et leurs bornes
de débordement IPv4 exactes, classification IP v4/v6/MAC, comportement
STP, cohérence croisée entre champs — une même MAC vue en `src` STP et
en `arp_sender_mac` ailleurs obtient le même pseudonyme —, réutilisation
du même `AddressRedactor` sur deux appels successifs, tri/format
d'`entries()`, export CSV via `tmp_path`, compatibilité `RawPacket`
construit directement avec tous ses champs). `ruff check`/`ruff format
--check` et `PYTHONPATH=src lint-imports` (57 fichiers, 136
dépendances, aucun cycle) tous réexécutés après modification, tout
passe.

Validation bout-en-bout avec un **vrai `tshark`** et de vrais pcap
`scapy` (pas de mock) : flux TCP de 4 paquets entre deux IP réelles,
généré une fois vu au point LAN et une fois vu au point WAN, plus une
requête ARP côté LAN. Rejeu du **vrai CLI**
(`cross_capture_analyzer_cli.py --capture LAN=... --capture WAN=...
--redact --redact-map map.csv --detail-csv detail.csv`) : `grep` sur la
sortie console et sur `detail.csv` confirme zéro occurrence des 3 IP et
de la MAC réelles ; `map.csv` contient la correspondance exacte (3
lignes IPv4, 1 ligne MAC) ; `detail.csv` contient bien les pseudonymes
RFC 5737 attendus à la place. `--redact --json-report --pdf-report` :
`meta.Anonymisation` présent dans le JSON chargé (`json.load`), zéro
occurrence des IP réelles dans le texte du JSON, mention
"Anonymisation" confirmée en page de garde du PDF via `pdftotext`
(extraction réelle du texte, pas une supposition sur le rendu
`reportlab`). `cross_capture_diff_cli.py --baseline LAN=... --current
LAN=... --redact --redact-map map_diff.csv` : mapping strictement
identique à celui obtenu côté analyzer (mêmes 3 IP + 1 MAC, mêmes
pseudonymes dans le même ordre), confirmant le partage baseline/courant.
Les 3 refus rejoués avec le vrai CLI (`--redact --tls`, `--redact
--client-group A=... --client-group B=...`, `--redact-map` seul sans
`--redact`, sur les deux CLI pour les combinaisons qui s'y appliquent) :
message explicatif clair, code de sortie 1 dans les 6 cas testés.
Non-régression confirmée explicitement : le même run sans `--redact`
laisse bien les adresses réelles dans `detail.csv` (comportement
strictement inchangé hors du nouveau flag).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : nouvelle sous-section `netcross_core.redact` en
  section 2 (juste avant `netcross_gtk4.app`, à la place occupée par le
  module le plus récemment ajouté, même convention que `json_report` en
  Session 12) ; nouvelle entrée en tête de section 4 ("Session 28")
  détaillant le piège STP, les décisions de conception et la validation
  complète ; section 5.2, ligne "Anonymisation (`--redact`)" barrée et
  marquée faite.
- **`claude.md`** (ce fichier) : cette section, ajoutée en fin de
  fichier (même remarque qu'en Session 27 : l'ordre des sections n'est
  déjà plus strictement chronologique depuis la Session 26, non corrigé
  ici, hors périmètre d'une session dédiée à une nouvelle fonctionnalité).
- **`README.md`** : nouvelle puce dans "Ce que fait l'outil" ;
  nouvelles puces `--redact`/`--redact-map` dans "Options utiles" (CLI
  analyzer) et dans les options du CLI diff ; nouvelle entrée dans
  "Limites connues" (périmètre adresses-only, refus des 3 combinaisons,
  GUI non câblée) ; compteur de tests corrigé (554 → 581).

### Non traité dans cette passe

- **`--tls`/`--quic`/`--client-group` restent incompatibles avec
  `--redact`** — un vrai support demanderait de retravailler ces trois
  pipelines indépendants pour qu'ils passent par le même
  `AddressRedactor` partagé (ou d'ajouter une étape de substitution
  texte a posteriori sur leurs messages, option plus fragile écartée
  d'emblée) ; laissé en l'état, refus explicite documenté plutôt que
  demi-mesure.
- **GUI GTK4** — pas de case à cocher `--redact` dans l'interface
  graphique. PyGObject/GTK4 indisponible dans cet environnement pour
  valider visuellement/fonctionnellement un câblage (contrairement aux
  deux CLI, entièrement rejouées avec un vrai `tshark`), et la GUI
  n'est de toute façon couverte par aucun test automatisé dans ce
  projet à ce jour — décision assumée, pas un oubli. Câblage estimé
  relativement simple en principe (une case de plus dans la grille
  d'options déjà partagée entre mode simple et mode diff, comme
  `--nat-tolerant`/`--parallel`) si une session future dispose d'un
  moyen de le valider.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  autre candidat 🟠 restant, toujours hors d'atteinte sans matériel/
  trafic vendeur réel.

