# Session 54 — décision architecturale tranchée : « négociations TLS incomplètes » rejoint le catalogue (39 → 41)

### Demande initiale

D'abord une question ouverte : « Quelles questions à trancher ? »,
suivie de la consigne récurrente habituelle : « Continue les features à
faire de la comparaison avec OmniPeek. Fais évoluer les fichiers de
suivi, de tests et de documentation. » Livraison du zip horodaté
`netcross-{YYYYMMDD-HHMMSS}.zip` sans enchaîner sur la feature
suivante.

### Choix de la feature

Réponse à la question posée : la section « Prochaine feature » de
`CLAUDE.md` (état de fin de Session 53) ne laissait qu'UNE seule
question de décision explicite, les deux autres pistes étant des
chantiers plus larges sans décision à trancher à proprement parler :

1. « négociations TLS incomplètes » (§6.2) — DÉCISION ARCHITECTURALE
   ouverte depuis la Session 49 : (a) faire vivre le signal dans
   `Report`/`analysis.py`, ou (b) l'enrichir dans `tls_diagnostics.py`
   en acceptant qu'il ne soit jamais catalogable.
2. un moteur d'EXÉCUTION qui évaluerait une `Rule` contre un `Report`
   pour produire lui-même un Finding — pas une question à trancher,
   un chantier à construire.
3. cause probable/impact (Session 3) — idem, pas une décision, un
   chantier à construire.

La question posée appelait donc directement le point 1. Plutôt que de
la laisser en suspens une session de plus (ce qui aurait été la
troisième session consécutive à la mentionner sans la traiter), cette
session la tranche.

### Vérification avant de trancher

Le raisonnement documenté depuis la Session 49 présentait l'option (a)
comme coûteuse : « probablement en réutilisant les primitives de
parsing déjà écrites dans `tls_diagnostics.py` [...] reste à
déterminer comment sans casser l'indépendance délibérée de ce module ».
Avant de choisir entre (a) et (b) sur la foi de cette note, vérification
dans le code — même discipline que la correction de la Session 53 :
jamais une affirmation reprise sans relecture de la source qu'elle
décrit.

Lecture de `tls_diagnostics.py` (docstring de module + `diagnose_tls`/
`HandshakeStatus`) : ce module re-parse LUI-MÊME, à la main, les octets
de la charge utile TCP brute (`RawPacket.payload`) pour obtenir des
informations riches (SNI, version/cipher négociés, description
d'alerte) — indépendant de `pcap_parser.protocols` par choix
architectural délibéré (voir sa docstring : "Zero risque de conflit si
analysis.py/models.py sont modifies en parallele").

Lecture de `pcap_parser/protocols.py::extract_tls_certificate`
(Session 26/53) : cette fonction, elle, ne fait AUCUN parsing manuel —
elle lit des champs déjà décodés par tshark lui-même, exposés dans le
JSON `-T ek` (`x509af_x509af_utcTime`, etc.). Lecture de
`pcap_parser/ek_source.py` : la commande tshark est invoquée en `-T ek`
SANS restriction de champs (pas de `-e`) — la dissection COMPLÈTE de
tshark pour chaque paquet est donc déjà disponible dans `layers`, y
compris pour TLS.

Hypothèse à vérifier : tshark expose-t-il nativement, dans ce même JSON
déjà consommé, le type d'enregistrement TLS (handshake/alert/
application_data) et le sous-type Handshake (ClientHello/ServerHello) ?
Si oui, l'option (a) ne coûte ni duplication du parsing de
`tls_diagnostics.py`, ni atteinte à son indépendance : une fonction
d'extraction FRAÎCHE, aussi légère que `extract_tls_certificate`,
suffirait.

#### Vérification empirique (pas supposée)

`tshark` n'était pas installé dans cet environnement — installé via
`apt-get install tshark` (4.2.2-1.1build3, même version que celle déjà
documentée dans ce projet — `archive.ubuntu.com`/`security.ubuntu.com`
sont dans le réseau autorisé). Capture générée sur `lo` :

1. Certificat auto-signé (`openssl req -x509 ...`, 3 jours de validité,
   SAN `test.example.com`/`alt.example.com`).
2. `openssl s_server -tls1_2 ...` + `openssl s_client -tls1_2 ...` sur
   `127.0.0.1:8443` — premier essai : le handshake N'A PAS abouti
   (`0 server accepts (SSL_accept())` côté serveur, `SSL handshake has
   read 0 bytes` côté client) — un ClientHello envoyé, jamais de
   réponse. Capturé tel quel (`capture.pcap`, 6 paquets) : un exemple
   RÉEL, non simulé, de négociation incomplète — exactement le
   phénomène à détecter.
3. Deuxième essai avec `curl -k --tlsv1.2` contre
   `openssl s_server -www` : handshake TLS 1.2 COMPLET (ClientHello →
   ServerHello+Certificate+ServerKeyExchange+ServerHelloDone →
   ClientKeyExchange+ChangeCipherSpec+Finished → réponse HTTP réelle →
   fermeture propre) capturé dans `capture2.pcap` (19 paquets).

Inspection de `capture2.pcap` via `tshark -r ... -T ek`, champ par
champ :

- `tls_tls_record_content_type` : présent sur CHAQUE enregistrement TLS
  (20/21/22/23 confirmés), y compris sur l'enregistrement du `Finished`
  CHIFFRÉ après `ChangeCipherSpec` (content_type=22 visible même si le
  sous-type Handshake ne l'est plus) et sur l'application_data chiffrée
  (content_type=23 visible sans que le contenu le soit) — confirme que
  ce champ est un en-tête d'enregistrement TOUJOURS en clair, jamais
  lui-même chiffré.
- `tls_tls_handshake_type` : `"1"` sur le ClientHello (paquet
  isolé) ; **LISTE** `["2", "11", "12", "14"]` sur le paquet qui
  coalesce ServerHello+Certificate+ServerKeyExchange+ServerHelloDone
  (le serveur regroupe souvent ces quatre messages Handshake dans un
  seul segment TCP) — confirme la nécessité d'un traitement
  scalaire-ou-liste, EXACTEMENT le même que celui déjà en place pour
  les dates de certificat (`x509af_x509af_utcTime`) dans
  `extract_tls_certificate`.
- `tls_tls_handshake_extensions_server_name`/`tls_tls_handshake_version`
  également présents et lisibles (confirmant au passage que le SNI et
  la version proposée sont accessibles nativement — hors périmètre de
  cette session mais utile à savoir pour une extension future).

Conclusion vérifiée : l'option (a) ne coûte NI duplication du parsing
manuel de `tls_diagnostics.py`, NI atteinte à son indépendance. Une
fonction neuve, aussi légère qu'`extract_tls_certificate`, suffit.
L'option (b) — accepter une lacune de couverture permanente — n'a donc
plus de justification : rien ne la rendait préférable à (a) une fois
son coût réel connu. **Décision : option (a).**

### Choix de conception

Portée du signal, volontairement plus modeste que
`tls_diagnostics.HandshakeStatus` (qui suit SNI, version/cipher,
description d'alerte) — seulement ce que `content_type`/
`handshake_type` permettent de dire sans ambiguïté :

- `tls_handshake_no_reply` : un ClientHello vu pour une connexion à un
  point, jamais suivi d'un ServerHello pour cette même connexion, à ce
  même point. PAR POINT (comme `tls_cert_invalid_dates`), pas de
  corrélation entre points ni d'hypothèse d'ordre — une négociation qui
  ne va pas à son terme se voit déjà au sein d'un seul point.
- `tls_handshake_incomplete` : un ServerHello EST vu, mais aucun
  enregistrement `application_data` jamais observé ensuite pour cette
  même connexion, à ce même point. Distinction délibérée en deux
  compteurs plutôt qu'un seul (même discipline que les quatre compteurs
  DNS de la Session 49) : silence total après l'ouverture (filtrage,
  service injoignable) est un phénomène différent d'une négociation qui
  démarre des deux côtés puis s'interrompt (abandon client, certificat
  refusé, middlebox qui coupe en cours de route).

Corrélation par connexion NON ORIENTÉE (les deux extrémités (ip, port)
triées) plutôt que par 5-tuple directionnel strict comme
`_analyse_handshake` (SYN/SYN-ACK) : ClientHello va client→serveur,
ServerHello va serveur→client, application_data peut aller dans les
deux sens selon qui parle en premier — un seul point de vue suffit
pour cette connexion à CE point, pas besoin de savoir quel côté a émis
quoi.

Limites assumées, documentées dans le code plutôt que découvertes plus
tard :

- Ne distingue pas une négociation réellement bloquée d'une capture
  arrêtée avant que la suite n'arrive — limite structurelle de toute
  analyse PAR POINT sur une capture finie, comme `dns_timeout`/
  `syn_no_synack`.
- TLS 1.3 déguise en `application_data` (content_type=23) les messages
  de handshake qui suivent le ServerHello (EncryptedExtensions,
  Certificate, CertificateVerify, Finished — pour la compatibilité des
  intermédiaires qui n'attendent que des types d'enregistrement TLS 1.2
  classiques) : `tls_handshake_incomplete` peut donc, dans de rares
  cas, ne pas se déclencher pour une négociation TLS 1.3 qui
  s'interrompt juste après ce déguisement mais avant tout vrai transfert
  applicatif. Même ambiguïté déjà documentée dans
  `netcross_core.tls_diagnostics` — pas une erreur d'implémentation
  propre à ce module.

### Ce qui a été livré

- `pcap_parser/protocols.py::extract_tls_handshake()` — nouvelle
  fonction, lit `tls_tls_record_content_type`/`tls_tls_handshake_type`
  (scalaire ou liste, même traitement que les dates de certificat),
  renvoie trois booléens par paquet.
- Trois nouveaux champs bout-en-bout : `RawPacket`
  (`pcap_parser/packet.py`) → `Pkt` (`netcross_core/models.py`) via
  l'adaptateur `netcross_core/parsing.py` —
  `tls_client_hello`/`tls_server_hello`/`tls_application_data`.
- `netcross_core/analysis.py::_analyse_tls_handshake()` — nouveau
  détecteur, PAR POINT, alimente les deux nouveaux compteurs
  `Report.tls_handshake_no_reply`/`tls_handshake_incomplete` (+
  `_examples`/`_frames`).
- `netcross_report/synthesis.py::build_findings()` — nouveau bloc
  « -- negociations TLS incompletes -- », deux sites de `Finding`,
  `rule_id` câblé dès la création.
- `netcross_core/expert_rules.py` — deux nouvelles règles
  (`tls_handshake_no_reply`/`tls_handshake_incomplete`, 39 → 41),
  domaine `"TLS"`, sévérité `anomalie`, confiance `0.8`.
- `netcross_core/report_text.py` — nouvelle section
  « -- Negociations TLS incompletes -- ».
- `netcross_core/baseline_diff.py` — deux nouveaux `_compare_count`
  dans la boucle par point.
- Docstrings de module mises à jour (`expert_rules.py` : section
  « Portée de la Session 54 » ; `synthesis.py` : paragraphe `rule_id`
  Session 54, remplace le paragraphe Session 53 devenu obsolète sur ce
  point).
- `CLAUDE.md`/`docs/features-backlog.md` mis à jour (état courant,
  section 4, section 13.3, section « Prochaine feature » réécrite —
  il ne reste plus que deux chantiers ouverts, tous deux de nature
  différente d'une décision de catalogue).

### Tests

- `tests/conftest.py`/`tests/test_parsing_adapter.py`/
  `tests/test_redact.py` : ajout des trois nouveaux champs
  (`tls_client_hello`/`tls_server_hello`/`tls_application_data`,
  défaut `False`) partout où `RawPacket`/`Pkt` sont construits
  explicitement — nécessaire pour que les fixtures existantes
  continuent de fonctionner (dataclass sans valeur par défaut).
- `tests/test_analysis.py` : huit tests neufs sur
  `_analyse_tls_handshake` — handshake complet sans signal ; `no_reply`
  détecté (message + numéro de trame) ; `incomplete` détecté (message +
  numéro de trame du ClientHello, pas du ServerHello) ; ServerHello
  seul sans ClientHello ignoré (rien à diagnostiquer à ce point) ;
  paquets sans signal TLS ignorés ; indépendance stricte entre points
  (le même ClientHello incomplet en A, complet en B).
- `tests/test_synthesis.py` : huit tests neufs — sévérité/segment pour
  les deux signaux, évidence (avec et sans numéro de trame) pour les
  deux, `rule_id` pour les deux.
- `tests/test_report_text.py` : trois tests neufs — affichage de
  chaque signal, message par défaut en l'absence de négociation
  incomplète.
- `tests/test_baseline_diff.py` : six tests neufs — nouvelle occurrence
  signalée pour les deux signaux, évidence (avec et sans numéro de
  trame) pour les deux.
- `tests/test_expert_rules.py` : `_EXPECTED_IDS` étendu ; comptage
  catalogue `39` → `41` (renommé) ; `test_negociations_tls_incompletes_
  non_cataloguees` devient `test_negociations_tls_incompletes_
  desormais_cataloguees` (assertion inversée : le domaine `"TLS"`
  contient désormais les QUATRE règles) ; `test_catalogue_deux_regles_
  tls` devient `test_catalogue_quatre_regles_tls` ; nouvelle section
  « spot checks Session 54 » (sévérité/confiance, autonomie/seuils
  vides, métriques requises pour les deux nouvelles règles) ; le test
  d'agrégation `rule_id` (renommé `..._quarante_et_une_...`) étend le
  `Report` synthétique avec les deux nouveaux champs.
- Total : **930 → 959** (+29 net : +4 `test_expert_rules.py`, +8
  `test_analysis.py`, +8 `test_synthesis.py`, +3 `test_report_text.py`,
  +6 `test_baseline_diff.py`).

### Validation

Suite complète rejouée avant tout nouveau code (930/930, héritée de la
Session 53) puis après (**959/959**, +29 net).

`ruff check .` propre ; `ruff format --check .` a signalé UN fichier
à reformater (`report_text.py`, ligne dépassant la limite de 120
caractères dans le nouveau bloc `print()`) — corrigé avec `ruff format`
directement, aucun changement de comportement (reformatage pur).
Vérifié avec la version épinglée `ruff==0.16.4`.

`PYTHONPATH=src lint-imports` : 65 fichiers, 164 dépendances, contrat
respecté — inchangé (aucun nouveau module créé cette session, seules
des fonctions ajoutées à des fichiers existants).

`mypy --ignore-missing-imports` sur les neuf fichiers source modifiés :
une erreur introduite PUIS corrigée dans la même session —
`extract_tls_handshake` annonçait `-> set[int]` mais son corps
produisait potentiellement `set[int | None]` (`hex_or_dec_to_int` peut
renvoyer `None` sur un champ malformé, chose que la compréhension
d'ensemble ne filtrait pas). Corrigé en filtrant explicitement les
`None` avant de construire l'ensemble — AUCUN changement de
comportement (les valeurs recherchées par les appelants, `1`/`2`/`23`,
ne sont de toute façon jamais `None`, filtrer les `None` en amont ou
les laisser ne jamais matcher en aval revient au même). Après
correction : 0 erreur imputable. Repassage complet sur `src/` :
toujours **49 erreurs sur 9 fichiers**, décompte identique à celui
confirmé en Session 53 — `pcap_parser/protocols.py` (seul fichier qui
aurait pu hériter de l'erreur introduite puis corrigée) n'apparaît PAS
dans la liste des 9 fichiers concernés.

**Validation bout en bout avec une vraie capture**, contrairement à la
Session 53 (justifié ici : détecteur ENTIÈREMENT nouveau, même
situation que la Session 52 pour HTTP, à la différence de la Session
53 qui ne faisait que cataloguer un détecteur déjà testé de longue
date) :

- Les deux pcaps générés pour la vérification empirique (voir
  « Vérification avant de trancher » ci-dessus) rejoués intégralement
  à travers `netcross_core.parsing.parse_capture` →
  `netcross_core.correlate.correlate` → `netcross_core.analysis.analyse`
  (le VRAI pipeline, pas `make_pkt` synthétique) :
  - `capture.pcap` (ClientHello réel sans réponse) →
    `tls_handshake_no_reply == {"A": 1}`, `tls_handshake_incomplete ==
    {}` — exemple exact : `"127.0.0.1:37486 -> 127.0.0.1:8443 :
    ClientHello envoye, aucun ServerHello observe a ce point"`.
  - `capture2.pcap` (handshake TLS 1.2 complet réel via `curl`) → les
    deux compteurs restent vides — zéro faux positif sur un handshake
    parfaitement sain.
  - Non-régression : `tls_cert_invalid_dates`/`tls_cert_mismatch`
    (Session 26/53) restent vides sur `capture2.pcap`, comme attendu
    (certificat auto-signé valide 3 jours, un seul point de capture).
- Rejoué une deuxième fois via le CLI complet
  (`cross_capture_analyzer_cli.py --capture "A=capture.pcap"`) plutôt
  que par appel direct des fonctions internes : la sortie texte
  affiche bien la nouvelle section « -- Negociations TLS incompletes
  -- » avec le compte et l'exemple attendus, confirmant que le câblage
  bout en bout (CLI → `parsing` → `analyse` → `report_text`) fonctionne
  réellement, pas seulement au niveau unitaire.

`README.md` volontairement NON modifié, même raison qu'aux Sessions
46-53 : aucune capacité visible côté CLI/PDF/GUI qui ne soit déjà
couverte par la description existante de l'analyse TLS ; seul le JSON
gagne deux valeurs possibles pour un champ (`rule_id`) déjà exposé
depuis la Session 48.

### Non traité dans cette passe

- Le moteur d'EXÉCUTION qui évaluerait une `Rule` du catalogue contre
  un `Report` pour PRODUIRE lui-même un Finding/ExpertEvent — le sens
  reste inverse : `rule_id` annote un Finding déjà produit par le code
  procédural existant.
- Cause probable/impact — bascule en réalité vers la Session 3
  (corrélation et causalité, difficulté 5/5).
- Les informations riches déjà accessibles nativement mais non
  exploitées ici (SNI via `tls_tls_handshake_extensions_server_name`,
  version proposée via `tls_tls_handshake_version`) — hors périmètre du
  signal « négociation incomplète » tel que nommé par la section 6.2 ;
  à reconsidérer si un signal futur en a besoin.
- Les 49 erreurs `mypy` documentées en Session 50 (nettoyage optionnel,
  jamais priorisé depuis la Session 38) — aucun des neuf fichiers
  concernés n'a été retouché cette session au-delà de l'erreur
  introduite puis corrigée dans `protocols.py` (qui n'en fait pas
  partie).

**Bilan** : à l'issue de cette session, la bibliothèque de règles
déclarative (§6.2) est complète — 41 règles, toutes les catégories de
`Finding` couvertes, tous les signaux nommés par la section 6.2
catalogués, et plus aucune décision architecturale en suspens sur ce
périmètre précis. Les deux chantiers restants (moteur d'exécution,
cause probable/impact) sont d'une nature différente : ce ne sont plus
des décisions à trancher mais des constructions à entreprendre.
