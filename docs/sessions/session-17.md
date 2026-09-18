# Session 17 — Codes de statut HTTP

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 16.

### Contrainte d'environnement de cette session

Vérifié en tout début de session : `apt-get install tshark` a réussi
(`tshark 4.2.2`), et `pip install pytest ruff import-linter pre-commit`
également. Les deux en même temps, comme les Sessions 9/10/11/14 —
**pas une première absolue** (à la différence de ce qu'une lecture rapide
de la mémoire pourrait laisser penser : la note "première fois dans
l'historique du projet" qui y figure concerne l'arrivée de `tshark`
**seul** à la Session 9, pas sa combinaison avec `pytest`). Situation
différente en revanche des Sessions 12/13/15/16, qui n'avaient ni l'un ni
l'autre — et notamment de la Session 13 (résolution DNS), dont la
conception la plus proche de celle-ci a dû se faire par analogie plutôt
que par vérification directe.

### Choix de la feature suivante

Section 4/5.2 de `FEATURES.md` passée en revue. Les deux pistes 🟠
urgence moyenne restent hors de portée quel que soit l'outillage
disponible (validation CAPWAP contre du vrai matériel Aruba/Cisco/
Fortinet, gestion mémoire de captures de plusieurs Go) : avoir `tshark`
ne fournit pas de trafic CAPWAP réel, seulement la capacité de le
décoder. Parmi les pistes 🟢, "Codes de statut HTTP" a été retenue :
même levier que DNS (dissection tshark native, aucune dépendance externe
à ajouter), et occasion unique d'utiliser le vrai `tshark` disponible
cette session pour vérifier empiriquement les champs EK réels avant
d'écrire `extract_http` plutôt que par analogie avec DHCP/DNS — chose que
ni DNS (Session 13) ni aucune autre extraction de ce fichier n'avait pu
faire pour ce protocole précis.

### Vérification empirique préalable (avant tout code)

Capture HTTP/1.1 réelle générée entièrement dans cet environnement :
petit serveur `http.server` Python (routes `/`, `/notfound` → 404,
`/error` → 500, `/slow` → 200 après 300ms, `/submit` → 201 en POST) sur
`127.0.0.1:8080`, capturée avec `tshark -i lo -f "tcp port 8080"` pendant
que `curl` interroge chaque route, puis décodée avec `tshark -T ek` pour
inspecter les champs bruts. Deux éléments ont directement influencé la
conception, décrits en détail dans `FEATURES.md` section 4 :

- `http.time` (écart requête→réponse) est calculé **nativement par
  tshark**, par transaction, uniquement sur le paquet de réponse — pas
  besoin de le recomposer à la main comme pour DNS/DHCP/SIP. Nouveau
  helper `as_float()` dans `ek_fields.py` pour le lire (chaîne flottante
  de secondes, ex. `"0.000467410"`).
- La réponse porte `http.response_for.uri` (l'URI complète déjà
  réappariée par tshark côté réponse) mais pas la méthode — utilisé
  directement plutôt que de refaire l'appariement requête/réponse.
- `http.request`/`http.response` : booléens JSON natifs, comme
  `ip.flags.df` (Session 9) — `as_bool()` existant suffit.

### Décision de conception assumée

Aucun identifiant applicatif HTTP ne joue le rôle de `dhcp.xid`/SIP
Call-ID/`dns.id` pour suivre une transaction à travers les points de
capture. Une position ordinale pure dans la connexion TCP
(1ère requête, 2e requête...) se désynchroniserait dès qu'une requête
entière est perdue sur un segment alors que les suivantes, sur une URI
différente, survivent — glissement d'un cran qui produirait un faux
négatif sur la requête réellement perdue et un faux positif sur celle
qui la suit. Retenu à la place : `(connexion TCP, URI, Nième occurrence
de cette URI sur cette connexion à ce point)`. Limite assumée résiduelle,
même famille que la réutilisation d'un id DNS 16 bits (Session 13) : si
la même URI est rejouée plusieurs fois sur la même connexion (polling)
ET qu'une occurrence précise est perdue à un point donné, le même
glissement peut se reproduire entre les occurrences restantes de cette
URI. Non gérée spécifiquement — documentée dans la docstring de
`_analyse_http` et dans un test dédié qui, lui, couvre le cas qui
fonctionne (deux URI différentes, perte de l'une des deux).

Sévérités retenues, par analogie DNS (NXDOMAIN/SERVFAIL) plutôt que
DHCP/SIP : 4xx = "info" (souvent légitime côté client), 5xx = "anomalie"
(échec serveur, souvent pris à tort pour un problème réseau). Cette
distinction a été poussée jusque dans `baseline_diff.py` : seuils
agressifs (`min_delta=1, rel_threshold=0.0`, comme SERVFAIL) pour le 5xx,
seuils par défaut plus tolérants (`min_delta=3, rel_threshold=0.5`) pour
le 4xx — un 404 isolé est trop souvent légitime pour déclencher une
régression dès la première occurrence.

### Ce qui a été livré

Voir `FEATURES.md` section 2 (`pcap_parser`/`netcross_core.analysis`)
pour le détail technique module par module. En résumé :

- `pcap_parser/ek_fields.py` : `as_float()`.
- `pcap_parser/protocols.py` : `extract_http(layers)`.
- `pcap_parser/packet.py` : 6 nouveaux champs sur `RawPacket`, extraction
  gatée sur `proto == "TCP"` uniquement (HTTP/2 : dissecteur distinct,
  HTTP/3 : QUIC/UDP déjà couvert séparément par `quic_diagnostics` —
  les deux hors périmètre, testé explicitement qu'une couche `http`
  présente à tort aux côtés d'UDP est ignorée).
- `netcross_core/models.py` : champs `Pkt` + `Report`.
- `netcross_core/parsing.py` : propagation dans `_to_pkt`.
- `netcross_core/analysis.py` : `_analyse_http`.
- `netcross_report/synthesis.py` : findings 4xx/5xx/timeout/missing/durée
  moyenne (avec `sample_size`, seuil 500ms — par analogie avec les autres
  seuils de latence déjà en dur dans ce fichier, pas issu d'une norme
  HTTP particulière, même réserve que le choix des 200ms pour DNS en
  Session 13).
- `netcross_core/baseline_diff.py` : comparaisons avant/après (voir
  seuils asymétriques 4xx/5xx ci-dessus). Pas de comparaison de
  `http_missing`, même choix que `dhcp_missing`/`dns_missing`/
  `sip_missing`, jamais comparés non plus dans ce fichier.
- `netcross_core/report_text.py` : section console dédiée.
- Automatique, sans nouveau flag CLI (même choix que DNS/PMTUD) : parité
  GUI/PDF/JSON gratuite via le mécanisme générique `Finding`/`Report` —
  confirmée par une génération PDF et un export JSON réels cette fois
  (voir Validation), pas seulement supposée par analogie avec DNS.

### Validation

Suite complète rejouée **avant** tout nouveau code : 362/362 hérités
intacts, confirmant l'absence de régression préalable.

Ajout des nouveaux champs obligatoires sur `Pkt`/`RawPacket` (sans valeur
par défaut, comme tous les champs DNS/DHCP/SIP précédents) a cassé deux
fabriques de test qui construisent ces objets avec une liste figée de
champs : `tests/conftest.py::make_pkt` et
`tests/test_parsing_adapter.py::_raw`. Corrigées avant d'écrire le
moindre nouveau test — sans quoi toute la suite (pas seulement les
nouveaux tests) aurait échoué en cascade, comme observé en local (88
échecs avant correction, tous liés à ces deux fabriques et pas à une
régression réelle du code).

74 nouveaux tests, tous `pytest` réels (`test_ek_fields.py` : `as_float`
en isolation ; `test_protocols.py` : `extract_http` en isolation, avec
les valeurs EK réelles relevées empiriquement ; `test_packet.py` :
`build_packet` sur TCP requête/réponse et confirmation qu'une couche
`http` est ignorée sur UDP ; `test_analysis.py` : `_analyse_http` via le
pipeline complet `correlate`/`analyse` — requête+réponse au même point,
message manquant entre points, timeout, 4xx/5xx comptés par point,
exemple d'erreur incluant la méthode de la requête correspondante,
glissement d'URI évité (test dédié à la décision de conception
ci-dessus), polling sans perte ne signale rien ; `test_synthesis.py` et
`test_baseline_diff.py` : sévérités et seuils asymétriques 4xx/5xx ;
`test_report_text.py` : rendu de la section console) — 399/399 au total.
Un test écrit avec une hypothèse initialement incorrecte sur le
comportement attendu (pensait qu'une transaction perdue sur un seul
segment déclencherait aussi un timeout global) a été corrigé après
l'avoir vu échouer : la lecture du résultat a montré que le comportement
du code était le bon (une réponse observée à un point n'est pas un
timeout global, seulement un message manquant sur le segment), l'erreur
venait de l'assertion, pas de `_analyse_http`.

`ruff check`, `ruff format`, `lint-imports` et
`pre-commit run --all-files` rejoués réellement (déjà fait par le passé
quand l'accès réseau le permettait, voir Session 7/9/14, pas une
première). `ruff check --fix` a corrigé un tri d'imports resté en
attente dans `tests/test_diff_cli_live.py` depuis la Session 16 (accès
réseau alors indisponible). `ruff format` a reformaté 3 fichiers
préexistants pour la même raison (`cross_capture_diff_cli.py`,
`netcross_report/triage.py`, un bloc de `tests/test_synthesis.py`) —
aucun changement de comportement, uniquement du style. `pre-commit run
--all-files` : les 3 hooks passent.

Validation bout-en-bout avec deux vraies captures tshark, au-delà des
tests unitaires : à partir de la capture loopback réelle décrite plus
haut, construction de deux fichiers "point A"/"point B" avec `editcap`
(outil de la suite Wireshark, disponible aux côtés de `tshark`) en
retirant précisément la transaction `/error` (requête+réponse) du second
fichier — simulant une perte sur le segment A→B — et la réponse de la
transaction `/slow` des deux fichiers — simulant un timeout global.
Rejeu du pipeline réel complet (`parse_captures_parallel` → `correlate`
→ `analyse` → `print_report`/`build_findings`/`generate_pdf`/export
JSON, ce dernier via la vraie CLI `cross_capture_analyzer_cli.py`) :
les deux scénarios sont détectés exactement comme attendu (message
manquant sur `/error` uniquement, timeout sur `/slow` uniquement),
sans aucun faux positif sur les 3 autres transactions présentes aux deux
points. Confirme en conditions quasi réelles la conception de la clé de
transaction par URI plutôt que par position ordinale.

### Fichiers de suivi/documentation mis à jour

- `FEATURES.md` : section 1 (diagrammes de classes `ek_fields`/
  `protocols`/`analysis_mod`), section 2 (paragraphe détaillé miroir de
  celui de DNS), section 4 (nouveau bloc "Nouvelle fonctionnalité ajoutée
  dans cette passe"), section 5.2 (entrée barrée avec renvoi).
- `claude.md` : cette entrée.
- `README.md` : à vérifier/mettre à jour si la liste des protocoles
  couverts y est énumérée (voir README.md lui-même pour le détail exact
  de ce qui a changé, le cas échéant).

### Non traité dans cette passe

Le reste de la section 5.2 (graphiques temporels, TLS approfondi,
analyse L2, fragmentation IPv6, timeout d'inactivité, score de santé
synthétique, historique inter-sessions, anonymisation, CAPWAP Fortinet,
NetFlow/sFlow, capture continue + diff en direct, pistes GitHub,
validations admin) : une feature à la fois, comme convenu.

---

