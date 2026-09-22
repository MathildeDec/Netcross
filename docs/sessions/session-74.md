# Session 74 — Extraction et reconstruction de fichiers (issue #150, SCENARIO-4)

**Date :** 22 septembre 2026
**Dépôt :** github.com/MathildeDec/Netcross
**Branche :** job150-file-extraction (PR vers main)

## Objectif

Implémenter l'issue #150 (SCENARIO-4 — « Extraction et reconstruction de
fichiers depuis les traces », issue parente #141) : reconstruire sur
disque les fichiers effectivement transférés dans une capture (objets
HTTP, pièces jointes email, fichiers SMB/FTP) et détecter, par carving
générique (magic bytes), les fichiers transférés sur un flux TCP
quelconque — hors du périmètre de `netcross_core.content`, qui reste
volontairement « metadata seulement » (aucun corps de paquet conservé).

## Analyse préalable

Le projet ne dépend plus de scapy (tout passe par `tshark` en
sous-processus, voir `requirements.txt`) : aucune charge utile brute
n'est disponible dans le pipeline `Pkt`. Deux options : réimplémenter le
réassemblage protocole par protocole en Python, ou déléguer entièrement
à tshark, qui sait déjà le faire. Choix retenu (conforme au critère
d'acceptation « pas de dépendance à un outil externe, tshark fait déjà
le travail de dissection ») : `tshark --export-objects TYPE,DIR`, qui
existe nativement pour `http`, `imf` (email), `smb` et `ftp-data`.
tshark reconstruit le corps (reassemblage TCP, dé-chunking HTTP,
décompression) mais **ne décode pas** le MIME email (base64) — délégué
au module standard `email` de Python (RFC 2045/2046), sans dépendance
supplémentaire.

Pour le carving générique (aucun protocole applicatif supposé), même
principe : `tshark -z follow,tcp,raw,N` reconstruit chaque flux TCP en
octets bruts (les deux sens confondus), puis une recherche de
signatures (magic bytes) fait le reste — ZIP (arrêt à l'enregistrement
EOCD), PDF (`%%EOF`), PNG (chunk IEND), EXE/GIF/JPEG (pas de marqueur de
fin fiable connu, le reste du flux est pris intégralement).

Les métadonnées (frame, timestamp, IP, Content-Type déclaré) ne sont pas
données par `--export-objects` : récupérées par une requête `-T fields`
séparée, filtrée sur les trames porteuses du champ applicatif complet
(`http.file_data`, `mime_multipart.header.content-disposition`,
`smb2.filename`, `ftp.command-response.bytes`), puis appariées par
position avec les fichiers écrits — vérifié empiriquement suivre le même
ordre que `--export-objects` sur les captures de test, documenté comme
best-effort (pas garanti sur des captures avec de nombreux objets
fortement entrelacés).

Aucun pcap réel n'étant disponible dans l'environnement, les captures de
test sont synthétisées octet par octet (Ethernet/IPv4/TCP, checksums
calculés) — même principe que `tests/test_security_report_pcap.py`,
généralisé dans `tests/eth_ip_tcp_builders.py` (`TcpStreamBuilder` :
poignée de main + échanges client/serveur avec gestion automatique de
seq/ack).

## Implémentation

### `src/netcross_core/extract/` (nouveau package)

- `models.py` — `ExtractedFile` (protocole, point, frame/timestamp,
  IP src/dst, nom, Content-Type déclaré, type détecté par signature,
  taille, MD5/SHA256, chemin écrit) + `extracted_files_to_dicts`.
- `_common.py` — utilitaires privés partagés : exécution de tshark
  (`run_export_objects`, `run_fields`), détection de type par magic
  bytes (`detect_type`, réutilisé aussi bien par le carving que pour
  vérifier la cohérence du Content-Type déclaré par HTTP/SMB/FTP),
  hashing, écriture sécurisée (`write_extracted` neutralise tout chemin
  traversant via `os.path.basename`, désambiguïse les collisions —
  jamais d'écrasement silencieux).
- `http.py` / `email.py` / `smb.py` / `ftp.py` — un extracteur par
  protocole, tous sur le même schéma (`--export-objects` + requête
  `-T fields` corrélée), `email.py` ajoutant le décodage MIME via le
  module standard.
- `carver.py` — carving générique (`_carve` : logique pure de
  détection/découpage par signatures, testée sans tshark ;
  `_follow_tcp_raw`/`_list_tcp_streams` : intégration tshark).
- `__init__.py` — `extract_all(pcap_path, dest_dir, *, point, protocols)` :
  orchestrateur combinant les 5 extracteurs, chacun indépendant (un
  `TsharkError` sur l'un n'empêche pas les autres).

### Intégration au reste du projet

- `netcross_core/models.py` — nouveau champ `Report.extracted_files`
  (même convention que `Report.capture_comments` : rempli par
  l'appelant, pas par `analyse()`, car il s'agit d'une métadonnée de
  fichier relue directement, pas d'une statistique par paquet).
- `netcross_core/report_text.py` — section « Fichiers extraits »
  (compte par protocole puis détail par fichier), absente si
  `extracted_files` est vide (sortie historique inchangée).
- `cross_capture_analyzer_cli.py` — flag `--extract-dir DIR` : relit
  chaque fichier passé à `--capture` (même discipline que
  `--security-report`/`--tls`), incompatible avec `--live` (rien à
  relire), `--merge`/`--split`/`--replay` (modes utilitaires qui
  n'analysent rien).

Non fait, hors périmètre de cette session : export JSON/PDF de
`extracted_files` (le champ précédent du même type,
`Report.checksum_errors`, n'est lui non plus câblé nulle part au-delà du
texte console — cohérent avec l'existant, pas une régression introduite
ici).

## Tests

`tests/eth_ip_tcp_builders.py` (nouveau) + `tests/test_extract.py`
(29 tests) :

- unitaires purs (sans tshark) : détection de type par signature,
  hashing, écriture sécurisée (collision, chemin traversant), logique
  de carving (`_carve` — arrêt correct à l'EOCD/`%%EOF`/IEND, prise du
  reste du flux sans marqueur de fin, plusieurs fichiers sans
  chevauchement), orchestration `extract_all` (protocole inconnu,
  isolation des échecs, `protocols=None` couvre tout) ;
- unitaires avec tshark simulé : `smb.py`/`ftp.py` invoquent bien
  `--export-objects smb`/`ftp-data` ; absence de tshark lève
  `TsharkNotFoundError` ;
- intégration avec un vrai tshark (sauté si absent du PATH) : HTTP
  (GET/200 avec corps PDF), email (pièce jointe base64 dans un message
  SMTP/MIME), carving générique (ZIP sur port non standard),
  bout-en-bout via la CLI (`--extract-dir`, y compris les deux refus
  d'incompatibilité `--live`/`--merge`).

## Résultat

`pytest` : 2409/2409 (5 sautés, tshark absent dans certains
environnements) — aucune régression. `ruff check`/`ruff format --check`/
`PYTHONPATH=src lint-imports` verts sur les fichiers de cette session.
`docs/class-diagram.md` régénéré. Pas de `mypy` dans l'outillage qualité
de ce dépôt (voir `.pre-commit-config.yaml` : `ruff`, `import-linter`,
régénération du diagramme de classes uniquement).
