# Session 14 — comparaison client vs client

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — meme consigne que
les Sessions 8/9/10/11/12/13.

### Contrainte d'environnement de cette session

Verifie en tout debut de session : `tshark`, `pytest`, `ruff` absents au
depart (comme d'habitude), mais **acces reseau disponible** cette fois
(`pip install`/`apt-get install` fonctionnent) — installes et utilises
reellement : `pytest 9.1.1`, `ruff 0.16.4`, `import-linter`, `tshark
4.2.2`, `scapy`. Meme situation que les Sessions 9/10/11, differente des
Sessions 1-8/12/13.

### Choix de la feature suivante

`FEATURES.md` section 5.2, 🟠 urgence moyenne : "Comparaison client vs
client" restait explicitement ecartee depuis la Session 13, faute d'un
detail de conception disponible dans l'archive livree (seule sa synthese
dans `FEATURES.md` l'etait). Avant de choisir une autre piste, verifie
si les documents sources (`idées.md`, `netcross_pistes_evolution2.md`)
sont accessibles via l'integration Google Drive de cette session — ils
le sont (dossier de suivi netcross, memes documents que ceux dont
`FEATURES.md` consolide deja la synthese). Lu integralement
`netcross_pistes_evolution2.md` §2 ("Axe complementaire : comparaison
client vs client") : design complet et directement actionnable —
reutilise `analyse()`/`diff_reports()` deja ecrits, aucun nouveau moteur.
Retenue en priorite (c'etait le point #1 de la section 5 "Suggestion de
priorisation" de ce meme document source).

Face aux autres candidats 🟠 restants (score de confiance/`sample_size`,
validation CAPWAP sur vraie capture, gestion memoire grosses captures) :
le detail de conception disponible et la nature "cablage, pas nouveau
moteur" de cette piste la rendaient la moins risquee a cadrer en une
seule session — meme raisonnement que la Session 13 pour DNS face a la
meme piste, desormais inverse par la disponibilite du design.

### Ce qui a ete livre

**`netcross_core/client_diff.py`** (fichier neuf, meme discipline que
`baseline_diff.py` — independant, ne modifie ni `parsing.py` ni
`analysis.py` ni `models.py` ni `correlate.py`) :
- `group_packets_by_client(all_packets, client_group)` — repartit une
  capture par poste selon un groupement EXPLICITE `{nom: {ip, ...}}`.
  **Decision de conception** : pas d'auto-detection par IP unique,
  contrairement a ce que suggere une lecture rapide de `idées.md` §2
  ("filtrer `all_packets` par IP") — le document ne precise pas quelle
  heuristique distinguerait les IP "clients" des IP "serveurs" presentes
  dans la meme capture ; une IP unique choisie automatiquement
  produirait un client par IP source vue, serveurs compris, ce qui n'a
  pas de sens pour cet axe de comparaison. Seul le groupement explicite
  est donc supporte pour cette session — une auto-detection resterait a
  concevoir specifiquement si le besoin se confirme (pas un choix par
  defaut risque).
- Un paquet est assigne a un client des que `pk.src` OU `pk.dst`
  correspond a une IP du groupe (le trafic dans les deux sens compte
  pour ce client, pas seulement ce qu'il emet). Consequence assumee et
  documentee : un paquet de trafic direct entre deux postes tous deux
  dans le perimetre de comparaison compterait pour les deux — rare en
  pratique (usage vise : client -> serveur), non filtre specifiquement.
- `build_client_report(...)` — un `ClientReport` (dataclass : client,
  ips, packet_count, report, signature) par client, en appelant
  `correlate()` puis `analyse()` sur le sous-ensemble de paquets qui lui
  est rattache, avec le meme `points_order` partage entre tous les
  clients (memes points de capture, seule la source change — sans quoi
  les `Report` deviendraient incomparables entre eux).
- `ClientSignature` — agregation `Counter` de `dhcp_vendor_class`/
  `sip_user_agent` par client (idées.md §2 point 4), deja partiellement
  captes ailleurs dans le projet, aucune nouvelle extraction de paquet.
  Le JA3/version TLS mentionne dans le meme document n'existe pas encore
  dans `tls_diagnostics.py` — non repris ici, pas de champ fantome.
- `compare_clients(all_packets, client_group, reference=None, ...)` —
  point d'entree principal : construit tous les `ClientReport` puis
  diffe chaque client SAUF la reference contre elle, en reutilisant
  `diff_reports()` deja ecrit (mode N-way, idées.md §2 point 3 : "prendre
  un client de reference ... et diffe chaque autre client contre lui.
  Aucun nouveau moteur de diff"). Reference par defaut : le premier
  client du dict fourni (donc le premier `--client-group` cote CLI,
  ordre d'insertion Python garanti depuis 3.7). Leve `ValueError` si
  moins de 2 clients, ou si la reference demandee n'existe pas dans le
  groupement.
- `print_client_comparison`/`write_client_diff_csv` — meme esprit que
  `print_diff_report`/`write_diff_csv` : banniere dediee pour la
  reference (meme style que les bannieres BASELINE/COURANT deja
  utilisees pour TLS/QUIC en Session 8), puis chaque client compare avec
  son verdict (marqueurs REGRESSION/MIEUX/A VERIFIER/STABLE identiques a
  `baseline_diff`). CSV : memes colonnes que `write_diff_csv` plus une
  colonne `client` en tete (la reference n'a pas de ligne, rien a
  diffee contre elle-meme).

**`netcross_core/__init__.py`** : export de `ClientComparisonResult`,
`ClientReport`, `compare_clients`, `print_client_comparison`,
`write_client_diff_csv`.

**`cross_capture_analyzer_cli.py`** :
- `--client-group NOM=IP1[,IP2,...]` (repetable, virgules pour le cas
  multi-IP/DHCP d'un meme client), `--client-reference NOM`,
  `--client-diff-csv CHEMIN`.
- Validation cote CLI (avant tout calcul) : au moins 2 `--client-group`
  distincts sinon erreur explicite ; `--client-reference` inconnu du
  groupement fourni sinon erreur explicite listant les clients
  disponibles ; `--client-reference`/`--client-diff-csv` sans
  `--client-group` egalement rejetes explicitement (plutot que
  silencieusement ignores).
- **Additif, pas un mode exclusif** : contrairement a `--live` qui
  interdit `--tls`/`--quic`/`--parallel`, `--client-group` s'applique
  APRES l'obtention de `all_packets`, quelle que soit son origine
  (fichiers ou `--live`) — aucune raison structurelle de l'exclure de
  l'un ou l'autre, decision differente de celle prise pour TLS/QUIC en
  mode live (qui, eux, ont besoin de relire un fichier). L'analyse
  principale (`Report` combine habituel) reste toujours calculee et
  affichee en premier, la comparaison client vs client s'affiche apres.
- **Non cable** : `--pdf-report`/`--json-report` (le mecanisme generique
  qui a donne la parite gratuite a PMTUD/retrans/options TCP/DNS ne
  s'applique pas ici — `compare_clients` produit PLUSIEURS `Report` et
  des `DiffFinding` par client, pas un seul `Report` consomme tel quel
  par `build_findings`/`generate_pdf`/`generate_json_report` ; un vrai
  travail d'integration serait necessaire cote `netcross_report`),
  GUI GTK4 (vrai travail d'interface), et `cross_capture_diff_cli.py`
  (combiner client vs client ET avant/apres dans une seule commande n'a
  pas de precedent ni de design tranche dans les documents source).

### Validation

**Premiere fois depuis les Sessions 9/10/11 avec un vrai acces reseau**
dans cet historique de sessions (verifie en tout debut de session,
contrairement a l'hypothese par defaut "pas d'acces reseau" qui avait
cours depuis la Session 12) :
- `pip install pytest ruff import-linter scapy --break-system-packages`
  et `apt-get install tshark` ont tous reussi.
- Suite complete rejouee **avant** tout nouveau code : 311/311 (heritee
  intacte de la Session 13), confirmant l'absence de regression
  prealable.
- 14 nouveaux tests (`tests/test_client_diff.py`, reels `pytest`, pas de
  harnais de secours cette fois) : regroupement par src/dst/IP multiple/
  IP non reconnue, `compare_clients` (erreur si < 2 clients, erreur si
  reference inconnue, reference par defaut = premier client, un
  `ClientReport` par client, regression detectee sur un client avec
  perte, aucun ecart si comportement identique), agregation de
  signature DHCP/SIP, sortie console (`capsys`), export CSV
  (`tmp_path`). **325/325 au total.**
- `ruff check .` : 1 erreur preexistante trouvee (`RUF019` dans
  `test_json_report.py`, dette residuelle de Session 12/13, jamais
  passee dans un vrai `ruff` faute d'acces reseau a l'epoque — pas liee
  a ce module). `ruff check`/`ruff format --check` cibles sur les
  fichiers de cette session (`client_diff.py`, `cross_capture_analyzer_cli.py`,
  `netcross_core/__init__.py`, `test_client_diff.py`) : propres sans
  correction.
- `PYTHONPATH=src lint-imports` : contrat de couches respecte (`54`
  fichiers analyses, `127` dependances, 0 cycle).
- `pre-commit run --all-files` (reel, pas simule) : `ruff`/`ruff-format`
  ont corrige automatiquement les 2 dernieres scories preexistantes
  (`report_text.py` : ligne > 120 caracteres reformattee ; `test_json_report.py` :
  `RUF019` corrige en `dict.get`) — corrections gardees (pur `ruff --fix`/
  `format`, aucun changement de comportement, coherent avec la discipline
  du projet de toujours livrer sur un `pre-commit run --all-files`
  entierement vert). Deuxieme execution de `pre-commit run --all-files`
  confirmee verte sur les 3 hooks. Suite complete rejouee une derniere
  fois apres ces corrections incidentes : toujours 325/325.
- **Rejeu de bout en bout contre un vrai `tshark 4.2.2` et de vrais pcap
  scapy** (premiere fois pour une fonctionnalite de ce projet depuis la
  Session 11) : deux pcap generes via `scapy` (`IP()/TCP()`, pas de
  `load_contrib` necessaire pour ce scenario simple) — un flux "PosteA"
  (10.0.0.5) present aux 2 points de capture (A et B), un flux "PosteB"
  (10.0.0.12) present seulement au point A. Rejoue via le vrai CLI :

  ```
  python3 cross_capture_analyzer_cli.py \
      --capture A=capA.pcap --capture B=capB.pcap --order A,B \
      --client-group PosteA=10.0.0.5 --client-group PosteB=10.0.0.12 \
      --client-reference PosteA --client-diff-csv client_diff.csv
  ```

  Resultat : PosteA (reference) sans ecart, PosteB correctement signale
  `[REGRESSION] [Pertes] B : taux de pertes 0.0% (0/1) -> 100.0% (1/1)`
  plus un ecart `a_verifier` sur la latence (plus d'echantillon cote
  PosteB). CSV relu et verifie ligne par ligne (colonnes `client`/
  `reference`/`severite`/... conformes). Verifie egalement les 3 chemins
  d'erreur CLI (`--client-group` unique, `--client-reference` inconnu,
  `--client-reference` sans `--client-group`) : tous les 3 sortent avec
  le message attendu et un code de sortie non nul.
- `python -m compileall` propre sur tout `src/` et `tests/`.

### Limite non resolue dans cette passe

**Pas d'auto-detection de client par IP** (voir "Decision de conception
assumee" ci-dessus) : le groupement `--client-group` doit toujours etre
fourni explicitement. Une heuristique d'auto-detection (par exemple : IP
source la plus frequente hors des IP connues comme "point de capture"
ou "serveur") resterait a concevoir et documenter specifiquement si le
besoin se confirme sur le terrain — pas traitee ici pour eviter un choix
par defaut hasardeux.

### Fichiers de suivi/documentation mis a jour

- **`FEATURES.md`** : nouvelle sous-section "Comparaison client vs
  client (Session 14)" en section 4 (juste avant la sous-section DNS de
  la Session 13) ; nouvelle sous-section `netcross_core.client_diff`
  en section 2 ; diagramme de classes mermaid (section 3) : nouvelles
  classes `ClientSignature`/`ClientReport`/`ClientComparisonResult`/
  `client_diff_mod` et leurs relations ; section CLIs mise a jour avec
  les 3 nouveaux flags ; section 5.1 (ligne "Comparaison client vs
  client" deplacee de 5.2 vers 5.1, "deja fait") ; section 5.2 (ligne
  "Comparaison client vs client" retiree, desormais dans 5.1).
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouveau bullet "compare des clients entre eux" dans
  "Ce que fait l'outil", nouvelle sous-section "Comparer des clients
  entre eux" dans "Utilisation" avec exemple de commande complet.

### Non traite dans cette passe

- **Integration PDF/JSON/GUI** pour la comparaison client vs client —
  vrai travail d'integration (pas un simple cablage generique comme pour
  PMTUD/DNS), voir "Ce qui a ete livre" ci-dessus pour le detail.
- **`--client-group` sur `cross_capture_diff_cli.py`** — combiner client
  vs client et avant/apres n'a pas de design tranche, question ouverte.
- **Auto-detection de client par IP** — decision de conception assumee,
  voir "Limite non resolue" ci-dessus.
- **Score de confiance/`sample_size`, validation CAPWAP sur vraie
  capture, gestion memoire grosses captures** — candidats 🟠 restants,
  aucun traite ici, une feature a la fois.

