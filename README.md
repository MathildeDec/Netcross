# netcross

**Analyse croisée de captures Wireshark multi-points pour le dépannage réseau.**

Corrèle plusieurs captures `.pcap`/`.pcapng` prises simultanément en différents
points d'un chemin réseau (2, 4, 9... points) pour localiser précisément où un
problème apparaît — pertes, latence, changement de QoS, saturation, fragmentation,
tunnels, DHCP, SIP, DNS, HTTP, RTP — plutôt que de deviner à partir d'une capture unique.

Auteur : **Mathilde Deuscher**

---

## Sommaire

- [Ce que fait l'outil](#ce-que-fait-loutil)
- [Solutions de capture prises en charge](#solutions-de-capture-prises-en-charge)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Qualité de code](#qualité-de-code)
- [Architecture du dépôt](#architecture-du-dépôt)
- [Construire les paquets .deb / .rpm](#construire-les-paquets-deb--rpm)
- [Limites connues](#limites-connues)
- [Licence](#licence)

---

## Ce que fait l'outil

À partir de N captures prises à des points différents du réseau (avec ou sans
ordre connu à l'avance), `netcross` :

- **déduit automatiquement l'ordre et la topologie** du chemin réseau (delta de
  TTL + recouvrement de flux entre points), y compris les cas de branchement
  (ECMP, load-balancing) et de convergence — sans qu'il soit nécessaire de
  connaître le chemin physique à l'avance ;
- détecte les **pertes de paquets**, en attribuant chaque perte au bon segment
  du réseau (et sait reconnaître un flux qui a légitimement pris une autre
  branche plutôt que de le compter comme perdu) ;
- mesure la **latence et la gigue** par segment, avec estimation du décalage
  d'horloge entre points (formule NTP via les handshakes TCP) quand les
  machines de capture ne sont pas synchronisées ;
- détecte les **sauts de routeur** et les changements de route (TTL instable,
  chemins ECMP) ;
- corrèle les **changements de marquage QoS (DSCP/802.1p)** avec le TTL pour
  distinguer un remarquage fait par un switch (L2) d'un remarquage fait par un
  routeur (L3) ;
- identifie la **fragmentation IP** apparue en cours de route et la relie à un
  éventuel tunnel qui réduit le MTU disponible ;
- détecte les **noirs PMTUD** (RFC 1191 IPv4 / RFC 8201 IPv6) : segment TCP
  de taille significative retransmis plusieurs fois sur un segment sans
  jamais atteindre le point suivant, et sans qu'aucun signal ICMP(v6) de
  MTU insuffisant (*Fragmentation Needed* côté IPv4, avec bit `DF` actif
  requis ; *Packet Too Big* côté IPv6, où la fragmentation par un routeur
  intermédiaire n'existe de toute façon pas) ne remonte jusqu'à l'émetteur
  — signature d'un pare-feu qui filtre l'ICMP(v6) nécessaire à la
  découverte du MTU, laissant la connexion stagner indéfiniment plutôt que
  d'échouer proprement ;
- détecte les **coupures NAT/pare-feu silencieuses** : une connexion TCP
  déjà établie des deux côtés d'un segment, dont le trafic s'interrompt
  plus longtemps qu'un silence applicatif normal (60s), puis reprend côté
  amont sans jamais atteindre l'aval — signature d'une table d'état
  NAT/pare-feu purgée pendant l'inactivité, sans le moindre RST pour
  prévenir client ou serveur ;
- détecte les **conflits d'adresse IP** via le trafic ARP observé : deux
  adresses MAC différentes qui revendiquent la même adresse IP sur un
  même point de capture — double affectation statique, ou bascule d'IP
  flottante VRRP/HA en cours de capture ;
- détecte l'**instabilité STP** : tempêtes de changements de topologie
  (notifications TCN ou bit de changement de topologie actif) et
  réélections répétées du pont racine — signatures classiques d'une
  boucle de commutation ou d'un lien qui bascule de façon répétée ;
- diagnostique le **certificat TLS** présenté lors d'un handshake :
  détecte un certificat hors de sa fenêtre de validité (déjà expiré, ou
  pas encore valide) et une substitution de certificat entre deux points
  de capture pour une même connexion — signature possible d'une
  interception/substitution TLS en cours de chemin ;
- analyse le **débit** par point et corrèle les pertes avec la charge pour
  distinguer saturation progressive, limitation nette (policing) et pertes
  sans lien avec le débit (indice de bufferbloat inclus) ;
- surveille la **fenêtre TCP, les ACK dupliqués, les RST injectés localement**
  (indice de filtrage actif par un pare-feu/IPS) et les **handshakes SYN sans
  réponse** ;
- classe chaque **retransmission TCP par cause probable** (rapide/3 ACK
  dupliqués, timeout/RTO, ou inutile/déjà acquittée) en lisant directement
  la classification native de tshark — une récupération rapide est un
  signe de bon fonctionnement, un timeout ou un renvoi inutile méritent
  un regard (minuteur mal calibré, chemin de retour ACK asymétrique) ;
- vérifie que les **options TCP négociées au handshake (MSS, Window
  Scale, SACK Permitted)** arrivent intactes d'un bout à l'autre du
  chemin — un MSS réduit en route est souvent une adaptation normale
  (tunnel/VPN), mais une option Window Scale ou SACK retirée par un
  équipement plafonne la fenêtre TCP effective ou dégrade la récupération
  de perte ;
- décapsule et analyse le trafic réel à travers des **tunnels MPLS, GRE,
  VXLAN, GTP-U, ERSPAN et CAPWAP** (WiFi Aruba/Cisco côté filaire) ;
- décompose une transaction en **temps réseau vs temps de traitement
  serveur** pour trancher entre ralentissement réseau et ralentissement
  applicatif ;
- suit les transactions **DHCP** (DISCOVER/OFFER/REQUEST/ACK/NAK) et les
  appels **SIP** (INVITE→200→ACK, échecs, User-Agent/Server) ;
- suit les transactions **DNS** entre points de capture : requête/réponse
  manquante sur un segment, requête sans aucune réponse observée nulle
  part (timeout ou serveur/résolveur injoignable), réponses NXDOMAIN et
  **SERVFAIL** (échec de résolution côté serveur — souvent pris à tort
  pour un problème réseau), et durée moyenne de résolution ;
- suit les transactions **HTTP/1.x** entre points de capture (même
  principe que DNS) : requête/réponse manquante sur un segment, requête
  sans aucune réponse observée nulle part, réponses d'erreur **4xx**
  (info, souvent légitime côté client) et **5xx** (anomalie, échec
  serveur/applicatif — souvent pris à tort pour un problème réseau, avec
  quelques exemples concrets méthode+URI+code), et durée moyenne de
  réponse (calculée nativement par tshark, pas recomposée à la main) ;
  HTTP/2 et HTTP/3 (QUIC) ne sont pas couverts par cette section ;
- calcule la **qualité vocale (MOS/R-factor)** sur les flux RTP détectés ;
- diagnostique les **handshakes TLS** par segment (SNI, cipher négocié,
  alertes fatales) et localise où un handshake qui aboutissait se met à
  échouer (indice d'inspection TLS/pare-feu sur SNI) ;
- extrait le **SNI des paquets QUIC/HTTP3 Initial** (v1, RFC 9001) en
  levant la protection d'en-tête et en déchiffrant l'AEAD avec les clés
  initiales (dérivation publique, pas un secret de session) — utile pour
  voir la visio moderne (Meet, Teams...) qui passe de plus en plus par
  QUIC plutôt que par du RTP classique ;
- **compare deux jeux de captures avant/après** (correctif, changement de
  config, site A vs site B) et ne remonte que les régressions/améliorations
  significatives, avec code de sortie exploitable en CI ;
- **compare des clients entre eux sur la même capture** (« ce poste
  fonctionne, pas l'autre ») : regroupe les paquets par IP de poste
  (`--client-group`), relance l'analyse séparément pour chaque client puis
  diffe chaque client contre un client de référence — troisième axe de
  comparaison, orthogonal au chemin réseau (point A vs point B) et au temps
  (avant vs après) ; enrichi des signatures déjà partiellement captées
  (vendor DHCP, User-Agent SIP) pour distinguer un écart réseau d'une
  version logicielle différente ;
- **triage inter-catégories** : un segment où plusieurs types d'anomalies
  convergent (RST + QoS + fragmentation en même temps, par exemple) remonte
  en tête plutôt qu'un simple tri par nombre brut de constats ; condensé en
  un **score de santé synthétique (0-100)** pour une lecture en un coup
  d'œil (console, JSON, badge coloré en tête du PDF) ;
- génère un **rapport PDF** (synthèse à seuils, graphiques, diagramme de
  topologie) ou un **export JSON structuré** (constats, triage, score de
  santé, diagnostics TLS/QUIC) pour l'intégration externe (dashboard,
  ticketing), et propose une **interface GTK4** en plus du CLI ;
- **anonymise les adresses IP/MAC** (`--redact`) avant l'analyse, pour
  partager un rapport ou une capture sans exposer l'adressage réel
  (support vendeur, ticket externe) ;
- **conserve un historique inter-runs** (`--history-db`, base SQLite
  locale) : score de santé et constats par sévérité de chaque run,
  pour suivre une tendance dans le temps (contrôle périodique du même
  lien) plutôt qu'un seul instantané.

Tout est fait pour être **automatique** : les protocoles applicatifs (RTP,
DHCP, SIP, DNS, HTTP, tunnels) sont détectés directement dans le contenu
des paquets, sans configuration préalable.

---

## Solutions de capture prises en charge

`netcross` analyse des fichiers `.pcap`/`.pcapng` déjà enregistrés — il ne
capture rien lui-même. La qualité du résultat dépend entièrement de la façon
dont ces captures ont été prises. Voici les méthodes courantes, leurs
avantages/inconvénients, et ce qu'il faut savoir pour bien les utiliser avec
cet outil.

### 1. Port miroir / SPAN (switch)

La méthode la plus accessible : on configure un port du switch pour qu'il
reçoive une copie du trafic d'un ou plusieurs autres ports/VLAN, et on y
branche une machine qui capture avec `tcpdump`/`dumpcap`.

```bash
# sur la machine de capture branchee sur le port SPAN
sudo tcpdump -i eth0 -w capture_pointA.pcapng -s 0
```

- **Avantages** : pas de matériel supplémentaire, disponible sur la plupart
  des switchs manageables.
- **Limites à connaître** : un port SPAN peut lui-même saturer et dropper si
  le trafic agrégé dépasse sa capacité (donc *perdre* des paquets qui n'ont
  jamais été perdus sur le vrai lien) ; il ne restitue généralement pas les
  trames en erreur L1/L2. À interpréter avec prudence si l'outil signale des
  pertes uniquement au point SPAN et nulle part ailleurs.

### 2. TAP réseau (matériel passif)

Un boîtier physique inséré en coupure sur le lien, qui duplique le signal
électrique/optique sans y participer activement. Plus fidèle qu'un SPAN,
notamment pour les erreurs physiques et en cas de lien déjà saturé.

- **Avantages** : capture exhaustive, aucun risque de saturation du miroir,
  restitue les trames que le SPAN peut avaler.
- **Limites** : nécessite d'insérer un boîtier physique (coupure de service
  au moment de l'installation), un TAP par lien à observer.

### 3. Capture directe sur l'hôte (client ou serveur)

`tcpdump`/`dumpcap` lancé directement sur la machine cliente ou serveur
concernée.

```bash
sudo tcpdump -i any -w capture_serveur.pcapng -s 0 host 10.0.1.10
```

- **Avantages** : simple, pas de matériel, donne le point de vue exact d'un
  des deux bouts de la communication (utile pour la décomposition temps
  réseau/temps serveur, section correspondante du rapport).
- **Limites** : la charge CPU de la capture elle-même peut légèrement
  influencer la machine observée sur des liens très chargés ; ne montre pas
  ce qui se passe *avant* d'arriver sur cette machine.

### 4. Capture distante via SSH

Utile quand on ne peut pas facilement récupérer un fichier depuis une machine
distante (équipement sans accès direct, capture ponctuelle) :

```bash
ssh user@routeur "tcpdump -i eth0 -w - -s 0" > capture_routeur.pcapng
```

### 5. Environnements virtualisés (hyperviseur)

- **VMware (vSphere/ESXi)** : port mirroring sur un vSwitch distribué (dvPort
  group en mode "promiscuous" ou politique de port mirroring dédiée).
- **Proxmox / KVM/libvirt** : mise en promiscuité de l'interface bridge
  (`ip link set br0 promisc on`) ou capture directe sur l'interface `tap`
  correspondant à la VM, depuis l'hyperviseur.
- **Avantages** : capture au plus près de la VM sans agent dedans ; utile pour
  voir le trafic est-ouest entre VM du même hyperviseur, invisible depuis un
  SPAN physique.

### 6. Miroir de trafic dans le cloud

- **AWS** : VPC Traffic Mirroring (copie vers une instance ou un load
  balancer Gateway Load Balancer).
- **Azure** : Virtual Network TAP (vTAP) ou Network Watcher.
- **GCP** : Packet Mirroring.

Ces solutions produisent en général du trafic encapsulé (VXLAN le plus
souvent côté AWS) — `netcross` décapsule VXLAN nativement, donc ces captures
sont directement exploitables une fois exportées en `.pcap`.

### 7. Côté contrôleur WiFi (Aruba, Cisco) — trafic client via CAPWAP

Pour analyser le trafic d'un client WiFi, capturer sur le lien filaire entre
le point d'accès et le contrôleur (CAPWAP, UDP/5247). Si le canal data n'est
pas chiffré par DTLS, `netcross` décapsule automatiquement et analyse le
trafic client réel (voir [Limites connues](#limites-connues) pour la
couverture exacte de ce module). Pour de l'analyse RF pure (retries radio,
RSSI, roaming), il faut une capture en mode moniteur dédiée — hors périmètre
de cet outil, qui travaille sur du trafic filaire encapsulé.

### Bonnes pratiques communes à toutes ces méthodes

- **Synchroniser les horloges** (NTP, idéalement PTP) sur toutes les machines
  de capture *avant* de commencer — sans ça, seule la latence corrigée
  (estimée via les handshakes TCP) reste exploitable, pas la latence brute.
- **Ne pas tronquer les paquets** : `tcpdump -s 0` / `dumpcap` sans snaplen
  réduit — un payload tronqué empêche la détection RTP/DHCP/SIP/DNS et la
  corrélation tolérante au NAT.
- **Désactiver les offloads NIC** avant capture
  (`ethtool -K eth0 gro off lro off tso off gso off`) pour voir les vrais
  paquets tels qu'ils circulent sur le câble, pas ceux reconstruits par le
  pilote.
- **Format pcapng** avec horodatage nanoseconde plutôt que pcap classique
  (microseconde), utile dès que les points de capture sont proches et donc la
  latence entre eux très faible.
- **Documenter l'emplacement physique** de chaque capture au moment de la
  prise — l'outil déduit l'ordre logique automatiquement, mais ne peut pas
  deviner à quel équipement physique correspond chaque point.
- Si un **NAT/PAT** est traversé entre deux points de capture, utiliser
  `--nat-tolerant` (corrélation par empreinte de payload plutôt que par
  IP/port).

---

## Installation

### Rapide (Debian/Ubuntu/Rocky/RHEL)

```bash
git clone <url-du-depot> netcross
cd netcross
./install.sh              # CLI + interface graphique GTK4
./install.sh --cli-only   # CLI et rapport PDF seulement, sans GTK4
```

### Paquet système (.deb / .rpm)

Voir [Construire les paquets .deb / .rpm](#construire-les-paquets-deb--rpm).
Installe les commandes `netcross`, `netcross-diff`, `netcross-history`
et `netcross-gui` directement dans `/usr/bin`.

### Manuelle (pip)

```bash
pip install -r requirements.txt
# l'interface GTK4 necessite en plus les paquets systeme python3-gi et
# gir1.2-gtk-4.0 (Debian/Ubuntu) ou python3-gobject et gtk4 (RHEL/Rocky)
```

---

## Utilisation

### CLI

```bash
python3 src/cross_capture_analyzer_cli.py \
    --capture LAN=capture_lan.pcapng \
    --capture WAN=capture_wan.pcapng \
    --capture DC=capture_datacenter.pcapng \
    --pdf-report rapport.pdf
```

`--order` est **optionnel** : sans lui, l'ordre et la topologie (y compris
les branchements/convergences) sont déduits automatiquement à partir du TTL
et du recouvrement de flux entre points. Le fournir permet de valider cet
ordre déduit (l'outil signale toute incohérence).

Options utiles :
- `--nat-tolerant` : corrélation par empreinte de payload si un NAT est
  traversé entre deux points.
- `--capture NOM=chemin1,chemin2,...` : plusieurs fichiers séparés par
  des virgules pour un même point rejouent une capture segmentée
  (rotation `tcpdump -C`/`tshark -b`) comme un seul point continu, sans
  fusion préalable (`mergecap` ou autre) — à lister dans l'ordre
  chronologique. Fonctionne aussi avec `--parallel` (un processus
  `tshark` par segment). Même syntaxe sur `--baseline`/`--current` du
  CLI de comparaison ci-dessous.
- `--bucket-ms` : largeur des fenêtres temporelles pour le débit et la
  corrélation pertes/saturation (défaut 1000ms, réduire pour des
  microbursts).
- `--rtp-clock-rate` : cadence d'horloge RTP (8000Hz voix par défaut, 90000
  pour de la vidéo).
- `--idle-timeout-seconds` : seuil (en secondes) au-delà duquel un silence
  entre deux paquets consécutifs d'une connexion TCP déjà établie est
  signalé comme un timeout d'inactivité / coupure NAT-FW silencieuse
  (défaut : 60.0, valeur de `analyse(idle_timeout_seconds=None)`). Même
  option disponible sur le CLI de comparaison ci-dessous.
- `--parallel` : lit les fichiers de capture en parallèle (un processus par
  fichier). Gain réel dépendant du nombre de cœurs CPU disponibles — sur un
  hôte à un seul cœur, aucun gain et léger surcoût plutôt qu'une
  accélération (mesuré, voir [Limites connues](#limites-connues)) ;
  `--parallel-workers` au-delà du nombre de cœurs détectés dégrade encore
  la situation (sur-souscription). Les deux CLI avertissent explicitement
  dans ces deux cas.
- `--detail-csv` : export du détail par flux.
- `--triage` : classement des segments par convergence de plusieurs
  catégories de constats ("par où commencer ?"), aussi inclus automatiquement
  en tête du rapport `--pdf-report`. `--triage-top-n` regle le nombre de
  segments affiches (defaut 5). Affiche aussi un **score de santé
  synthétique (0-100)** condensant la même évidence en un seul chiffre
  (également inclus dans `--json-report` et en badge coloré en tête du
  rapport `--pdf-report`). Sous chaque constat qui en porte une, affiche
  aussi les **preuves brutes** ayant mené à ce constat (exemples déjà
  collectés pendant l'analyse — segment TCP, échange DHCP/DNS/HTTP/SIP
  manquant, etc., voir "preuves" ci-dessous).
- `--tls` / `--quic` : diagnostics TLS et QUIC/HTTP3 sur les mêmes fichiers
  passés à `--capture` (`--quic` nécessite `cryptography` ; pipeline de
  décodage indépendant de celui utilisé pour le reste de l'analyse mais
  passant lui aussi par tshark, voir `netcross_core/tls_diagnostics.py`
  et `quic_diagnostics.py`). Combinés à `--pdf-report`, ces diagnostics
  sont aussi integres au rapport PDF (section dediee + triage global).
- `--live LABEL:INTERFACE[:FILTRE_BPF]` : capture en direct sur une
  interface reseau plutot que sur des fichiers deja captures (repetable
  pour plusieurs points simultanes). S'arrete sur Ctrl+C ou
  `--live-duration SECONDES`. Mutuellement exclusif avec
  `--capture`/`--parallel`/`--tls`/`--quic` (mêmes limitations que le
  mode live de la GUI). Necessite les memes droits que tshark en direct
  (root, ou capacites `CAP_NET_RAW`/`CAP_NET_ADMIN` sur `dumpcap`).
- `--json-report chemin.json` : export JSON structuré (points, constats,
  triage, diagnostics TLS/QUIC si `--tls`/`--quic` sont fournis) pour
  l'intégration externe (dashboard, ticketing, script d'analyse). Aucune
  dépendance supplémentaire (contrairement à `--pdf-report`) — toujours
  disponible. Chaque constat qui a une preuve rattachée (voir `--triage`
  ci-dessus) porte une clé `evidence` (liste de `{"point": ..., "text":
  ...}`) — absente sinon, comme `sample_size`. Sur la catégorie PMTUD
  uniquement (pilote, voir "preuves" ci-dessous), chaque ligne de preuve
  porte aussi une clé `frame_number` quand le numéro de trame tshark du
  paquet représentatif est connu. Expose aussi cinq clés supplémentaires
  (objets de contrat de la comparaison OmniPeek/Wireshark, voir
  `docs/features-backlog.md` section 13.3 "Session 0") : `flows` (un flux par entrée,
  agrégation multi-points déjà calculée par la corrélation), `conversations`
  (regroupement par paire d'adresses), `expert_events` (vue générique des
  constats, `cause`/`impact` toujours `null` — le moteur de corrélation
  causale n'existe pas encore), `diagnoses` (regroupement des
  `expert_events` par segment), `compliance` (statut `CONFORME`/
  `VIOLATION`/`INDETERMINE` contre 2 référentiels par défaut : absence de
  noir PMTUD, taux de perte ≤ 1%). Une sixième clé, `wireshark_expert_events`
  (Session 1 de la même section 13.3, "exploitation de l'expertise
  Wireshark/TShark"), porte les signaux d'expertise BRUTS déjà produits
  par tshark lui-même (retransmissions, ACK dupliqués, fenêtre nulle...),
  regroupés par point et par type de signal, sur **toutes les couches**
  du paquet (pas seulement TCP) — jamais fondus dans `expert_events`
  ci-dessus (`source` vaut `"tshark"` ici contre `"netcross"` pour
  `expert_events`) : ce sont des preuves supplémentaires brutes, pas des
  diagnostics Netcross. La sévérité de chaque entrée reflète la sévérité
  NATIVE tshark quand elle est disponible (`Error`/`Warning`/
  `Note`/`Chat`/`Comment` traduits vers `anomalie`/`a_surveiller`/`info`),
  avec repli sur une table interne pour les flags déjà connus de ce
  projet sinon ; chaque ligne de `evidence` inclut le message natif
  tshark quand il est disponible, en plus des adresses et du libellé.
  Chaque entrée `wireshark_expert_events` porte aussi trois clés
  supplémentaires (Session 2 de la section 13.3, "moteur d'événements
  d'expertise", premier lot) : `confidence` (0.0 à 1.0 — 1.0 si la
  sévérité est native tshark, 0.7 si le flag est seulement connu de la
  table interne, 0.4 sinon), `first_seen`/`last_seen` (timestamps du
  premier et du dernier paquet ayant produit ce signal, calculés sur la
  totalité des occurrences). Deux clés de plus (deuxième lot de la même
  Session 2) : `layer` (couche OSI — `"liaison"`/`"reseau"`/
  `"transport"`) et `protocol` (`"ARP"`/`"STP"`/`"IPv4"`/`"IPv6"`/
  `"ICMP"`/`"ICMPv6"`/`"TCP"`/`"UDP"`), lus directement depuis le
  préfixe du nom de flag EK brut ayant produit le signal — pas une
  déduction. Trois clés de plus, ajoutées dans des lots successifs de la
  même Session 2 : `flow_keys` (troisième lot — liste des flux concernés
  au sens exact de `netcross_core.correlate.flow_key()`, calculée sur la
  totalité des occurrences et dédoublonnée, chaque élément une liste
  `[proto, src, sport, dst, dport, key_id]` directement comparable à la
  clé `flows`/`conversations` ci-dessus) et `packet_evidence`
  (quatrième lot — liste **complète** des paquets porteurs du signal,
  chaque élément `{"point": ..., "frame_number": ...}`, calculée elle
  aussi sur la totalité des occurrences : contrairement à `evidence`
  ci-dessus, plafonnée à 5 exemples, `packet_evidence` n'omet aucune
  occurrence — utile pour rouvrir le pcap source directement sur chaque
  paquet concerné, pas seulement les cinq premiers). Une dernière clé,
  `remediation` (cinquième et dernier lot de la Session 2, action de
  vérification/remédiation) : piste de vérification technique **rédigée**
  (pas calculée), disponible uniquement pour les onze flags EK déjà
  répertoriés par ce projet (retransmissions, ACK dupliqué, fenêtre
  nulle/pleine, keep-alive, hors séquence, ports réutilisés...) —
  `null` pour tout autre flag EK (y compris les flags de suivi de
  connexion TCP comme `tcp.completeness`) plutôt qu'un conseil générique
  inventé sans connaître la nature exacte du signal. Ces huit clés
  (`confidence`/`first_seen`/`last_seen`/`layer`/`protocol`/`flow_keys`/
  `packet_evidence`/`remediation`) valent toujours `null`/`[]` sur
  `expert_events`/`diagnoses` (source `"netcross"`) : un `Finding`
  Netcross ne porte aujourd'hui aucune notion de confiance, de
  timestamp, de couche, de protocole, de flux, de liste complète de
  paquets calculée ni de bibliothèque de remédiation par catégorie —
  voir `netcross_core.expert_model.ExpertEvent`.
- `--topn-charts N` : nombre de catégories affichées par graphique dans
  la section "Évolution temporelle (top-N)" du rapport `--pdf-report`
  (défaut 5, le reste des catégories est regroupé sous "autres"). Quatre
  graphiques (protocole / port de destination / IP de destination /
  marquage DSCP), tracés pour un seul point de capture (le premier de
  `--order`/`--capture`) — superposer plusieurs points de capture sur la
  même aire empilée compterait certains paquets en double, un même
  paquet physique pouvant être vu à plusieurs points. Sans effet sans
  `--pdf-report`.
- `--redact` : anonymise les adresses IP (plages de documentation RFC
  5737/3849) et MAC (OUI localement administré) avant l'analyse, avec un
  mapping cohérent sur tout le run — pour partager un rapport (ou une
  capture) sans exposer l'adressage réel (ticket support vendeur, rapport
  transmis à un tiers). Ne couvre que les *adresses* : noms DNS/URI HTTP/
  SAN de certificat TLS/identifiants SIP restent inchangés (voir
  `netcross_core/redact.py` pour le détail du périmètre). Mutuellement
  exclusif avec `--tls`/`--quic`/`--client-group`, qui accèdent aux
  adresses réelles indépendamment de cette anonymisation (relecture de
  fichier ou argument direct). `--redact-map chemin.csv` conserve la
  correspondance adresse réelle ↔ pseudonyme dans un fichier **local, à
  ne jamais transmettre avec le rapport**.
- `--history-db chemin.db` : enregistre un résumé de ce run (score de
  santé, nombre de constats par sévérité) dans une base SQLite locale,
  créée si absente — pour suivre une tendance dans le temps sur des runs
  successifs (ex : contrôle hebdomadaire du même lien). Ne remplace pas
  `--json-report`/`--pdf-report`/`--detail-csv` (détail complet d'un run
  donné) : l'historique ne conserve qu'un résumé compact par run.
  `--history-label étiquette` distingue plusieurs historiques qui
  partagent le même fichier `.db` (plusieurs sites suivis dans la même
  base). `--history-show [N]` affiche après l'analyse les N derniers
  runs enregistrés (défaut 10), filtré automatiquement sur
  `--history-label` si elle est fournie. `--history-label`/
  `--history-show` nécessitent `--history-db`.

### Comparer des clients entre eux (« ce poste fonctionne, pas l'autre »)

```bash
python3 src/cross_capture_analyzer_cli.py \
    --capture LAN=capture_lan.pcapng \
    --capture WAN=capture_wan.pcapng \
    --client-group PosteA=10.0.0.5 \
    --client-group PosteB=10.0.0.12,10.0.0.13 \
    --client-reference PosteA \
    --client-diff-csv client_diff.csv
```

Regroupe les paquets de la **même capture** par poste (IP source ou
destination) plutôt que par point de capture, relance l'analyse pour
chaque client séparément, puis compare chaque client au client de
référence (`--client-reference`, par défaut le premier `--client-group`
fourni). Un client peut avoir plusieurs IP (`IP1,IP2,...`, cas
multi-IP/DHCP) ; `--client-group` est répétable et nécessite au moins 2
clients. Additif à l'analyse principale ci-dessus (n'affecte pas
`--triage`/`--tls`/`--quic`/`--pdf-report`/`--json-report`, qui restent
calculés sur l'ensemble des captures sans distinction de client).
`--client-diff-csv` exporte le détail des écarts par client.

### Comparer deux captures (avant/après)

```bash
python3 src/cross_capture_diff_cli.py \
    --baseline LAN=avant_lan.pcapng --baseline WAN=avant_wan.pcapng \
    --current  LAN=apres_lan.pcapng --current  WAN=apres_wan.pcapng \
    --triage --tls --quic \
    --pdf-report diff.pdf
```

Réutilise les mêmes noms de point des deux côtés (`LAN`, `WAN`...) pour
permettre la comparaison point par point. Renvoie un code de sortie non nul
si au moins une régression est détectée — exploitable directement en CI.
`--diff-csv` exporte le détail des écarts, `--pdf-report` génère un rapport
PDF dédié (triage + synthèse + table des écarts).

Options supplémentaires (parité avec `cross_capture_analyzer_cli.py`) :
- `--idle-timeout-seconds` : même seuil que sur `cross_capture_analyzer_cli.py`
  ci-dessus, appliqué aux deux scénarios (baseline et courant).
- `--triage` / `--triage-top-n` : même classement par convergence de
  catégories que sur l'analyzer, calculé sur les écarts (`DiffFinding`) —
  déjà inclus automatiquement en tête de `--pdf-report`, ce flag l'affiche
  aussi sur la sortie console. Affiche aussi le score de santé synthétique
  (0-100) — ici, l'ampleur des régressions détectées entre baseline et
  courant, pas un état absolu (100 = aucune régression significative).
  Sous chaque écart qui en porte une, affiche aussi les **preuves
  brutes** (mêmes catégories câblées que sur l'analyzer — PMTUD, NAT/
  Pare-feu, ARP, STP, TLS, MSS, DNS, HTTP —, toujours issues du rapport
  courant).
- `--tls` / `--quic` : diagnostics exécutés **séparément** sur le baseline
  et sur le run courant (ces deux modules ne connaissent qu'un état à un
  instant donné, pas de vraie diff sémantique possible entre les deux),
  affichés l'un après l'autre en console et dans une section dédiée du
  PDF — comparer les deux à l'œil plutôt que d'y chercher un écart chiffré.
  `--quic` nécessite `cryptography`. Indisponibles avec `--live-current`
  (voir ci-dessous).
- `--json-report chemin.json` : export JSON structuré de comparaison
  (points baseline/courant, écarts, triage, diagnostics TLS/QUIC), même
  principe que sur l'analyzer. Les diagnostics TLS/QUIC y sont exposés
  séparément (`tls_findings_baseline`/`tls_findings_current`/...), pas
  fondus dans les écarts principaux — même raison que dans le PDF.
  Chaque écart qui a une preuve rattachée (voir `--triage` ci-dessus)
  porte lui aussi une clé `evidence`, toujours issue du rapport
  **courant** (jamais du baseline) — absente sinon, comme `sample_size`.
- `--live-current LABEL:INTERFACE[:FILTRE_BPF]` (répétable) : capture en
  direct le run **courant** au lieu de le lire depuis des fichiers —
  mutuellement exclusif avec `--current` (l'un des deux est requis).
  Le **baseline reste toujours un ou plusieurs fichiers** via
  `--baseline` : une référence de comparaison est par nature déjà
  enregistrée, la capturer en direct en parallèle n'aurait pas de sens
  et n'a pas de précédent côté GUI (mode comparaison et capture live y
  sont mutuellement exclusifs). `--live-duration` fixe une durée max
  optionnelle (sinon Ctrl+C). Mutuellement exclusif avec
  `--parallel`/`--tls`/`--quic` (mêmes limitations assumées que `--live`
  sur `cross_capture_analyzer_cli.py`). Exemple :
  ```bash
  python3 src/cross_capture_diff_cli.py \
      --baseline LAN=avant_lan.pcapng \
      --live-current LAN:eth0 \
      --live-duration 60 \
      --triage --diff-csv regressions.csv
  ```
- `--redact` / `--redact-map` : même anonymisation que sur
  `cross_capture_analyzer_cli.py` (voir ci-dessus), avec **un seul
  mapping partagé entre baseline et courant** — une adresse réelle
  présente des deux côtés garde le même pseudonyme, sans quoi la
  comparaison perdrait son sens. Même exclusion mutuelle avec
  `--tls`/`--quic` (pas de `--client-group` sur ce CLI).
- `--history-db` / `--history-label` / `--history-show` : même mécanisme
  que sur `cross_capture_analyzer_cli.py` (voir ci-dessus) — un même
  fichier `.db` peut mélanger des runs d'analyse et de comparaison
  (`--history-show` les affiche ensemble, plus récent d'abord).

### Consulter l'historique sans relancer d'analyse

`netcross-history` (`cross_history_cli.py`) interroge une base déjà
alimentée par `--history-db`, sans capture ni comparaison à fournir —
utile pour vérifier une tendance sans avoir de nouvelles captures sous
la main. Aucun prérequis `tshark` : ce script ne lit jamais de capture.

```bash
# tout l'historique d'un fichier
netcross-history --db suivi_site_a.db

# les 10 derniers runs d'un site donne, tous types confondus
netcross-history --db suivi_partage.db --label Site-A --limit 10

# seulement les comparaisons (--run-type diff) d'un fichier partage
netcross-history --db suivi_partage.db --run-type diff
```

- `--db CHEMIN` : seul argument obligatoire. Un chemin qui n'existe pas
  encore n'est pas une erreur : affiche simplement un historique vide.
- `--label ÉTIQUETTE` : ne montre que les runs portant cette étiquette
  exacte (voir `--history-label` ci-dessus).
- `--run-type {analyse,diff}` : ne montre que les runs de ce type.
  Combinable avec `--label`.
- `--limit N` : nombre maximum de runs affichés (défaut : tous), les
  plus récents en premier.

### Interface graphique

```bash
cd src && python3 -m netcross_gtk4.app
# ou, si installe via .deb/.rpm :
netcross-gui
```

Trois pages navigables : Configuration (captures + options), Travail
(journal d'avancement en temps réel), Résultats (rapport + export CSV/PDF).

La GUI propose désormais la lecture parallèle, la déduction automatique de
topologie (case à cocher, équivalent à ne pas passer `--order`), le triage,
les diagnostics TLS/QUIC, l'export CSV du détail par flux, l'export JSON
structuré (bouton "Exporter en JSON", équivalent GUI de `--json-report`,
disponible en mode simple et en mode comparaison), l'anonymisation des
adresses (case "Anonymiser les adresses IP/MAC (--redact)", mutuellement
exclusive avec les diagnostics TLS/QUIC des deux modes), et un **mode
comparaison** (case à cocher en haut de la page Configuration) qui bascule
sur deux listes de captures (Baseline/Courant) et reproduit
`cross_capture_diff_cli.py` — export PDF, CSV et JSON des écarts inclus,
avec ses propres cases TLS/QUIC dédiées au mode comparaison.

Elle propose aussi un **mode capture en direct** (case "Capture en direct") :
un panneau nom/interface/filtre BPF par point plutôt qu'un sélecteur de
fichiers, démarrage/arrêt manuel (ou durée max optionnelle), compteur de
paquets par point mis à jour en direct dans le journal. Mode analyse simple
uniquement (pas de comparaison), TLS/QUIC indisponibles dans ce mode
(nécessitent un fichier à relire, qu'une capture live ne produit pas). Le
"top N" du triage est réglable directement dans la GUI (à côté de la case
"Triage"), équivalent à `--triage-top-n` côté CLI ; le nombre de catégories
affichées par graphique dans le rapport PDF (mode simple) l'est aussi
(spinbutton dédié, équivalent GUI de `--topn-charts`).

**Parité restante avec le CLI** : la capture en direct est désormais
disponible sur les deux CLI — `--live` sur `cross_capture_analyzer_cli.py`
et `--live-current` sur `cross_capture_diff_cli.py` (voir ci-dessus, le
baseline y reste toujours un fichier). La GUI, de son côté, n'expose pas
la capture en direct en mode comparaison (mode comparaison et capture live
y restent mutuellement exclusifs).

---

## Tests

Suite de tests automatisés (`pytest`) couvrant le cœur analytique
(`netcross_core`), la couche de décodage (`pcap_parser`) et la synthèse/
triage (`netcross_report`) — 720 tests, sans dépendance à `tshark`,
`scapy` ni GTK4 (paquets et couches EK construits synthétiquement).

```bash
uv sync --extra dev   # gestionnaire de dependances canonique depuis la Session 55
uv run pytest
# repli sans uv (voir requirements.txt/requirements-dev.txt) :
#   pip install -r requirements.txt -r requirements-dev.txt
#   pytest
```

Non couverts pour l'instant : `netcross_report/charts.py`/`pdf.py`
(rendu matplotlib/reportlab) et `netcross_gtk4/` (interface graphique),
ainsi que l'invocation réelle du sous-processus `tshark` — voir
`docs/sessions/session-06.md` et `docs/features-backlog.md` section 4 pour le détail.

---

## Qualité de code

Lint, formatage et respect de l'architecture en couches sont vérifiés par
[`ruff`](https://docs.astral.sh/ruff/) (lint + format) et
[`import-linter`](https://import-linter.readthedocs.io/) (couches),
orchestrés par `pre-commit` :

```bash
uv sync --extra dev       # gestionnaire de dependances canonique depuis la Session 55
uv run pre-commit install # une fois par clone : active les hooks sur `git commit`
uv run pre-commit run --all-files
# repli sans uv : pip install -r requirements.txt -r requirements-dev.txt
```

- **Lint + format** (`ruff check` / `ruff format`, config dans
  `pyproject.toml`) : `line-length = 120`, cible `py39`, imports absolus
  uniquement (`from .module import ...` est banni — préférer
  `from netcross_core.module import ...`).
- **Architecture en couches** (`PYTHONPATH=src lint-imports`, contrat
  `[tool.importlinter]`) : `netcross_gtk4` peut dépendre de
  `netcross_report`, `netcross_core`, `pcap_parser` ; `netcross_report` de
  `netcross_core`, `pcap_parser` ; `netcross_core` de `pcap_parser` — jamais
  l'inverse, et `pcap_parser` ne dépend d'aucun autre package du projet.

---

## Architecture du dépôt

```
netcross/
├── CLAUDE.md                 etat courant, prochaine feature, commandes qualite
├── install.sh              installation des dependances systeme
├── requirements.txt         installation alternative via pip (repli sans uv)
├── requirements-dev.txt     dependances de developpement, repli sans uv (pytest, ruff, import-linter, pre-commit)
├── pyproject.toml           dependances (uv, Session 55) + config ruff (lint/format) + import-linter (couches)
├── uv.lock                  verrou de dependances uv (Session 55)
├── .pre-commit-config.yaml  hooks pre-commit (ruff, ruff-format, import-linter)
├── pytest.ini               configuration pytest (pythonpath = src)
├── docs/
│   ├── features-backlog.md  fonctionnalites, diagramme de classes, dette, comparaison OmniPeek
│   └── sessions/             historique detaille session par session (session-01.md ... session-41.md)
├── tests/                   suite de tests automatisés (pytest)
├── src/
│   ├── cross_capture_analyzer_cli.py   CLI (argparse)
│   ├── netcross_core/       moteur d'analyse (aucune dependance a une UI)
│   ├── netcross_report/     generation du rapport PDF (synthese, graphiques)
│   └── netcross_gtk4/       interface graphique GTK4
├── build-deb/               packaging Debian/Ubuntu (.deb)
└── build-rpm/                packaging RHEL/Rocky (.rpm)
```

Le suivi de projet est volontairement scindé en trois niveaux de détail
croissant : `CLAUDE.md` (à lire à chaque démarrage), `docs/features-backlog.md`
(fonctionnalités, dette, priorisation — importé depuis `CLAUDE.md` via la
syntaxe `@docs/features-backlog.md`) et `docs/sessions/` (raisonnement et
décisions de conception détaillés session par session, consultés à la
demande plutôt que reparcourus systématiquement).

`netcross_core` ne dépend d'aucune interface : il peut être réutilisé tel
quel dans un autre projet Python (`from netcross_core import parse_capture,
correlate, analyse, print_report`).

---

## Construire les paquets .deb / .rpm

### Debian / Ubuntu

```bash
sudo apt-get install debhelper dpkg-dev
./build-deb/build.sh
sudo apt install ./build-deb/dist/netcross_*.deb
```

### Rocky / RHEL 8 et 9

```bash
sudo dnf install rpm-build
./build-rpm/build.sh
sudo dnf install ./build-rpm/dist/netcross-*.rpm
```

Les deux scripts assemblent une arborescence de build temporaire à partir de
`src/`, appellent l'outil de packaging natif de la distribution, et déposent
le paquet résultant dans `dist/` (à supprimer manuellement après usage —
pas de `.gitignore` dans ce dépôt à ce jour).

**Testé réellement** : le `.deb` a été construit, installé et exécuté de
bout en bout (CLI, rapport PDF, interface GTK4) sur Ubuntu 24.04. Le `.rpm`
a été construit avec succès via `rpmbuild` mais **n'a pas pu être installé
ni exécuté sur une vraie Rocky Linux** (non disponible dans l'environnement
de développement) — la structure du paquet est correcte et cohérente avec
le `.deb`, mais une validation sur un système Rocky 8/9 réel reste à faire
avant un déploiement en production.

---

## Limites connues

- **Captures segmentées (`NOM=chemin1,chemin2,...`)** : les segments sont
  lus dans l'ordre où ils sont listés et simplement concaténés, sans tri
  par timestamp — les lister dans l'ordre chronologique (ordre naturel
  d'une rotation `tcpdump`/`tshark`). Les quelques analyses sensibles à
  l'ordre au sein d'un même point (instabilité STP, timeout d'inactivité)
  trient déjà explicitement en interne, donc un mauvais ordre n'affecte
  que la lisibilité des messages `[LABEL] N paquets... chargés depuis`
  en console, pas la justesse de ces deux détecteurs précis.
- **Détection de pertes sur un segment de branchement** : désactivée
  volontairement (un flux absent sur une branche peut avoir légitimement
  pris l'autre branche — impossible à distinguer d'une vraie perte sans
  information supplémentaire, donc l'outil ne se prononce pas plutôt que de
  se tromper).
- **Graphiques temporels top-N (protocole/port/IP/DSCP)** : un seul point
  de capture tracé par graphique (le premier de `--order`/`--capture`),
  pas de vue combinée multi-points — un même paquet physique pouvant être
  vu à plusieurs points, les additionner gonflerait artificiellement le
  volume affiché. Les catégories `port` et `ip` sont ventilées par
  **destination uniquement** (pas source+destination), pour que la somme
  des catégories d'un point égale exactement son débit total : côté
  retour serveur→client, le port de destination observé est un port
  éphémère qui se disperse dans la longue traîne plutôt que de faire
  ressortir un service — comportement recherché, pas une approximation à
  corriger. Non disponible sur `cross_capture_diff_cli.py` (pas de
  direction de conception évidente pour une comparaison avant/après sur
  ce type de graphique) ni réglable depuis la GUI (nombre de catégories
  toujours à la valeur par défaut, 5, quand le PDF est généré depuis
  l'interface).
- **Gestion mémoire des grosses captures** : le pipeline tient
  entièrement en RAM (pas de streaming multi-passes — la corrélation
  multi-points a besoin d'une vue d'ensemble). Mesuré empiriquement
  (Session 19, vrai `tshark`) : environ **636 octets par paquet** en
  régime établi (`RawPacket`/`Pkt`, objets à emplacements fixes —
  `__slots__` — plutôt que `__dict__`, avec réutilisation du même objet
  `str` pour les valeurs répétées comme les IP/URI/User-Agent). Pic
  mémoire réel du process principal mesuré sur un scénario réaliste à 2
  points de capture, 200 000 paquets chacun : environ **500 Mo** (contre
  1,3 Go avant cette optimisation, sur le même scénario — voir
  `docs/sessions/session-19.md` pour le détail de la mesure). Extrapolation
  approximative : une capture de plusieurs millions de paquets par point
  se compte encore en Go, pas en dizaines de Mo — dimensionner la
  machine d'analyse en conséquence sur de très gros volumes.
- **Fragmentation IPv6** : détectée via l'en-tête d'extension Fragment
  (`ipv6.fragment`, RFC 8200), câblée dans le même compteur générique que
  la fragmentation IPv4 (`--capture`/`--parallel`, comptage par point,
  aucun flag dédié). Limite protocolaire assumée, différente d'IPv4:
  l'identifiant de datagramme (`ipv6.fragment.id`) n'existe QUE sur un
  datagramme déjà fragmenté — un datagramme IPv6 jamais fragmenté n'a
  simplement aucun identifiant à exposer, contrairement à IPv4 où
  `ip.id` est un champ ordinaire toujours présent. Conséquence : la
  détection d'une **nouvelle** fragmentation apparaissant entre deux
  points de capture (« non fragmenté en amont, fragmenté en aval »,
  typiquement un tunnel qui réduit le MTU disponible) ne fonctionne que
  pour IPv4 ; côté IPv6, seule une fragmentation déjà présente aux deux
  points (et partageant le même identifiant 32 bits) est suivie —
  cohérent avec le fait que seule la source fragmente en IPv6, jamais un
  routeur intermédiaire en cours de route.
- **Décodage ICMPv6** (Session 22) : type/code décodés pour tout message
  (`icmpv6.type`/`icmpv6.code`), identifiant/séquence pour Echo
  Request/Reply uniquement (absents des autres types, comme
  `icmp.ident`/`icmp.seq` côté ICMPv4). La valeur de MTU annoncée par un
  message *Packet Too Big* (`icmpv6.mtu`) n'est pour l'instant pas
  conservée — seul son occurrence (type 2) est comptée, au même niveau de
  détail que *ICMP Fragmentation Needed* côté IPv4.
- **Détection de noir PMTUD** : le rapprochement avec le signal ICMP(v6)
  correspondant (*Fragmentation Needed* côté IPv4, *Packet Too Big* côté
  IPv6, RFC 4443 §3.2) se fait sur l'ensemble de la capture au point
  amont, pas sur une fenêtre temporelle précise autour du segment concerné
  (nécessiterait de décoder le paquet IP embarqué dans la charge utile
  ICMP(v6) pour un appariement par flux exact) ; couvre IPv4 et IPv6
  depuis la Session 22 (IPv4 exige un bit `DF` actif sur toutes les
  tentatives observées — un segment sans `DF` n'autorise pas la
  fragmentation en route à être mise en cause ; IPv6 n'a pas de bit
  équivalent, la sémantique « ne pas fragmenter » y étant implicite pour
  tout paquet, voir la fragmentation IPv6 ci-dessus) ; seuil de taille de
  segment (512 octets) fixe, non configurable pour l'instant.
- **Détection de coupure NAT/pare-feu silencieuse** (Session 23) : scope
  volontairement limité à TCP (la notion de session avec établissement/
  silence/reprise n'a de sens direct que pour un protocole avec état) ;
  seuil de silence fixe (60s), non configurable pour l'instant — choisi
  pour être largement au-dessus d'un keepalive TCP applicatif classique
  sans se caler sur le timeout exact d'un équipement précis (non
  documenté par les fabricants, impossible à déduire d'une seule
  capture). N'effectue pas de vérification explicite de l'absence de
  FIN/RST juste avant le silence : une connexion proprement close puis
  suivie bien plus tard d'un paquet résiduel partageant le même 5-tuple
  (réutilisation rapide du même port éphémère, rare) pourrait en théorie
  être confondue avec une coupure silencieuse.
- **Détection de conflit d'adresse IP (ARP)** (Session 24) : aucune
  fenêtre temporelle — deux MAC revendiquant la même IP à n'importe quel
  moment de la capture (même très espacées) sont considérées en conflit,
  sans distinction avec un remplacement matériel légitime au cours d'une
  capture très longue. Ne distingue pas un vrai conflit persistant d'un
  basculement légitime d'IP flottante (VRRP/keepalived, HA de pare-feu) :
  les deux se traduisent de la même façon côté ARP (nouvelle MAC qui
  revendique une IP déjà vue avec une autre) ; distinguer les deux
  demanderait de connaître la configuration réseau (IP virtuelles
  déclarées), hors de portée d'une simple lecture de capture.
- **Détection d'instabilité STP** (Session 25) : le "flapping de port"
  au sens strict (un port de commutateur qui bascule haut/bas de façon
  répétée) n'est pas directement observable depuis une capture réseau —
  cette information vit dans la table d'état interne du commutateur
  (SNMP/syslog), pas sur le fil. Le détecteur observe la conséquence
  visible sur le fil (tempête de changements de topologie, réélections
  de racine) plutôt que la cause exacte (quel port, sur quel
  commutateur) — limite architecturale, pas un oubli. Ne distingue pas
  non plus une tempête causée par une vraie boucle physique d'une
  tempête causée par une autre instabilité de lien (auto-négociation,
  câble défectueux, alimentation PoE instable) : le signal remonte "le
  réseau est instable", pas sa cause racine exacte.
- **Diagnostics de certificat TLS** (Session 26) : n'extrait ni Subject
  ni Issuer (Distinguished Name complet) — tshark les aplatit en `-T ek`
  dans des tableaux positionnels partagés entre toutes les RDN de tous
  les certificats de la chaîne, sans moyen fiable de déterminer par
  position laquelle correspond à quel attribut ; reconstruire cette
  information demanderait `-T json`/`-T pdml` plutôt que le flux EK
  aplati utilisé partout ailleurs dans ce pipeline. Seul le certificat
  feuille (le premier de la chaîne, garanti par RFC 5246 §7.4.2) est
  analysé — pas les certificats intermédiaires/racine. Aucune
  vérification de la chaîne de confiance PKI (autorité, révocation) :
  hors de portée d'une capture passive, qui n'a pas accès au magasin de
  confiance du client. Invisible en TLS 1.3 sans `SSLKEYLOGFILE` : le
  message Certificate y est chiffré par construction (RFC 8446) — limite
  protocolaire, pas contournable par ce projet.
- **Anonymisation (`--redact`, Session 28)** : ne couvre que les
  *adresses* — IP (RFC 5737/3849) et MAC (OUI localement administré) —
  pas les noms : `dns.qry.name`, l'URI/host HTTP, le SAN de certificat
  TLS et les identifiants SIP (`Call-ID`, `User-Agent`, `Server`)
  restent inchangés. Une capture "redigee" peut donc rester identifiante
  via ces canaux — à garder en tête avant tout partage externe. De plus,
  `--redact` est refusé en combinaison avec `--tls`/`--quic`/
  `--client-group` : ces trois options accèdent aux adresses réelles
  indépendamment de la liste de paquets anonymisée (relecture de fichier
  pour `--tls`/`--quic`, argument direct pour `--client-group`) — les
  combiner aurait laissé filtrer des adresses réelles sans le signaler.
  Câblé sur l'interface graphique GTK4 depuis une passe ultérieure (case
  dédiée, même garde-fou mutuellement exclusif avec TLS/QUIC) — voir
  "Interface graphique" ci-dessus (la GUI reste toutefois non couverte
  par les tests automatisés, voir "Tests" ci-dessous).
- **Historique inter-runs (`--history-db`, Session 29)** : ne conserve
  qu'un **résumé** par run (score de santé, nombre de constats par
  sévérité, points, étiquette) — pas le détail des constats eux-mêmes,
  toujours disponible via `--json-report`/`--pdf-report`/`--detail-csv`.
  `--history-show` n'affiche l'historique qu'**après** un run normal,
  jamais à sa place — pour une interrogation seule sans relancer
  d'analyse, voir `netcross-history` ci-dessous (Session 30).
  `record_diff_run` n'intègre pas les diagnostics TLS/QUIC au score
  (même limite assumée que `--json-report`/`--pdf-report` en mode
  comparaison, voir plus haut). Non câblé sur l'interface graphique
  GTK4 (aucun équivalent de `--history-db`/`--history-show` dans
  `netcross_gtk4.app`).
- **`netcross-history` / `cross_history_cli.py` (Session 30)** : pas de
  sortie `--json`/structurée, uniquement le rendu texte console — le
  besoin n'a pas été exprimé dans la piste d'origine, `--json-report`
  sur les deux autres CLI couvre déjà le besoin de sortie structurée
  pour un run donné. Wrapper packagé et **paquet `.deb` réellement
  construit et vérifié** cette session ; le `.spec` RPM correspondant a
  été mis à jour par symétrie mais **n'a pas pu être rejoué** :
  `rpmbuild` est absent de l'environnement de développement utilisé pour
  cette session (voir aussi la note sur le `.rpm` en général,
  ci-dessus/ci-dessous selon la section).
- **Classification des retransmissions TCP** : calculée par tshark
  indépendamment pour chaque fichier de capture (un point = un fichier =
  un processus tshark, sans vue d'ensemble multi-points). La condition
  "retransmission rapide" de tshark exige notamment d'avoir vu le dernier
  ACK il y a moins de 20 ms — un point de capture éloigné de l'émetteur
  (RTT important jusqu'à ce point) peut donc classer différemment une
  même retransmission réelle sur le fil qu'un point plus proche de
  l'émetteur. Comportement de tshark lui-même, pas une approximation
  ajoutée par cet outil.
- **CAPWAP (WiFi Aruba/Cisco)** : decodage delegue au dissecteur CAPWAP natif
  de tshark (RFC 5415), **pas encore verifie contre une vraie capture
  Aruba/Cisco reelle** en conditions terrain. Chiffrement DTLS du canal
  data : non dechiffrable (comportement attendu, signale explicitement dans
  le rapport comme `CAPWAP(chiffre DTLS)` plutot que de planter).
- **DNS** : corrélation par identifiant de transaction (`dns.id`, 16 bits)
  — sur une capture très longue et très chargée en requêtes concurrentes
  vers le même résolveur, une réutilisation d'id avant qu'une transaction
  précédente ne soit terminée n'est pas gérée spécifiquement (les deux
  seraient alors vues comme une seule, à tort ; même limite de principe
  que `dhcp.xid`, sur 32 bits et donc bien moins probable en pratique).
  Une réponse NXDOMAIN est signalée pour information mais n'est pas en
  elle-même une anomalie réseau.
- **HTTP** : HTTP/1.x uniquement (TCP) — HTTP/2 (dissecteur tshark
  distinct) et HTTP/3 (QUIC, voir ci-dessous — SNI uniquement, pas de
  code de statut) ne sont pas couverts par cette section. Faute
  d'identifiant de transaction applicatif comparable à `dns.id`, une
  requête est suivie par connexion TCP + URI ; si la **même** URI est
  rejouée plusieurs fois sur la même connexion (ex : polling d'un
  endpoint de santé) et qu'une occurrence précise est perdue entièrement
  sur un segment, un décalage entre occurrences restantes est possible
  (non géré spécifiquement — cas différent de deux requêtes successives
  sur des URI différentes, qui reste correctement distingué). Une réponse
  4xx est signalée pour information mais n'est pas en elle-même une
  anomalie réseau.
- **QUIC/HTTP3** : seule la v1 (RFC 9001) est gérée ; la dérivation de clés
  a été validée octet pour octet contre les vecteurs de test officiels de
  la RFC 9001 Annexe A.2. Seul le paquet Initial (ClientHello, SNI) est
  accessible — les échanges 0-RTT/1-RTT sont chiffrés avec des clés de
  session qui ne sont pas publiques, donc structurellement indéchiffrables
  sans capture des clés côté client (keylog). QUIC v2 (RFC 9369) non geré.
- **TLS/QUIC sur `cross_capture_diff_cli.py`** : `--tls`/`--quic` exécutent
  le diagnostic séparément sur le baseline et sur le run courant plutôt que
  de produire une vraie comparaison chiffrée — ces deux modules ne
  connaissent qu'un état à un instant donné (voir limites ci-dessus), pas
  de notion d'"avant/après" comme pour le reste du diff. Les deux sections
  sont affichées côte à côte (console et PDF) pour comparaison visuelle.
- **TLS** : parseur maison (structures TLS lues à la main depuis la charge
  utile TCP fournie par tshark, pas de bibliothèque TLS tierce), limité à
  l'état du handshake par segment (ClientHello/ServerHello/Alert) — pas de
  réassemblage TCP inter-segments, pas de TLS en tunnel, pas de chaîne de
  certificats.
- **Analyse RF WiFi** (retries, RSSI, roaming 802.11) : hors périmètre,
  nécessiterait des captures en mode moniteur distinctes du scénario filaire
  multi-points de cet outil.
- **Protocoles propriétaires non standard** (ex : signalisation Alcatel NOE
  historique, non-SIP) : non couverts, faute de spécification publique
  fiable.
- **Parallélisation (`--parallel`)** : mesuré empiriquement en Session 31
  sur un environnement à un seul cœur CPU (`os.cpu_count()==1`) — **aucun
  gain**, léger surcoût mesurable (+4% avec le nombre de workers par
  défaut, jusqu'à +10% en sur-souscription explicite) par rapport au mode
  séquentiel, contrairement à ce qu'affirmait une version antérieure de
  cette note ("résultats identiques"). Les deux CLI affichent désormais
  un avertissement explicite quand `--parallel` tourne avec un seul
  worker effectif ou en sur-souscription (`--parallel-workers` au-delà du
  nombre de cœurs détectés). Le mécanisme (un processus `tshark`
  indépendant par fichier) reste architecturalement sain et devrait
  apporter un gain réel sur une machine multi-cœurs, mais cette
  hypothèse **n'a toujours pas pu être mesurée** en développement, faute
  d'un tel hôte disponible — à vérifier sur votre matériel.
- **Package RPM** : voir ci-dessus, construit mais pas installé sur une
  vraie Rocky Linux.
- **Tests automatisés** : couvrent `netcross_core`, `pcap_parser` et
  `netcross_report/synthesis.py`/`triage.py` (voir section [Tests](#tests)
  ci-dessus), mais pas `charts.py`/`pdf.py` (rendu matplotlib/reportlab),
  ni la GUI GTK4 ; la suite `pytest` elle-même reste construite sur des
  objets `Pkt`/`RawPacket` synthétiques (pas de dépendance ajoutée sur un
  `tshark` réel, dont la disponibilité n'est pas garantie d'un
  environnement de développement à l'autre pour ce projet). Un vrai
  `tshark` (4.2.2) **a exceptionnellement été disponible le temps d'une
  session** (voir `docs/sessions/session-09.md`) et a permis une validation
  ponctuelle hors suite `pytest` : décodage EK réel de paquets DF/MF via
  des pcaps synthétiques (scapy), invocation réelle du sous-processus
  `tshark` via `parse_capture()`, génération réelle de PDF relue avec
  `pypdf`, et rejeu des deux CLIs de bout en bout — sans garantie que ce
  soit à nouveau le cas la prochaine fois.
- Les verdicts de saturation/policing/bufferbloat/injection RST sont des
  **indices heuristiques** basés sur des corrélations statistiques, pas des
  certitudes absolues — à confirmer avec les journaux des équipements
  suspectés.

---

## Licence

MIT — voir [LICENSE](LICENSE). Adresse de contact du mainteneur à compléter
dans `LICENSE`, `build-deb/debian/control` et `build-rpm/netcross.spec`
(actuellement `FIXME-mettre-votre-email@example.com`).
