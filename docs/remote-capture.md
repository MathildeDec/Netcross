# Capture distante : rpcap, sshdump, pipe

Job 46 (issue #166). Jusqu'ici Netcross ne pouvait capturer que sur une
interface locale : pour un réseau distribué, il fallait capturer à la
main sur chaque machine puis rapatrier les fichiers. Le champ
« interface » de la capture en direct accepte désormais, en plus d'un
nom d'interface local (`eth0`), une URL décrivant une source distante.

Code : `pcap_parser.ek_source._resolve_live_source` (détection du type
de source) et `pcap_parser.ek_source._build_args` (traduction en
arguments `tshark`). Utilisable partout où une interface locale l'était
déjà : `iter_live`, `iter_live_multi`, `iter_ek_records`, et donc aussi
le champ interface de la capture en direct de la GUI.

## Syntaxes reconnues

| Source | Syntaxe | Exemple |
|---|---|---|
| Interface locale | `interface` (inchangé) | `eth0` |
| RPCAP (Remote Packet Capture Protocol) | `rpcap://hote:port/interface` | `rpcap://192.168.1.10:2002/eth0` |
| SSH (extcap sshdump) | `ssh://[utilisateur[:motdepasse]@]hote[:port]/interface` | `ssh://admin:secret@192.168.1.20/eth1` |
| Pipe / stdin | `-` ou `pipe://` | `-` |

Le type de source est détecté depuis le préfixe de la chaîne ; une
chaîne sans schéma reconnu est traitée comme une interface locale, à
l'identique du comportement avant #166.

### RPCAP

Suppose un démon `rpcapd` lancé sur la machine distante et joignable
sur `port` (2002 par défaut pour `rpcapd`, mais le port est toujours
obligatoire dans l'URL — aucune valeur par défaut n'est supposée côté
Netcross). L'URL est transmise telle quelle à `tshark -i` : RPCAP est
compris nativement par libpcap, aucune option `-o` supplémentaire
n'est nécessaire. Hôte, port et interface distante sont obligatoires ;
leur absence lève `InvalidCaptureSourceError` avant même de lancer
`tshark`.

### SSH (sshdump)

Ne nécessite qu'un accès SSH à la machine distante (pas de démon dédié
à installer, contrairement à RPCAP) — mais nécessite que l'interface
**extcap `sshdump`** soit installée localement (paquet
`wireshark-common` ou équivalent selon la distribution ; fait partie de
l'installation standard de Wireshark/tshark).

sshdump est une interface *extcap*, pas un périphérique `libpcap`
direct : contrairement à ce qu'on pourrait attendre, ses paramètres ne
se passent ni en flags directs sur `tshark` (`--remote-host` sur la
ligne `tshark` elle-même n'est pas reconnu), ni en `-o
sshdump:remote-host=...`. Netcross construit la forme réellement
acceptée, `-o extcap.sshdump.<option>:<valeur>` — vérifié empiriquement
contre tshark 4.2.2 (voir le docstring de `_resolve_ssh_source` pour le
détail de la démarche). Sans utilisateur/mot de passe dans l'URL,
sshdump retombe sur l'utilisateur courant et l'authentification par
agent/clé SSH par défaut. Port par défaut : 22.

**Mot de passe en clair dans les arguments du processus.** Si un mot de
passe est fourni dans l'URL, il finit en clair dans les arguments du
sous-processus `tshark` — visible via `ps aux` ou `/proc/<pid>/cmdline`
pour tout utilisateur local ayant accès à la machine qui lance la
capture. C'est une limite de sshdump lui-même, pas de Netcross.
Préférer une authentification par clé SSH (agent, ou clé par défaut de
l'utilisateur) à un mot de passe en URL dès que la machine qui lance la
capture est partagée ou que l'usage est sensible.

Un caractère spécial (`@`, `:`...) dans l'utilisateur ou le mot de
passe doit être encodé en URL (ex. `%40` pour `@`) : Netcross décode ces
deux champs avant de les transmettre à `tshark`.

### Pipe / stdin

`-` (ou `pipe://`, équivalent) fait lire `tshark` depuis son entrée
standard, comme un flux de paquets déjà en cours (par exemple un named
pipe alimenté par un outil tiers en amont). Aucune option
supplémentaire.

## Dans la GUI

Le champ « interface » de chaque point de capture en direct (onglet
« Capture en direct ») accepte directement une de ces URL à la place
d'un nom d'interface local — l'infobulle du champ rappelle la syntaxe.
Comme pour les interfaces locales, plusieurs sources séparées par des
virgules démarrent des captures simultanées, un thread par point ; il
est possible de mélanger interfaces locales et sources distantes sur
une même ligne.

Une URL malformée (hôte, port ou interface distante manquant/invalide)
ne bloque pas la saisie : l'erreur apparaît dans le journal au moment
du démarrage de la capture (`[NOM] ERREUR : ...`), au même endroit que
les autres erreurs de capture (interface locale inconnue, permissions).

## Erreurs

`pcap_parser.InvalidCaptureSourceError` (sous-classe de `ValueError`) :
levée avant tout lancement de `tshark` si l'URL `rpcap://` ou `ssh://`
est malformée (hôte, port ou interface distante manquant, port hors de
la plage 1-65535). Les erreurs de connexion elles-mêmes (hôte
injoignable, authentification refusée, démon `rpcapd` absent) restent
remontées par `tshark` sous forme de `TsharkError`, comme pour une
interface locale inexistante.
