# Session 3 — élimination de scapy, câblage TLS/QUIC sur `pcap_parser`

Demande : "Faire disparaitre scapy et aller connecter les fonctions
correctement sur le nouveau parser [pcap_parser]." Puis, en confirmation :
"pas de fallback scapy".

### Contexte

`tls_diagnostics.py` et `quic_diagnostics.py` avaient leur propre
pipeline de lecture de capture indépendant (`scapy.rdpcap()`), séparé du
pipeline tshark utilisé partout ailleurs depuis la Session 1 — c'était la
dette structurelle explicitement signalée en fin de Session 1/2
(FEATURES.md section 4, point 7).

### Corrigé

- **`pcap_parser.RawPacket`** : nouveau champ `payload: bytes` (charge
  utile brute de la couche transport TCP/UDP). Cette valeur était déjà
  calculée en interne dans `packet.py` (pour RTP/SIP/le hash) mais
  jetée ensuite — elle est maintenant conservée et exposée sur l'objet
  public. `netcross_core.models.Pkt` n'a volontairement **pas** été
  touché (pas de `payload` dessus) pour ne pas alourdir le pipeline
  principal, qui n'en a pas besoin.
- **`tls_diagnostics.parse_tls_capture`** : n'importe plus `scapy.all`
  du tout. Lit désormais via `pcap_parser.parse_capture(path)`, filtre
  `raw.proto == "TCP"` + `raw.payload`, et lit `src/dst/sport/dport/ts`
  directement sur le `RawPacket` (plus de distinction IP/IPv6 à la main,
  déjà gérée en amont par `pcap_parser`).
- **`quic_diagnostics.parse_quic_capture`** : même traitement, filtre
  `raw.proto == "UDP"` + `raw.payload`. Toute la logique HKDF/AEAD/parsing
  QUIC (déjà indépendante de scapy, ne touchait que des `bytes`) est
  inchangée.
- **`quic_diagnostics.py` : import `cryptography` désormais protégé**
  par un `try/except ImportError` explicite (message "necessite
  cryptography : pip install cryptography --break-system-packages"),
  à l'image de ce que faisait l'ancien garde scapy — défaut préexistant
  corrigé au passage (l'import n'était auparavant protégé par rien du
  tout, alors que c'est une dépendance optionnelle propre à `--quic`).
- **CLI (`cross_capture_analyzer_cli.py`) et GUI (`netcross_gtk4/app.py`)** :
  tous les messages/tooltips "necessite scapy" retirés. Le bloc
  `try/except ImportError` autour de l'import de `tls_diagnostics` a été
  **supprimé** (plus rien à y capturer : le module n'a plus de
  dépendance optionnelle). Celui autour de `quic_diagnostics` est
  **conservé**, mais son message pointe maintenant vers `cryptography`.
- **Packaging** : `requirements.txt` (`scapy>=2.5.0` remplacé par
  `cryptography>=41.0`, déjà nécessaire mais absent du fichier —
  deuxième défaut préexistant corrigé au passage), `install.sh`
  (`python3-scapy` -> `python3-cryptography` sur apt/dnf, texte EPEL mis
  à jour), `build-rpm/netcross.spec` (`Requires: python3-scapy` ->
  `python3-cryptography`), `build-deb/debian/control` (idem).
- **README.md** : les deux dernières mentions de scapy (description de
  `--tls`/`--quic`, limite du parseur TLS maison) reformulées.
- **Nettoyage des commentaires historiques** : tous les commentaires
  explicatifs dans `pcap_parser/*.py` et `netcross_core/parsing.py` qui
  comparaient le nouveau code à "l'ancienne version scapy" ont été
  reformulés pour ne plus nommer scapy (le contexte/la justification
  technique est conservée, juste sans le nom du paquet désormais
  absent du projet).

### Validation effectuée

- `grep -rni scapy` sur tout le dépôt (code, docs, packaging) : plus
  aucune occurrence en dehors de ce fichier et de FEATURES.md, qui
  documentent l'historique.
- `python -m compileall` propre sur tout `src/`.
- `ruff check --select F,E9` propre sur les fichiers touchés (les 3
  erreurs F541 restantes sont dans `report_text.py`, non touché par
  cette passe, préexistantes).
- Import de `cross_capture_analyzer_cli`, `netcross_core.tls_diagnostics`
  et `netcross_core.quic_diagnostics` vérifié dans un environnement
  **sans scapy installé du tout** (`ModuleNotFoundError: No module named
  'scapy'` confirmé, aucun import ne le requiert plus).
- **tshark non disponible dans l'environnement de cette session** (pas
  d'accès réseau au dépôt système) : le câblage `RawPacket -> TlsEvent`
  et `RawPacket -> QuicEvent` a été revalidé en isolation, en construisant
  des `RawPacket` synthétiques à la main (ClientHello TLS minimal, en-tête
  QUIC Initial structurellement valide) et en monkeypatchant
  `pcap_parser.parse_capture` pour les injecter. `parse_tls_capture`
  retrouve bien le ClientHello (SNI/version), `parse_quic_capture`
  retrouve bien le paquet Initial et échoue proprement son déchiffrement
  sur un ciphertext invalide (`decryptable=False`, pas de crash) — les
  deux confirment que le nouveau chemin RawPacket -> src/dst/sport/dport/
  ts/payload est correctement branché. Le sous-processus tshark
  lui-même (déjà validé en Session 1) n'a pas été retouché.

### Non traité dans cette passe (dette restante, voir FEATURES.md section 4)

- **Parité GUI/CLI** (`netcross_gtk4/app.py`) : toujours hors périmètre,
  nécessite un vrai travail d'interface.
- **`iter_live`/`parse_live`** (capture en direct) : toujours orphelin.
- **Pas de suite de tests automatisés** dans le dépôt — la validation
  TLS/QUIC de cette session a été faite manuellement (voir ci-dessus,
  faute de tshark disponible), formaliser au moins ce cas en test de
  non-régression éviterait de le refaire à la main au prochain
  changement de ces deux modules.

---

