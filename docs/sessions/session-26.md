# Session 26 — TLS approfondi : certificat serveur (dates de validité, substitution entre points)

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8 à 25.

### Contrainte d'environnement de cette session

`tshark`, `pytest`/`ruff`/`import-linter`/`pre-commit`, `scapy` et
`openssl` disponibles simultanément (accès réseau disponible). `tshark`
4.2.2, `scapy` 2.7.0, `openssl` 3.0.13. Suite `pytest` rejouée avant
toute modification : 514/514 verts (aucune régression héritée de la
Session 25).

### Choix de la feature suivante

`FEATURES.md` section 5.2 : dernier candidat 🟢 substantiel restant,
"TLS approfondi (chaîne de certs, réassemblage)" -- "toujours listé
comme limite assumée ; passerait par le dissecteur TLS de tshark plutôt
que `scapy.layers.tls`". Suggestion suivie a la lettre : lire ce que
tshark a DEJA dissèque, plutôt qu'etendre le parseur TLS binaire fait
main de `netcross_core/tls_diagnostics.py` (473 lignes, module
volontairement independant, dedie au suivi d'etat du handshake --
SNI/version/cipher/alertes/reussi-bloque -- pas au CONTENU du
certificat, qui reste hors de sa portee : `certificate` (type 11) y est
reconnu comme LABEL de type de message mais son corps n'est jamais
parse). Ce module n'est PAS touche cette session -- nouvelle
fonctionnalite ajoutee en parallele, via le patron etabli
`extract_XXX(layers)` de `pcap_parser/protocols.py` (DNS/HTTP/SIP/DHCP),
pas en etendant tls_diagnostics.py.

### Exploration empirique -- nettement plus lourde que d'habitude

Contrairement aux sessions precedentes (ICMPv6, ARP, STP), qui
construisaient des pcap synthetiques avec scapy SANS jamais capturer de
vrai trafic reseau, cette session a d'abord verifie si la capture reseau
REELLE etait possible dans cet environnement -- jamais tente
auparavant :

```bash
tshark -i lo -w test_cap.pcap -a duration:3
```

Reponse : OUI, la capture loopback fonctionne (root, interfaces listees
via `tshark -D`). Decision : generer un VRAI handshake TLS plutot que
deviner les noms de champs EK depuis la documentation ou l'intuition.

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=FR/O=Transcende/OU=Lab/CN=test.transcende.fr" \
  -addext "subjectAltName=DNS:test.transcende.fr,DNS:alt.transcende.fr"
```

Puis capture + serveur + client dans un unique script borne par
`timeout` (une premiere tentative avec des sous-shells `(... &)`
imbriques a fait echouer plusieurs appels d'outil consecutifs -- retour
`-1` -- probablement des descripteurs de fichiers non refermes ; corrige
en structurant tout dans un seul `bash -c '...'` avec `wait $PID`
explicite, sans jamais utiliser `pkill`/`ps aux`, eux-memes responsables
d'echecs similaires) :

```bash
timeout 10 bash -c '
tshark -i lo -f "tcp port 44330" -w tls_handshake.pcap -a duration:6 -q > tshark.log 2>&1 &
TSHARK_PID=$!
sleep 1
timeout 5 openssl s_server -accept 44330 -cert cert.pem -key key.pem -quiet > s_server.log 2>&1 &
sleep 1
echo -e "Q" | timeout 3 openssl s_client -connect 127.0.0.1:44330 -CAfile cert.pem > s_client.log 2>&1
wait $TSHARK_PID
' < /dev/null
```

**Premiere decouverte, avant meme d'arriver au certificat** : le client
`openssl` recent negocie TLS 1.3 par defaut, et en TLS 1.3 le message
Certificate est CHIFFRE (RFC 8446) -- invisible dans la capture en
clair. Confirme concretement (pas juste connu en theorie) en relisant
la capture : paquets applicatifs chiffres, aucun message Certificate
visible. Recapture en forcant TLS 1.2 des deux cotes
(`-tls1_2` sur `s_server` et `s_client`) -- la ou un handshake TLS 1.2
"classique" envoie bien le Certificate en clair, cas realiste pour un
outil de capture PASSIVE sur le terrain (beaucoup de trafic
d'entreprise reste en 1.2 ; meme en 1.3, un tap passif sans
`SSLKEYLOGFILE` -- rarissime en dehors d'un labo de debogage -- ne
verrait de toute facon rien).

**Deuxieme decouverte, structurante pour la conception du detecteur** :
inspection du paquet Certificate via `tshark -r ... -T ek`, en aplatissant
tout l'arbre `layers` recursivement pour voir TOUS les champs presents :

```
x509af_x509af_utcTime[0] = '2026-08-31 18:46:38 (UTC)'
x509af_x509af_utcTime[1] = '2027-08-31 18:46:38 (UTC)'
x509af_x509af_serialNumber = '38:f5:42:4e:...'
x509ce_x509ce_dNSName[0] = 'test.transcende.fr'
x509ce_x509ce_dNSName[1] = 'alt.transcende.fr'
x509if_x509if_RDNSequence_item[0..7] = '1' (x8, juste des COMPTEURS)
x509sat_x509sat_uTF8String[0..5] = (6 valeurs -- 2 RDN de 3 attributs chacune)
```

`x509if`/`x509sat` (Subject/Issuer) sont des tableaux **positionnels
partages entre TOUTES les RDN de TOUS les certificats de la chaine** --
sans reconstruire l'arbre imbrique (`-T json`/`-T pdml`, pas `-T ek`),
impossible de determiner de facon fiable laquelle des deux RDN (Issuer
ou Subject) correspond a quel attribut (CN/O/OU/C), ni meme laquelle
appartient a quel certificat pour une chaine de plusieurs certificats.
**Decision prise a ce moment precis, avant d'ecrire le detecteur** :
Subject/Issuer explicitement EXCLUS du perimetre -- risque juge trop
eleve de produire un resultat SILENCIEUSEMENT FAUX (pire qu'une absence
de fonctionnalite pour un outil de diagnostic). `x509af.utcTime`
(dates) et `x509ce.dNSName` (SAN), eux, sont des champs a PLAT sans
cette ambiguite -- le premier element correspond TOUJOURS au certificat
FEUILLE (RFC 5246 §7.4.2 : "the sender's certificate MUST come first in
the list") quelle que soit la longueur de la chaine -- d'ou le
perimetre finalement retenu : dates de validite + SAN + numero de
serie du certificat feuille uniquement.

### Implémentation

**`pcap_parser/protocols.py`** : nouvelle fonction
`extract_tls_certificate(layers)`, meme patron exact que
`extract_dns`/`extract_http`/`extract_sip`/`extract_dhcp` -- lit une
dissection deja faite par tshark, aucun parsing manuel. Renvoie `None`
si aucun certificat dans ce paquet (grande majorite des paquets TLS).
Testee directement contre le vrai flux tshark avant meme d'ecrire un
test unitaire :

```python
pk.tls_cert_not_before, pk.tls_cert_not_after, pk.tls_cert_san, pk.tls_cert_serial
# ('2026-08-31 18:46:38 (UTC)', '2027-08-31 18:46:38 (UTC)',
#  ('test.transcende.fr', 'alt.transcende.fr'),
#  '38:f5:42:4e:fc:8e:44:c1:50:f9:3c:d4:21:ed:90:60:b9:df:5c:f6')
```

**`pcap_parser/packet.py`** : nouveaux champs `RawPacket.tls_cert_not_
before`/`tls_cert_not_after`/`tls_cert_san`/`tls_cert_serial`, cablés
sous `if proto == "TCP":` (TLS est TCP uniquement -- TLS-sur-UDP/QUIC
deja couvert separement par `quic_diagnostics.py`, verifie par un test
dedie `test_build_packet_tls_ignore_sur_udp`).

**`netcross_core/analysis.py`** : `_analyse_tls_certificate(r,
all_packets, pairs)`, deux diagnostics dans une seule fonction (meme
principe de bundling que le double compteur STP en Session 25) :

1. `tls_cert_invalid_dates` (par POINT) -- le certificat est present
   hors de sa fenetre de validite au moment ou le paquet a ete capture.
   Comparaison contre l'horodatage du PAQUET LUI-MEME (`pk.ts`), pas
   contre l'heure actuelle du systeme -- decision de conception
   importante : une analyse a froid d'une capture ancienne (faite il y a
   des mois) doit rester correcte, un certificat valide au moment de la
   capture mais expire depuis aujourd'hui ne doit PAS etre signale a
   tort. Nouvelle fonction `_parse_tls_cert_date` pour convertir le
   format tshark ("YYYY-MM-DD HH:MM:SS (UTC)") en `datetime` UTC --
   renvoie `None` (paquet ignore, pas de plantage) si le format ne
   correspond pas a ce qui est attendu.
2. `tls_cert_mismatch` (par PAIRE de points) -- pour une meme connexion
   (5-tuple), le numero de serie differe entre l'amont et l'aval.
   C'est ce second diagnostic qui exploite le mieux l'identite propre
   de cet outil (comparaison multi-points) -- un simple `openssl x509
   -checkend` ou une capture Wireshark mono-point ne pourrait jamais
   detecter ca.

### Aucun changement nécessaire côté charts/JSON/GUI

Vérifié par lecture de code avant d'écrire quoi que ce soit, comme les
sessions précédentes : `json_report.py` entièrement générique sur les
objets `Finding`, `pdf.py`/`charts.py`/GUI GTK4 sans référence
spécifique nécessaire.

### Non traité dans cette passe -- limites documentées, pas des oublis

- **Subject/Issuer (Distinguished Name)** -- voir "Exploration
  empirique" ci-dessus : ambiguïté positionnelle en `-T ek`,
  demanderait `-T json`/`-T pdml` pour reconstruire l'arbre ASN.1 --
  chantier à part.
- **Certificats intermédiaires/racine de la chaîne** -- seul le
  certificat feuille (le premier) est analysé, garanti par RFC 5246
  §7.4.2. Vérifier toute la chaîne de confiance PKI serait de toute
  façon hors de portée d'une capture passive (pas d'accès au magasin de
  confiance du client).
- **TLS 1.3 sans `SSLKEYLOGFILE`** -- limite protocolaire, pas
  contournable par ce projet (le Certificate est chiffré par
  construction, RFC 8446).
- **Réassemblage TCP** -- déjà gratuit : tshark réassemble les segments
  TCP avant dissection, contrairement au parseur binaire fait main de
  `tls_diagnostics.py`. Ce module continue néanmoins d'exister
  séparément pour ses propres besoins (suivi d'état du handshake) --
  fusionner les deux approches serait un chantier de refonte à part,
  hors de portée de cette session à scope unique.

### Validation effectuée

- **Tests unitaires** : suite complète rejouée avant toute modification
  (514/514 hérités de la Session 25, aucune régression préalable). 26
  nouveaux tests : `tests/test_protocols.py` (6 -- champs réels, un
  seul SAN pas en liste, SAN absent, plusieurs certificats de la chaîne
  prend le premier, absence de certificat, moins de deux dates) ;
  `tests/test_packet.py` (3 -- certificat présent, absent, ignoré sur
  UDP) ; `tests/test_analysis.py` (9 -- valide, expiré, pas encore
  valide, sans certificat, date illisible sans planter, substitution
  détectée, pas de substitution si même série, pas de substitution si
  vu à un seul point, indépendance par connexion) ; `tests/
  test_synthesis.py` (3), `tests/test_report_text.py` (3), `tests/
  test_baseline_diff.py` (2) -- **540/540** au total, aucune
  régression.
- **Bout en bout réel, avec de VRAIS handshakes TLS capturés en local**
  (pas seulement des couches EK synthétiques comme les sessions
  précédentes) : deux certificats auto-signés distincts générés
  (numéros de série différents), deux handshakes TLS 1.2 séparés
  capturés sur loopback, puis pcap réécrits avec `scapy` pour leur
  donner un 5-tuple apparent identique (nécessaire pour simuler "la
  même connexion vue à deux points différents" à partir de deux
  captures loopback physiquement distinctes) et des horodatages
  contrôlés :
  1. Point A : handshake avec cert1, horodatage décalé à 2031 (bien
     au-delà de sa validité de 365 jours). Point B : handshake avec
     cert2 (numéro de série différent), horodatage normal (dans sa
     fenêtre de validité). Rejoué via le **vrai CLI**
     (`cross_capture_analyzer_cli.py --order A,B --triage
     --json-report`) : les DEUX diagnostics déclenchés simultanément et
     corrects -- « 1 certificat(s) hors de leur fenetre de validite »
     au point A (avec le numéro de série complet et les deux dates dans
     l'exemple), et « 1 connexion(s) presentent un certificat different
     entre les deux points » pour la paire A→B (avec les deux numéros
     de série complets). Confirmé aussi dans le JSON (deux findings
     catégorie "TLS" distincts) et le triage.
  2. Même certificat aux deux points, horodatage dans sa fenêtre de
     validité : aucun faux positif, message par défaut "aucune anomalie
     de certificat détectée" affiché.
- **Outillage qualité** : `ruff check` (1 import trop long corrigé
  automatiquement via `ruff check --fix` + `ruff format`), `ruff format
  --check` (49 fichiers conformes), `PYTHONPATH=src lint-imports`
  (aucun cycle introduit, 1 contrat respecté), `pre-commit run
  --all-files` (les 3 hooks passent) -- tous rejoués réellement sur un
  dépôt git temporaire créé pour l'occasion (supprimé après coup).

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : section 2 (`pcap_parser` pour l'extraction
  X.509, `netcross_core.analysis` pour le détecteur) ; section 4 --
  nouvelle sous-section "TLS approfondi -- certificat serveur (Session
  26)" en tête, avant la Session 25 ; section 5.2 -- ligne "TLS
  approfondi" marquée faite pour le certificat feuille, avec les trois
  limites (Subject/Issuer, chaîne complète, PKI) explicitement listées
  comme architecturales plutôt que comme reliquat.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouvelle entrée "Fonctionnalités" pour les
  diagnostics de certificat TLS ; nouvelle entrée dans "Limites
  connues" ; compteur de tests mis à jour (514 → 540).

