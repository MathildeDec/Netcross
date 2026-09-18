# Session 13 — résolution DNS

### Demande initiale

"Continue les features à faire. Fait évoluer les fichiers de suivi, de
tests et de documentation. Tu livres juste après le
`netcross{date-ymd-hms}.zip` sans passer à la suite" — même consigne que
les Sessions 8/9/10/11/12.

### Contrainte d'environnement de cette session

Vérifié en tout début de session, avant tout choix de feature : `tshark`
absent (`which tshark` vide), `scapy` et `pytest` non installés
(`ModuleNotFoundError`), et **pas d'accès réseau** — `pip install pytest`
et `apt-get install tshark` échouent tous les deux (403 sur
`pypi.org`/`archive.ubuntu.com`). Même contrainte que les Sessions 1-8 et
12, à nouveau différente des Sessions 9/10/11 qui avaient eu accès à un
vrai `tshark`.

### Choix de la feature suivante

`FEATURES.md` section 5.2, 🟠 urgence moyenne — trois candidats
restaient sans le signal explicite "ne dépend pas de tshark" qu'avait eu
`--json-report` en Session 11/12 : comparaison client vs client,
résolution DNS, score de confiance. Résolution DNS retenue :
- Le dissecteur DNS de tshark existe déjà (comme DHCP/SIP avant lui) —
  toute la dissection est déléguée à tshark via `extract_dns`, exactement
  comme `extract_dhcp`/`extract_sip` ; le travail réellement nouveau ici
  (corrélation par transaction entre points de capture, calcul de durée,
  détection de message manquant/timeout) ne dépend lui-même d'aucun appel
  à `tshark` — même situation de fait que `--json-report` en Session 12,
  simplement non formulée aussi explicitement dans `FEATURES.md` (le
  texte disait "dissecteur DNS déjà présent côté tshark", ce qui est un
  signal équivalent une fois qu'on le relie au constat de Session 11
  "l'export JSON ne dépend pas de tshark").
- Face à "comparaison client vs client" : cette piste est décrite comme
  ayant un "design déjà détaillé" dans `idées.md`/
  `netcross_pistes_evolution2.md` — documents jamais inclus dans aucune
  archive livrée jusqu'ici (seule leur synthèse dans `FEATURES.md` l'est),
  donc ce détail de conception n'est pas disponible ici. Deviner sa forme
  exacte (comparer quoi, entre quels axes — deux clients du même appel
  vocal ? deux exécutions du même test à des heures différentes ?)
  aurait été plus risqué que d'étendre un patron déjà éprouvé trois fois
  de suite (DHCP Session -, SIP idem, maintenant DNS) avec une sémantique
  sans ambiguïté (requête/réponse, transaction, timeout).
- Face à "score de confiance / `sample_size`" : décrit comme transversal
  ("protège la crédibilité de tous les modules"), donc plus large et plus
  risqué à cadrer correctement en une seule session sans retour
  intermédiaire possible — repoussé, cohérent avec le principe "une
  feature à la fois" déjà suivi par les sessions précédentes.

### Ce qui a été livré

**`pcap_parser/protocols.py`** :
- `extract_dns(layers)` — même style que `extract_dhcp` : lit
  `dns_dns_id`/`dns_dns_flags_response`/`dns_dns_qry_name`/
  `dns_dns_flags_rcode` (convention EK `<proto>_<proto>_<champ>` déjà
  vérifiée empiriquement pour DHCP en Sessions 9-11, appliquée par
  analogie ici — **non re-vérifiée empiriquement**, `tshark` absent de
  cette session, voir "Limite assumée" ci-dessous). Renvoie `None` si
  `dns.id` est absent (paquet non-DNS). `dns.qry.name` peut en théorie
  être une liste si le paquet contient plusieurs questions
  (`dns.count.queries > 1`, rarissime) : seule la première est gardée,
  même simplification que `layer()`/`innermost()` ailleurs dans ce
  package pour des couches empilées.
- **Différence assumée avec RTP/SIP** : pas de repli heuristique par
  lecture d'octets bruts. RTP a une signature binaire reconnaissable
  sans dissection préalable (version bits + payload type), SIP a un
  format texte avec des verbes identifiables (`INVITE`, `SIP/2.0`...) —
  les deux ont un usage réel documenté (SIP sur un port non-standard,
  RTP négocié dynamiquement par SDP hors bande). DNS n'a pas cette forme
  "sans signalisation préalable" à détecter par heuristique : soit tshark
  reconnaît la conversation (port standard ou port suivi depuis le
  début de la capture — cas très majoritaire), soit le paquet reste non
  identifié. Pas de logique de repli à écrire ni à tester séparément ici.
- Table `DNS_RCODES` (RFC 1035 §4.1.1) : affichage seulement, la logique
  elle-même teste `NXDOMAIN`(3)/`SERVFAIL`(2) en dur dans `analysis.py`
  (même schéma que `DHCP_MESSAGE_TYPES` : affichage lisible, logique
  ailleurs sur la valeur numérique).

**`pcap_parser/packet.py`** : 4 nouveaux champs sur `RawPacket`
(`dns_txn_id`/`dns_is_response`/`dns_qry_name`/`dns_rcode`), extraits
dans un bloc dédié après SIP, sur la condition `proto in ("TCP", "UDP")`
— **pas** `if payload and proto in (...)` comme SIP, puisque
`extract_dns` ne lit que la dissection tshark native (pas de dépendance
au payload brut assemblé par ce projet).

**`netcross_core/models.py`** : mêmes 4 champs sur `Pkt` ; nouveaux
champs sur `Report` — `dns_query_count`/`dns_response_count`/
`dns_nxdomain_count`/`dns_servfail_count` (compteurs par point),
`dns_missing` (par paire de points, liste de messages), `dns_timeout`
(par point, liste), `dns_duration_ms` (liste globale, comme
`dhcp_duration_ms`/`sip_setup_duration_ms`).

**`netcross_core/analysis.py`** — `_analyse_dns(r, all_packets, points,
points_order)`, appelée juste après `_analyse_sip` dans `analyse()`.
Même schéma exact que `_analyse_dhcp`/`_analyse_sip` : dictionnaire
`txn_id -> point -> [Pkt]`, puis pour chaque transaction :
- Comptage par point (requêtes, réponses, NXDOMAIN, SERVFAIL) en une
  seule boucle sur `all_packets` avant la boucle de corrélation, comme
  pour DHCP/SIP.
- Message manquant entre deux points adjacents (`r.pairs`) : différence
  d'ensemble `{is_response} en A` moins `{is_response} en B`, même
  logique que `types_a - types_b` pour `dhcp_msg_type`/`sip_msg_type`.
- Timeout applicatif : requête vue à un point, aucune réponse observée
  nulle part dans la capture entière (`response_ts is None`) — signal
  distinct du "message manquant sur un segment" ci-dessus (une requête
  totalement sans réponse déclenche généralement les deux, ce qui est
  correct : elle est bien "manquante" sur tous les segments en aval ET
  "sans réponse nulle part").
- Durée query→réponse : `min(ts requête)` à `min(ts réponse)`, tous
  points confondus (une transaction DNS n'apparaît généralement qu'à un
  seul point de capture, contrairement à un flux TCP qui traverse
  plusieurs points) — même widening "tous points confondus" que
  `dhcp_duration_ms`.

**Limite assumée, documentée en commentaire** (même famille que
`dhcp.xid`/SIP Call-ID, jamais mentionnée explicitement pour ceux-ci
faute d'être pertinente à leur échelle) : `dns.id` ne fait que 16 bits
contre 32 pour `dhcp.xid` — sur une capture très longue et très chargée
en requêtes DNS concurrentes, une réutilisation d'id avant qu'une
transaction précédente ne soit terminée est théoriquement possible et
n'est pas gérée spécifiquement ici (les deux transactions seraient vues
comme une seule, à tort).

**`netcross_report/synthesis.py`** — nouvelles règles dans
`build_findings` : SERVFAIL = "anomalie" (précisément l'angle mort visé
par cette piste : un échec de résolution côté serveur/résolveur est
souvent pris à tort pour un problème réseau alors que les paquets ont
bien transité), NXDOMAIN = "info" (domaine inexistant, pas
nécessairement un problème quelconque — utile à voir sans alarmer),
timeout = "anomalie", message manquant sur un segment = "a_surveiller",
durée moyenne de résolution > 200ms = "a_surveiller" (seuil choisi par
analogie avec les autres seuils de latence déjà en dur dans ce fichier,
pas issu d'une norme DNS particulière — 200ms de résolution DNS est
généralement perceptible par un utilisateur final au premier chargement
d'une page/service).

**`netcross_core/report_text.py`** — nouvelle section console "DNS
(résolution de noms)", même structure que la section SIP juste
au-dessus (compteurs par point, listes tronquées à 20 lignes avec
"... N autres" au-delà, message dédié si aucun trafic DNS détecté).

**`netcross_core/baseline_diff.py`** — nouveau bloc, juste après DHCP :
`_compare_count` pour NXDOMAIN/SERVFAIL/timeout par point (mêmes seuils
`min_delta=1, rel_threshold=0.0` qu'un compteur DHCP NAK — tout nouvel
incident compte, pas de bruit à filtrer sur un compteur qui part
normalement de zéro), et une comparaison dédiée pour la durée moyenne
globale (pas de `_compare_latency` générique disponible à segment
paramétrable avec catégorie personnalisée : cette fonction fige la
catégorie sur "Latence" en dur — répliqué comme un bloc inline dédié,
même style que le bloc `server_think_time` déjà présent dans ce fichier,
catégorie "DNS" à la place).

**Aucun changement PDF/JSON/GUI/triage** : les quatre restent génériques
sur `Finding`/`Report` (même situation que PMTUD/retrans/options TCP en
Sessions 9-11) — parité gratuite via le mécanisme déjà en place.

### Validation

Même absence totale d'outils que les Sessions 1-8/12 (confirmé en tout
début de session ci-dessus) :
- **Harnais de test minimal réutilisé** (`_pytest_shim_runner.py`, resté
  hors de l'arbre `netcross/` livré, comme en Sessions 8/12) — un bug de
  capture de `stderr` trouvé et corrigé dans le harnais lui-même avant de
  lui faire confiance (`Capsys` ne redirigeait que `sys.stdout`, alors
  que deux tests existants de `test_capture.py`/`test_parsing_adapter.py`
  lisent `capsys.readouterr().err` — les deux échouaient à tort avant
  correction, aucune régression réelle du projet) : même discipline que
  les Sessions 8/12, qui avaient chacune trouvé et corrigé un bug
  différent dans ce même harnais avant de faire confiance à son résultat.
- Rejeu complet de `tests/` **avant** tout nouveau code : 287/287 (hérité
  intact de la Session 12), confirmant l'absence de régression du bug de
  capture `stderr` lui-même (les deux tests visés sont ceux qui l'ont
  révélé, pas un effet de bord des changements DNS).
- 21 nouveaux tests répartis sur 6 fichiers existants
  (`test_protocols.py` : `extract_dns` en isolation, requête/réponse/
  NXDOMAIN/liste de noms/tolérance chaîne-vs-booléen/absence ;
  `test_packet.py` : `build_packet` sur UDP et TCP, paquet non-DNS
  inchangé — **incident de tool-use résolu en cours de session** : un
  premier appel d'édition avec un `old_str`/`new_str` strictement
  identiques (relecture par erreur du même bloc) a semblé faire
  disparaître le test `test_build_packet_udp_dhcp` existant à la relecture
  suivante ; plutôt que de reconstruire ce test à la main par
  approximation, le fichier a été restauré depuis l'archive source
  d'origine (`unzip` ciblé sur ce seul fichier) puis les nouveaux tests
  DNS ajoutés par-dessus — aucune perte de couverture, incident détecté
  avant livraison ; `test_analysis.py` : `_analyse_dns` via le pipeline
  complet `correlate`/`analyse` (requête+réponse au même point calcule la
  durée, requête vue à un point absente à l'autre, timeout sans réponse
  nulle part, NXDOMAIN/SERVFAIL comptés, paquet non-DNS ignoré) ;
  `test_synthesis.py` : sévérité de chaque règle DNS ; `test_baseline_diff.py` :
  nouvelle SERVFAIL = régression, résolution plus lente = régression,
  petit écart de durée ignoré ; `test_report_text.py` : section DNS
  affichée avec compteurs/NXDOMAIN/durée moyenne, message dédié si aucun
  trafic DNS).
- Résultat final : **311/311**.
- **`python -m compileall`** propre sur tout `src/` et `tests/`.
- **`ruff`/`lint-imports`/`pytest` réels non exécutables** (mêmes
  contraintes que les Sessions 8/12) : vérification manuelle ciblée sur
  les fichiers touchés — aucune ligne > 120 caractères, aucun import
  relatif, imports triés, aucune dépendance nouvelle ajoutée au contrat
  de couches (`analysis.py` et `baseline_diff.py` n'importent rien de
  nouveau, `protocols.py`/`packet.py`/`models.py` non plus).
- **Vérification manuelle bout en bout** (build_packet direct, sans le
  harnais) sur des layers EK synthétiques construits à la main : requête
  UDP, réponse UDP avec NXDOMAIN, requête TCP (transfert de zone), et
  paquet TCP ordinaire sans DNS pour confirmer que les 4 nouveaux champs
  restent à leurs valeurs par défaut (`None`/`None`/`None`/`False`) —
  tous conformes avant même l'écriture des tests formels.

### Limite non résolue dans cette passe

**Noms de champs EK non vérifiés empiriquement** (comme la Session 12
pour `--json-report`, différent des Sessions 9/10/11 qui avaient eu accès
à un vrai `tshark`) : `dns_dns_id`/`dns_dns_flags_response`/
`dns_dns_qry_name`/`dns_dns_flags_rcode` sont déduits par analogie avec
la convention déjà vérifiée pour DHCP (`dhcp_dhcp_type`,
`dhcp_dhcp_option_dhcp_server_id`), pas confirmés sur une vraie sortie
`tshark -T ek`. Point explicite à vérifier dès qu'un environnement avec
`tshark` redevient disponible — même remarque que celle laissée pour
RTP/DHCP/SIP en Sessions 1-8, confirmée exacte pour DHCP a posteriori en
Sessions 9-11.

### Fichiers de suivi/documentation mis à jour

- **`FEATURES.md`** : nouvelle sous-section "Résolution DNS (Session 13)"
  en section 4 (juste avant la sous-section JSON de la Session 12) ;
  section 2 `pcap_parser`/`netcross_core.analysis`/
  `netcross_core.baseline_diff`/`netcross_report.synthesis` mis à jour
  avec une ligne DNS chacun ; diagramme de classes mermaid (section 3) :
  4 nouveaux champs sur `RawPacket`/`Pkt`, 7 nouveaux champs sur `Report`,
  `extract_dns` sur `protocols`, `_analyse_dns` sur `analysis_mod` ;
  section 5.2, ligne "Résolution DNS" déplacée vers "fait". La ligne de
  validation générale de la section 1 (Session 7) n'a **pas** été mise à
  jour, pour la même raison qu'en Session 12 : elle reflète le dernier
  run réel des outils (Session 11), pas disponible cette fois-ci.
- **`claude.md`** (ce fichier) : cette section.
- **`README.md`** : nouveau bullet DNS dans "Ce que fait l'outil".

### Non traité dans cette passe

- **Comparaison client vs client / score de confiance / validation
  CAPWAP sur vraie capture / gestion mémoire grosses captures** —
  candidats 🟠 restants, aucun traité ici, une feature à la fois.
- **`--live` sur `cross_capture_diff_cli.py`** — toujours hors périmètre,
  question de conception non résolue, non demandée ici.
- Comme pour DHCP/SIP avant lui, **pas de champ CLI dédié** pour DNS (pas
  de flag à passer, extraction et analyse automatiques) — cohérent avec
  le choix déjà fait pour DHCP/SIP/PMTUD/retrans/options TCP.

