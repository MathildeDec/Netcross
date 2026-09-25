# Architecture : Ingestion NetFlow / sFlow (Job 32, issue #32)

## Contexte

Netcross analyse actuellement des captures pcap multi-points via tshark.
Le chantier NetFlow/sFlow vise a accepter ces protocoles de collecte de flux
comme source de donnees alternative aux captures paquet par paquet.

**Statut : Phases 1 et 2 implementees** (voir `src/netcross_core/netflow/`
et `tests/test_netflow_v5.py`) — parseur NetFlow v5 et adaptateur
FlowRecord -> Pkt. Phases 3-5 (collecteur UDP live, NetFlow v9
templates, sFlow v5) restent a faire, voir "Plan d'implementation"
ci-dessous pour le detail phase par phase.

**Point d'entree (issue #362)** : `--netflow [EXPORTATEUR=]FICHIER` du CLI
principal, mode autonome (incompatible avec `--capture`/`--live`) qui
affiche le resume de `netcross_core.netflow.summary` et l'ecrit sous la
cle `netflow` de `--json-report`. Les flux ne sont PAS injectes dans
l'analyse multi-points comme un faux point de capture (premiere version
de #381, retiree) : voir « Correlation multi-points ne s'applique pas ».

## Decision

### Placement : `src/netcross_core/netflow/`

Sous-package dedie dans `netcross_core`, au meme niveau que les autres
modules d'analyse. Le contrat de couches est respecte :
`netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser`.

### Structure proposee

```
src/netcross_core/netflow/
    __init__.py          # exports publics
    collector.py         # recepteur UDP (mode passif) ou lecteur de fichiers
    netflow_v5.py        # parseur NetFlow v5 (RFC 3954)
    netflow_v9.py        # parseur NetFlow v9 (RFC 3954, templates)
    sflow.py             # parseur sFlow v5 (RFC 3176)
    adapter.py           # conversion FlowRecord -> Pkt (compatibilite pipeline)
```

### Adaptateur : FlowRecord -> Pkt

Les flux NetFlow/sFlow ne contiennent pas de paquets individuels — ce sont
des agregats (5-tuple, octets, paquets, timestamps). Pour les integrer dans
le pipeline existant sans tout reecrire, un adaptateur convertira chaque
FlowRecord en un Pkt synthetique :

- `proto` : derive du protocol IP (TCP=6, UDP=17...)
- `src/dst/sport/dport` : du 5-tuple
- `length` : octets du flux / nombre de paquets (selon metrique)
- `ts` : first_switched / flow_start
- `point` : label du collecteur (ex: "NETFLOW-ROUTER-A")

Ces Pkt synthetiques alimentent `correlate()` -> `analyse()` comme les
captures pcap. Les limitations :
- Pas de retransmission, pas de TTL, pas de QoS (DSCP present dans NetFlow
  mais pas dans sFlow de maniere fiable)
- La correlation multi-points ne s'applique pas (un flux NetFlow vient d'un
  seul routeur) — le point de capture est le routeur lui-meme
- Les statistiques de latence inter-points ne sont pas disponibles

### Source de donnees : `iter_netflow()` / `iter_sflow()`

Deux modes, mirroir de `iter_live()` dans `pcap_parser.capture` :

1. **Mode fichier** : lire un fichier `.nfcapd` ou export NetFlow en CSV
2. **Mode collecteur** : ecouter en UDP sur le port 2055 (NetFlow) ou 6343
   (sFlow) en mode passif

Le mode collecteur s'arrete proprement via `stop_event`, comme `iter_live()`.

### Integration avec le diff live (Job 33)

Le module `live_diff.py` peut accepter des sources NetFlow en plus de pcap.
L'interface `iter_live()` et `iter_netflow()` partagent le meme contrat :
un iterateur de Pkt (synthetiques pour NetFlow, reels pour pcap).

## Limitations assumees

1. **Pas de paquet par paquet** : NetFlow est un agregat. Les analyses
   qui dependent du contenu paquet (TLS, VoIP, forensic) ne s'appliquent pas.
2. **Pas de correlation multi-points** : un flux NetFlow vient d'un seul
   routeur — il n'y a pas de "point A -> point B" dans le sens Netcross.
3. **Templates v9** : NetFlow v9 utilise des templates dynamiques. Le parseur
   doit les memoriser et les appliquer — plus complexe que v5.
4. **Pas de validation sur vrai equipement** : comme pour CAPWAP (Job 29),
   la validation sur un vrai routeur Cisco/Juniper reste necessaire.

## Plan d'implementation

1. **Phase 1 (fait)** : parseur NetFlow v5 (le plus simple, format fixe)
   — `netflow_v5.py` : `parse_netflow_v5_packet()` (un datagramme) et
   `iter_netflow_v5_file()` (mode fichier, rejeu de datagrammes
   concatenes). En-tete et enregistrements decodes via `struct`,
   erreurs fortes (`NetflowV5Error`) sur version inattendue ou
   datagramme tronque plutot que des FlowRecord partiels.
2. **Phase 2 (fait)** : adaptateur FlowRecord -> Pkt — `adapter.py` :
   `flow_record_to_pkt()`/`flow_records_to_pkts()`. Tous les champs
   Pkt non derivables d'un agregat sont mis a une valeur neutre
   explicite (jamais devinee), voir docstring du module. Integration
   directe avec `correlate()`/`analyse()` non testee ici (necessite un
   vrai jeu de flux multi-flow representatif) : a valider en Phase 3
   quand le mode collecteur permettra un test de bout en bout.
3. **Phase 3 (a faire)** : collecteur UDP passif (`collector.py`,
   `iter_netflow()` mirroir de `pcap_parser.capture.iter_live()`)
4. **Phase 4 (a faire)** : parseur NetFlow v9 (templates dynamiques)
5. **Phase 5 (a faire)** : parseur sFlow v5

Chaque phase est cadrable en une session, testable independamment.
