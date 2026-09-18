# Architecture : Ingestion NetFlow / sFlow (Job 32, issue #32)

## Contexte

Netcross analyse actuellement des captures pcap multi-points via tshark.
Le chantier NetFlow/sFlow vise a accepter ces protocoles de collecte de flux
comme source de donnees alternative aux captures paquet par paquet.

**Statut : à cadrer avant de coder** — ce document est la decision
d'architecture.

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

1. **Phase 1** : parseur NetFlow v5 (le plus simple, format fixe)
2. **Phase 2** : adaptateur FlowRecord -> Pkt + test d'integration avec
   `correlate()` et `analyse()`
3. **Phase 3** : collecteur UDP passif
4. **Phase 4** : parseur NetFlow v9 (templates dynamiques)
5. **Phase 5** : parseur sFlow v5

Chaque phase est cadrable en une session, testable independamment.
