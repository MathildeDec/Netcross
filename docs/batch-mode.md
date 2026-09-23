# Mode batch : un dossier de captures

Issue #277. `cross_capture_batch_cli.py` expertise toutes les captures d'un
dossier et tente l'analyse croisée des captures qui semblent être plusieurs
points de vue d'un même événement.

```bash
python3 src/cross_capture_batch_cli.py --input /data/incident-4412 --output rapports/
```

## Regroupement conservateur

Regrouper à tort deux captures sans rapport produit un rapport croisé faux
mais d'apparence normale (pertes et latences inventées). Ne pas regrouper ne
coûte qu'une analyse relançable à la main. Deux captures ne sont donc
regroupées que si les **trois** critères sont satisfaits :

1. **recouvrement temporel** ≥ `--min-overlap` (défaut 50 % de la plus courte) ;
2. **au moins `--min-common-ips` IP communes** (défaut 2), hors broadcast,
   multicast, loopback, lien-local et IP vues uniquement dans du trafic
   d'infrastructure (DNS, NTP, DHCP, mDNS, LLMNR, NetBIOS, SSDP) ;
3. **au moins une conversation commune** (même couple IP source → IP
   destination vu des deux côtés).

Une capture ne rejoint un groupe que si elle est compatible avec **chacun**
de ses membres : pas de chaînage A~B, B~C ⇒ A+B+C.

**Horloges non synchronisées** : un décalage est estimé (médiane des écarts
de première apparition des conversations communes). S'il reste dans
`--group-window` (défaut 60 s), le recouvrement est calculé après correction
et le décalage est mentionné dans la justification.

## Index de lot

`index.txt` est le vrai livrable :

```
LOT : 4 capture(s), /data/lot
  regroupees : 1 groupe(s) (2 capture(s)), 1 capture(s) isolee(s), 1 echec(s)
  [groupe 1] amont + aval  -> analyse croisee : rapport-groupe-1.txt
             amont / aval : recouvrement 100% (22:13:20-22:13:37 UTC), 2 IP communes (10.0.0.5, 10.0.0.9), ...
             rapports individuels : rapport-amont.txt, rapport-aval.txt
  isolees :
    autre (/data/lot/autre.pcap) : hors fenetre (24.0 h d'ecart); aucune IP commune; ... -> rapport-autre.txt
  echecs :
    casse (/data/lot/casse.pcap) : tshark: The file appears to be damaged or corrupt.
  synthese :
    ...
```

- chaque groupe dit pourquoi il existe ;
- chaque capture isolée dit pourquoi elle l'est (critères manqués face au candidat le plus proche) ;
- chaque capture en échec est listée avec son motif — une capture illisible n'arrête pas le lot ;
- invariant vérifié à chaque lot : entrées = groupées + isolées + échecs ;
- les fichiers à l'extension non reconnue sont cités dans la synthèse.

## Options

| Option | Effet |
|--------|-------|
| `--no-group` | aucune analyse croisée, chaque capture seule |
| `--group-window S` | décalage d'horloge maximal toléré et corrigé |
| `--min-overlap R`, `--min-common-ips N` | seuils des critères 1 et 2 |
| `--jobs N` | inventaire parallèle (défaut 1, voir #283 pour la mémoire) |
| `--skip-existing` | reprise : inventaires en cache (`.netcross-batch/`) et rapports existants réutilisés |
| `--security-report` | ajoute l'analyse de sécurité ; la synthèse cite les rapports à constats critiques/élevés |
| `--recursive` | parcourt les sous-dossiers |

Code de sortie : 0 si tout a été traité, 2 si au moins une capture ou une
analyse est en échec (le lot va quand même au bout), 1 sur erreur d'usage.
