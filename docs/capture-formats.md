# Conversion de formats de capture (Job 49, issue #169)

`pcap_parser.convert.convert_capture(path_in, path_out, format="pcapng", fields=None)`
(réexportée par `pcap_parser` et `netcross_core`) et le flag `--convert` de
`cross_capture_analyzer_cli.py` convertissent **un** fichier de capture vers un autre format.
Comme `--merge`/`--split`/`--replay`, `--convert` ne lance aucune analyse.

```bash
# pcap -> pcapng (format déduit de l'extension de la sortie)
python3 cross_capture_analyzer_cli.py --capture LAN=lan.pcap --convert lan.pcapng
# export structuré ; --convert-format prime sur l'extension
python3 cross_capture_analyzer_cli.py --capture LAN=lan.pcapng --convert paquets.txt --convert-format csv
```

```python
from pcap_parser import convert_capture

convert_capture("lan.pcap", "lan.pcapng", format="pcapng")
convert_capture("lan.pcapng", "lan.csv", format="csv", fields=["timestamp", "src", "dst", "sport", "dport"])
```

## Formats de sortie

| `format` | Outil | Contenu | Remarques |
|----------|-------|---------|-----------|
| `pcap` | `mergecap -F pcap` | libpcap classique | Refusé par Wireshark si l'entrée mélange plusieurs types de liaison (pcapng multi-interfaces) : `TsharkError`. |
| `pcapng` | `mergecap -F pcapng` | pcapng | Défaut de `convert_capture` et de `--convert` pour une extension inconnue. |
| `erf` | `mergecap -F erf` | Endace ERF | Wireshark ajoute un enregistrement « Provenance Metadata » : il compte dans `capinfos -c` mais n'est pas un paquet. |
| `csv` | `tshark -T ek` | 1 en-tête + 1 ligne par paquet | Colonnes ci-dessous. Les paquets non IP (ARP, STP, LLDP…) ont leur ligne. |
| `json` | `tshark -T ek` | tableau JSON, 1 objet par paquet | `{"frame_number", "timestamp", "layers"}` ; `layers` = tous les champs EK de tshark, tels quels. |

Entrées acceptées : tout ce que Wireshark sait lire (pcap, pcapng, ERF, formats compressés…).

### Pourquoi `mergecap` et non `tshark -F` (comme le suggérait l'issue)

Sur Wireshark 4.2.2, `tshark -F erf` et `editcap -F erf` échouent (*« record type that can't be saved in a
"erf" file »*), y compris pour un simple pcap Ethernet, alors que `mergecap -F erf` produit un fichier ERF valide.
`mergecap` est déjà requis par `--merge` ; appliqué à un seul fichier il re-encode sans réordonner. Non pris en charge
(vérifié) : ERF → ERF, refusé par `mergecap` (conversion sans objet).

## Table de compatibilité (vérifiée sur Wireshark 4.2.2)

| Entrée \ Sortie | pcap | pcapng | erf | csv | json |
|-----------------|:----:|:------:|:---:|:---:|:----:|
| pcap            | ✅ | ✅ | ✅ | ✅ | ✅ |
| pcapng (une interface / un type de liaison) | ✅ | ✅ | ✅ | ✅ | ✅ |
| pcapng (types de liaison mixtes) | ❌ | ✅ | ❌ | ✅ | ✅ |
| erf             | ✅ | ✅ | ❌ | ✅ | ✅ |

❌ = erreur `TsharkError` (message de `mergecap` repris), aucune sortie créée. Le mélange de types de liaison est refusé
par Wireshark pour tout format de sortie qui n'en porte qu'un (pcap, erf) ; pcapng, csv et json l'acceptent.

## Colonnes CSV

Défaut (`CSV_DEFAULT_FIELDS`) : `timestamp,src,dst,proto,length`. Toutes les colonnes possibles (`CSV_FIELDS`) :

| Colonne | Valeur |
|---------|--------|
| `frame_number` | numéro de trame tshark (1-indexé dans ce fichier) |
| `timestamp` | secondes epoch UTC, 9 décimales exactes (`1700000000.500000000`) |
| `src` / `dst` | IP (v4 puis v6) de la couche la plus externe, sinon adresse MAC ; vide si aucune |
| `proto` | couche la plus haute reconnue par tshark, hors pseudo-protocole `data` (`udp`, `tls`, `arp`…) |
| `length` | taille de la trame sur le fil (`frame.len`) |
| `sport` / `dport` | ports TCP ou UDP ; vides sinon |

`fields` fixe le sous-ensemble et l'ordre ; il n'est accepté que pour `format="csv"`. Les paquets tunnelisés sont
décrits par leur couche externe (ce qui est sur le fil), à la différence de l'analyse qui privilégie la couche interne.

## Garanties

- **Écriture atomique** : intermédiaires dans un répertoire temporaire du dossier de sortie puis `os.replace`. En cas
  d'échec, la sortie préexistante est intacte et rien n'est laissé derrière.
- Sortie identique à l'entrée, format inconnu, `fields` invalide : `ValueError` ; entrée absente ou dossier de sortie
  inexistant : `FileNotFoundError` ; outil absent du PATH : `TsharkNotFoundError` ; échec de l'outil : `TsharkError`.
- Export CSV/JSON en flux : la mémoire ne dépend pas de la taille de la capture.
- Prérequis : paquet `tshark` (fournit `mergecap` et `capinfos`).
