# Conversion de formats (`--convert`)

`--convert SORTIE` convertit **une** capture (`--capture NOM=fichier`) vers un autre format
de capture ou l'exporte en données structurées, puis s'arrête sans lancer d'analyse (mode
utilitaire, comme `--merge` et `--split`).

```bash
netcross-analyze --capture A=trace.erf --convert trace.pcapng                   # défaut : pcapng
netcross-analyze --capture A=trace.pcapng --convert trace.pcap --convert-format pcap
netcross-analyze --capture A=trace.pcapng --convert paquets.csv --convert-format csv
netcross-analyze --capture A=trace.pcapng --convert paquets.json --convert-format json
```

En Python : `pcap_parser.convert_capture(entree, sortie, fmt="pcapng")`,
`pcap_parser.export_csv(entree, sortie)` et `pcap_parser.export_json(entree, sortie)`.

## Table de compatibilité

| Format | Lecture (`--capture`) | Écriture (`--convert-format`) | Outil | Remarques |
|---|---|---|---|---|
| pcap (libpcap) | oui | `pcap` | `tshark -F pcap` | un seul type de lien par fichier ; commentaires et secrets TLS perdus |
| pcapng | oui | `pcapng` (défaut) | `tshark -F pcapng` | multi-interfaces, commentaires, horodatage à la nanoseconde |
| ERF (Endace) | oui | `erf` | `tshark -F erf` | l'en-tête ERF est reconstruit pour les liens Ethernet |
| CSV structuré | — | `csv` | `tshark -T fields` | un paquet par ligne (voir colonnes) |
| JSON structuré | — | `json` | `tshark -T json` | tableau JSON, un objet par paquet avec toutes les couches disséquées |
| snoop, NetMon, 5View… | oui (tout ce que lit tshark) | non | — | convertir d'abord en pcapng |

Le format produit est celui demandé par `--convert-format`, quelle que soit l'extension de la
sortie. La conversion pcapng → pcap échoue (message de tshark) si la capture mélange plusieurs
types de lien.

## Colonnes du CSV

| Colonne | Contenu |
|---|---|
| `frame.time_epoch` | horodatage Unix (secondes, fraction décimale) |
| `ip.src`, `ip.dst` | adresses IPv4 (vides pour un paquet IPv6 ou non-IP) |
| `ipv6.src`, `ipv6.dst` | adresses IPv6 (vides sinon) |
| `_ws.col.Protocol` | protocole de plus haut niveau reconnu |
| `frame.len` | taille de la trame en octets |

Les champs sont entre guillemets doubles (`quote=d`) et une seule occurrence est gardée par
champ (paquet IP encapsulé, ICMP d'erreur) : le fichier se relit directement avec
`csv.DictReader`, un tableur ou `pandas.read_csv`. Aucune résolution de noms (`-n`) : les
adresses restent des adresses.

## Garde-fous

- la sortie ne peut pas être le fichier source (il serait tronqué avant d'être lu) ;
- un seul fichier source : fusionner d'abord avec `--merge` ;
- `--convert` est exclusif avec `--merge`, `--split`, `--replay`, `--export-pcap`, `--live`
  et les options d'analyse.
