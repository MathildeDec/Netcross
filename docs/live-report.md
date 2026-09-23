# Rapport temps réel (`--live-report`)

Pendant une capture `--live`, Netcross publie un **dictionnaire structuré** (schéma
`netcross.live/1`) mis à jour à intervalle régulier, et une page HTML pour le présenter.
L'analyse complète reste faite à l'arrêt, comme avant.

```bash
netcross-analyze --live LAN:eth0 --live WAN:eth1 \
    --live-report ./live --live-report-interval 5 --live-report-serve 8765
# page : http://127.0.0.1:8765/            (relecture successive)
#        http://127.0.0.1:8765/?mode=completive
```

## Proposition : deux formes pour deux lectures

| Fichier | Écriture | Lecture | Pour |
|---|---|---|---|
| `live.json` | **instantané complet**, remplacé atomiquement à chaque relevé (fichier temporaire + `os.replace`) | **successive** : relire le tout, remplacer l'affichage | tableau de bord, supervision (« où en est-on ? ») |
| `live.jsonl` | **journal en ajout seul**, une ligne par relevé numérotée `seq` | **complétive** : ne traiter que les lignes de `seq` > dernier vu | chronologie, ingestion SIEM/`tail -f`, relecture après coup |
| `index.html` | régénérée à chaque relevé | les deux modes | lecture humaine |

Un lecteur ne voit jamais un `live.json` à moitié écrit ; une dernière ligne de
`live.jsonl` incomplète (écriture en cours) est simplement ignorée puis relue au relevé
suivant.

### Instantané (`live.json`)

```json
{
  "schema": "netcross.live/1", "seq": 12, "final": false,
  "generated_at": "2026-09-23T06:30:00+00:00", "started_at": "...", "elapsed_s": 60.0,
  "totals": {"packets": 48210, "bytes": 39011234, "hosts": 87},
  "points": {"LAN": {"status": "capture", "error": null, "packets": 30110, "bytes": 25011000,
                     "retransmissions": 14, "pps": 512.4, "bps": 3400112,
                     "first_packet": "...", "last_packet": "..."}},
  "protocols": {"TCP": 40100, "UDP": 8110},
  "top_conversations": [{"src": "10.0.0.5", "dst": "10.0.0.9", "proto": "TCP", "bytes": 9120000}],
  "last_events": [{"type": "pic_de_debit", "point": "LAN", "pps": 512.4, "moyenne": 120.3, "t": "..."}]
}
```

### Journal (`live.jsonl`)

```json
{"schema":"netcross.live/1","seq":12,"t":"...","elapsed_s":60.0,"final":false,
 "points":{"LAN":{"packets":2561,"bytes":2100000,"pps":512.4,"bps":3400112}},"events":[...]}
```

`points` y contient les **deltas** depuis le relevé précédent : la somme des lignes
redonne les totaux de l'instantané.

### Événements

| Type | Signification |
|---|---|
| `nouvel_hote` | adresse jamais vue dans la session (200 au plus, puis `nouveaux_hotes_nombreux` avec un compte) |
| `point_silencieux` / `point_repris` | un point qui avait du trafic n'en reçoit plus / en reçoit de nouveau |
| `pic_de_debit` | paquets/s > 3 × moyenne glissante (et ≥ 50 paquets/s) |
| `point_erreur` / `point_arrete` | fin de capture d'un point (avec le motif en cas d'erreur) |

Le dernier relevé porte `"final": true` ; la page cesse alors de se rafraîchir.

## La page

- servie par `--live-report-serve PORT` (écoute **uniquement sur 127.0.0.1**), elle se met
  à jour sans rechargement : `?mode=successive` relit `live.json`, `?mode=completive`
  relit `live.jsonl` et ajoute les nouvelles lignes à la chronologie (les compteurs sont
  cumulés dans le navigateur, rien n'est effacé) ;
- ouverte directement (`file://`, où le navigateur interdit `fetch`), elle embarque
  l'instantané et les 200 dernières lignes du journal et se recharge à chaque intervalle.

Aucune donnée capturée n'est insérée en HTML brut (tout passe par `textContent`, JSON en
ligne échappé) : un nom d'hôte ou une adresse forgés ne peuvent pas injecter de script.

## Coût et limites

- Seules des métriques **incrémentales** (O(1) par paquet) sont tenues : relancer l'analyse
  complète à chaque relevé coûterait O(n) sur une capture qui grossit.
- Une erreur d'écriture (disque plein…) est journalisée sans interrompre la capture.
- Le journal d'une session remplace celui de la précédente dans le même répertoire.
