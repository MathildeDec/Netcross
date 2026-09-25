# API REST Netcross (issue #209)

## Démarrage

```bash
# Installer les dépendances optionnelles
pip install -e ".[api]"

# Lancer le service
uvicorn netcross_api.app:app --reload --port 8000
```

Le service est accessible sur `http://localhost:8000`.

La spécification OpenAPI est disponible sur :
- `http://localhost:8000/openapi.json` (JSON)
- `http://localhost:8000/docs` (Swagger UI interactif)
- `http://localhost:8000/redoc` (ReDoc)

## Endpoints

| Méthode | Path | Description |
|---------|------|-------------|
| `POST` | `/captures` | Upload d'un pcap, lance l'analyse |
| `POST` | `/captures/multi` | Plusieurs pcaps étiquetés, analyse croisée entre points |
| `GET` | `/analyses/{id}` | Rapport complet (JSON) |
| `GET` | `/analyses/{id}/security` | Constats de sécurité |
| `GET` | `/analyses` | Liste des analyses |
| `GET` | `/health` | Health check |

## Exemples curl

### Upload d'une capture

```bash
curl -X POST http://localhost:8000/captures \
  -F "file=@capture.pcapng" \
  -F "label=point-A"
```

Réponse :
```json
{
  "analysis_id": "a1b2c3d4e5f6",
  "status": "completed",
  "point_count": 1,
  "packet_count": 1247,
  "security_finding_count": 3
}
```

### Analyse multi-points (issue #354)

Équivalent de `netcross -f LAN=lan.pcap -f DC=dc.pcap --order LAN,DC` :

```bash
curl -X POST http://localhost:8000/captures/multi \
  -F "files=@lan.pcap" -F "files=@dc.pcap" \
  -F "labels=LAN,DC" \
  -F "points_order=LAN,DC"
```

- `labels` : une étiquette par fichier, dans l'ordre des fichiers ; une
  étiquette manquante ou dupliquée est refusée (400).
- `points_order` (facultatif) : ordre amont -> aval. S'il est fourni, il
  doit citer chaque étiquette exactement une fois ; absent, l'ordre est
  déduit du trafic comme la CLI sans `--order` (`order_source: "auto"`).
- Chaque fichier est soumis à la même limite de taille (413) et au même
  jeton que `POST /captures`.

Réponse (pertes comptées au point aval, comme le tableau « Qualité par
segment » des rapports) :
```json
{
  "analysis_id": "b2c3d4e5f6a1",
  "status": "completed",
  "point_count": 2,
  "packet_count": 2493,
  "security_finding_count": 0,
  "points": ["LAN", "DC"],
  "order_source": "points_order",
  "segments": [
    {
      "segment": "LAN -> DC",
      "upstream": "LAN",
      "downstream": "DC",
      "loss_count": 12,
      "loss_pct": 0.97,
      "seen_downstream": 1236,
      "off_path_count": 0,
      "latency_samples": 1224,
      "latency_avg_ms": 3.412
    }
  ]
}
```

Dans `GET /analyses/{id}`, les champs indexés par segment (`latency`,
`qos_change`, `hop_delta`...) ont pour clés `"amont -> aval"`.

### Récupérer le rapport complet

```bash
curl http://localhost:8000/analyses/a1b2c3d4e5f6
```

### Récupérer les constats de sécurité

```bash
curl http://localhost:8000/analyses/a1b2c3d4e5f6/security
```

Réponse :
```json
{
  "analysis_id": "a1b2c3d4e5f6",
  "findings": [
    {
      "severity": "moyenne",
      "category": "anomalie",
      "detail": "mouvement lateral (port_scan) : ...",
      "point": "point-A"
    }
  ],
  "service_fingerprints": [],
  "lateral_movement_events": [],
  "dga_alerts": [],
  "fast_flux_alerts": []
}
```

### Health check

```bash
curl http://localhost:8000/health
```

## Génération de la spécification OpenAPI

```bash
python scripts/generate_openapi.py
```

La spec est écrite dans `docs/openapi.yaml`. En CI, on vérifie qu'elle est à
jour (même discipline que le diagramme de classes).

## Architecture

- `src/netcross_api/app.py` — application FastAPI, endpoints
- `src/netcross_api/models.py` — modèles Pydantic (requêtes/réponses)
- `src/netcross_api/store.py` — store en mémoire des analyses
- `src/netcross_api/__init__.py` — exporte `app`

Le store en mémoire est un MVP. Pour la persistance, remplacer `AnalysesStore`
par une implémentation avec base de données sans changer les endpoints.
