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
