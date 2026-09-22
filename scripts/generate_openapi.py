#!/usr/bin/env python3
"""
Génère la spécification OpenAPI depuis l'application FastAPI (issue #209).

Usage :
    python scripts/generate_openapi.py

Écrit docs/openapi.yaml à la racine du dépôt. À appeler en CI pour
vérifier que la spec est à jour (comme le diagramme de classes).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# PYTHONPATH=src pour importer netcross_api
src = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src))

from fastapi.openapi.utils import get_openapi

from netcross_api.app import app


def main() -> int:
    spec = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )

    output = Path(__file__).resolve().parent.parent / "docs" / "openapi.yaml"
    output.parent.mkdir(parents=True, exist_ok=True)

    # Écrire en YAML (pyyaml fait partie des deps de FastAPI)
    try:
        import yaml

        with output.open("w") as f:
            yaml.dump(spec, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except ImportError:
        # Repli : JSON si pyyaml n'est pas disponible
        output = output.with_suffix(".json")
        with output.open("w") as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)

    print(f"OpenAPI spec écrite dans {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
