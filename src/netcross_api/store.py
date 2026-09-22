"""
netcross_api.store -- store en mémoire des analyses (issue #209).

Conserve les rapports d'analyse en mémoire (dict ID → Report). Suffisant
pour un MVP et les tests ; remplaçable par une base de données sans
changer l'interface des endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any

from netcross_core.models import Report


class AnalysesStore:
    """Store en mémoire des analyses : ID → (Report, metadata)."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    def add(self, report: Report, metadata: dict | None = None) -> str:
        """Enregistre un rapport, retourne l'ID généré."""
        analysis_id = uuid.uuid4().hex[:12]
        self._store[analysis_id] = {
            "report": report,
            "metadata": metadata or {},
        }
        return analysis_id

    def get(self, analysis_id: str) -> dict | None:
        """Retourne l'analyse ou None si introuvable."""
        return self._store.get(analysis_id)

    def get_report(self, analysis_id: str) -> Report | None:
        entry = self._store.get(analysis_id)
        return entry["report"] if entry else None

    def exists(self, analysis_id: str) -> bool:
        return analysis_id in self._store

    def list_ids(self) -> list[str]:
        return list(self._store.keys())


# Singleton global partagé entre les endpoints.
store = AnalysesStore()
