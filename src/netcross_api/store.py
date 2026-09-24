"""
netcross_api.store -- store des analyses avec statut et persistance optionnelle.

Issue #356 : ajout du suivi de statut (pending -> completed/failed) et
d'une persistance SQLite optionnelle (env NETCROSS_DB_PATH).

Conserve les rapports d'analyse en mémoire (dict ID → Report) par défaut.
Si NETCROSS_DB_PATH est défini, les analyses sont aussi persistées en SQLite.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from typing import Any

from netcross_core.models import Report


class AnalysesStore:
    """Store des analyses : ID → (Report, metadata, status)."""

    def __init__(self, db_path: str | None = None) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._db_path = db_path or os.environ.get("NETCROSS_DB_PATH")
        if self._db_path:
            self._init_db()

    def _init_db(self) -> None:
        assert self._db_path is not None
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'completed',
                    metadata TEXT NOT NULL DEFAULT '{}',
                    report_json TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            conn.commit()

    def add(self, report: Report, metadata: dict | None = None, status: str = "completed") -> str:
        """Enregistre un rapport, retourne l'ID généré."""
        analysis_id = uuid.uuid4().hex[:12]
        entry = {
            "report": report,
            "metadata": metadata or {},
            "status": status,
        }
        with self._lock:
            self._store[analysis_id] = entry
            if self._db_path:
                self._persist(analysis_id, entry)
        return analysis_id

    def add_pending(self, metadata: dict | None = None) -> str:
        """Crée une analyse en statut 'pending' (issue #356)."""
        analysis_id = uuid.uuid4().hex[:12]
        entry = {
            "report": None,
            "metadata": metadata or {},
            "status": "pending",
        }
        with self._lock:
            self._store[analysis_id] = entry
            if self._db_path:
                self._persist(analysis_id, entry)
        return analysis_id

    def complete(self, analysis_id: str, report: Report) -> None:
        """Marque une analyse comme terminée avec son rapport."""
        with self._lock:
            if analysis_id in self._store:
                self._store[analysis_id]["report"] = report
                self._store[analysis_id]["status"] = "completed"
                if self._db_path:
                    self._persist(analysis_id, self._store[analysis_id])

    def fail(self, analysis_id: str, error: str) -> None:
        """Marque une analyse comme échouée."""
        with self._lock:
            if analysis_id in self._store:
                self._store[analysis_id]["status"] = "failed"
                self._store[analysis_id]["error"] = error
                if self._db_path:
                    self._persist(analysis_id, self._store[analysis_id])

    def get(self, analysis_id: str) -> dict | None:
        """Retourne l'analyse ou None si introuvable."""
        with self._lock:
            return self._store.get(analysis_id)

    def get_report(self, analysis_id: str) -> Report | None:
        with self._lock:
            entry = self._store.get(analysis_id)
            return entry["report"] if entry else None

    def get_status(self, analysis_id: str) -> str | None:
        with self._lock:
            entry = self._store.get(analysis_id)
            return entry.get("status") if entry else None

    def exists(self, analysis_id: str) -> bool:
        with self._lock:
            return analysis_id in self._store

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._store.keys())

    def _persist(self, analysis_id: str, entry: dict) -> None:
        assert self._db_path is not None
        report_json = None
        if entry.get("report"):
            try:
                report_json = json.dumps(entry["report"], default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                pass
        metadata = json.dumps(entry.get("metadata", {}), default=str, ensure_ascii=False)
        status = entry.get("status", "completed")
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analyses (id, status, metadata, report_json)
                VALUES (?, ?, ?, ?)
                """,
                (analysis_id, status, metadata, report_json),
            )
            conn.commit()


# Singleton global partagé entre les endpoints.
store = AnalysesStore()
