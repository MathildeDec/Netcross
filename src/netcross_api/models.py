"""
netcross_api.models -- modèles Pydantic pour les requêtes/réponses API
(issue #209).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


class HealthResponse(BaseModel):
    """Réponse du health check."""

    status: str = "ok"
    version: str = "1.0.0"


class AnalysisSummary(BaseModel):
    """Résumé d'une analyse (retourné par POST /captures)."""

    analysis_id: str
    status: str = "completed"
    point_count: int = 0
    packet_count: int = 0
    security_finding_count: int = 0


class SecurityFinding(BaseModel):
    """Un constat de sécurité sérialisé."""

    severity: str = ""
    category: str = ""
    detail: str = ""
    point: str | None = None


class SecurityReport(BaseModel):
    """Rapport de sécurité pour GET /analyses/{id}/security."""

    analysis_id: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    service_fingerprints: list[dict] = Field(default_factory=list)
    lateral_movement_events: list[dict] = Field(default_factory=list)
    dga_alerts: list[dict] = Field(default_factory=list)
    fast_flux_alerts: list[dict] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Réponse d'erreur standard."""

    detail: str
