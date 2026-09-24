"""
netcross_api.app -- application FastAPI pour exposer les analyses Netcross
(issue #209).

Endpoints :
    POST /captures          — upload d'un pcap, lance l'analyse
    GET  /analyses/{id}     — rapport complet (JSON)
    GET  /analyses/{id}/security — constats de sécurité
    GET  /health            — health check

Le service dépend de netcross_core (analyse) et netcross_report (sérialisation
JSON). FastAPI/uvicorn sont en dépendance optionnelle (extra ``api``).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from netcross_api.models import (
    AnalysisSummary,
    ErrorResponse,
    HealthResponse,
    SecurityFinding,
    SecurityReport,
)
from netcross_api.store import store
from netcross_core import analyse, correlate, parse_capture
from netcross_core.security.findings import apply_security_findings, scan_capture_exploits

# Singleton pour éviter B008 (File() in argument defaults).
_FILE_REQUIRED = File(default=..., description="Fichier pcap/pcapng à analyser")

# Issue #356 : authentification par jeton configurable via env var.
# Si NETCROSS_API_TOKEN n'est pas défini, l'authentification est désactivée
# (mode développement local).
_API_TOKEN = os.environ.get("NETCROSS_API_TOKEN")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Limite d'upload configurable (défaut 100 Mo).
_MAX_UPLOAD_BYTES = int(os.environ.get("NETCROSS_MAX_UPLOAD_MB", "100")) * 1024 * 1024


def _verify_api_key(api_key: str | None = Depends(_api_key_header)) -> None:
    """Dépendance FastAPI : vérifie le jeton d'authentification.

    Issue #356 : si NETCROSS_API_TOKEN est défini, toutes les routes
    nécessitent l'en-tête X-API-Key. Sinon, l'authentification est
    désactivée (mode développement local).
    """
    if _API_TOKEN and api_key != _API_TOKEN:
        raise HTTPException(status_code=401, detail="Jeton d'authentification invalide ou manquant")


app = FastAPI(
    title="Netcross API",
    description="Analyse croisée de captures réseau — service REST",
    version="1.0.0",
)


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Health check du service."""
    return HealthResponse()


@app.post(
    "/captures",
    response_model=AnalysisSummary,
    status_code=201,
    tags=["captures"],
    responses={400: {"model": ErrorResponse}},
)
async def upload_capture(
    file: UploadFile = _FILE_REQUIRED,
    label: str = "capture",
    _auth: None = Depends(_verify_api_key),
) -> AnalysisSummary:
    """Upload d'un fichier pcap, lancement de l'analyse.

    Le fichier est temporairement écrit sur disque pour que tshark puisse
    le lire, puis supprimé. L'analyse complète (correlation + sécurité) est
    exécutée et le rapport est stocké en mémoire.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")

    # Issue #356 : limite de taille d'upload configurable
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        max_mb = _MAX_UPLOAD_BYTES // 1024 // 1024
        raise HTTPException(status_code=413, detail=f"Fichier trop volumineux (max {max_mb} Mo)")

    # Écrire le fichier uploadé sur disque (tshark lit des fichiers, pas des streams)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        packets = parse_capture(label, tmp_path)
        if not packets:
            raise HTTPException(status_code=400, detail="Aucun paquet trouvé dans le fichier")

        # Corrélation + analyse
        flows = correlate(packets)
        report = analyse(flows, points_order=[label], all_packets=packets)
        detections = scan_capture_exploits(label, tmp_path)
        apply_security_findings(report, packets, detections=detections)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erreur de parsing: {exc}") from exc
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    # Stocker l'analyse
    analysis_id = store.add(report, metadata={"filename": file.filename, "label": label})

    return AnalysisSummary(
        analysis_id=analysis_id,
        point_count=len(report.points),
        packet_count=len(packets),
        security_finding_count=len(report.security_findings),
    )


@app.get(
    "/analyses/{analysis_id}",
    tags=["analyses"],
    responses={404: {"model": ErrorResponse}},
)
async def get_analysis(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> JSONResponse:
    """Récupère le rapport complet d'une analyse (JSON).

    Le rapport est sérialisé en dict JSON directement (sans passer par
    generate_json_report qui écrit sur disque).
    """
    report = store.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")

    # Sérialiser le rapport en dict JSON directement
    from dataclasses import fields

    doc: dict = {}
    for f in fields(report):
        val = getattr(report, f.name)
        # Les defaultdict(list) et defaultdict(dict) doivent être convertis
        if hasattr(val, "items"):
            doc[f.name] = dict(val) if val else {}
        elif isinstance(val, (list, tuple)):
            doc[f.name] = list(val)
        else:
            doc[f.name] = val

    doc["_analysis_id"] = analysis_id
    return JSONResponse(content=doc)


@app.get(
    "/analyses/{analysis_id}/security",
    response_model=SecurityReport,
    tags=["analyses"],
    responses={404: {"model": ErrorResponse}},
)
async def get_security_report(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> SecurityReport:
    """Récupère les constats de sécurité d'une analyse."""
    entry = store.get(analysis_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")

    report = entry["report"]
    findings = [
        SecurityFinding(
            severity=f.get("severity", ""),
            category=f.get("category", ""),
            detail=f.get("detail", ""),
            point=f.get("point"),
        )
        for f in report.security_findings
    ]

    return SecurityReport(
        analysis_id=analysis_id,
        findings=findings,
        service_fingerprints=report.service_fingerprints,
        lateral_movement_events=getattr(report, "lateral_movement_events", []),
        dga_alerts=getattr(report, "dga_alerts", []),
        fast_flux_alerts=getattr(report, "fast_flux_alerts", []),
    )


@app.get("/analyses", tags=["analyses"])
async def list_analyses(_auth: None = Depends(_verify_api_key)) -> dict:
    """Liste les IDs d'analyses disponibles."""
    return {"analyses": store.list_ids()}


@app.get(
    "/analyses/{analysis_id}/status",
    tags=["analyses"],
    responses={404: {"model": ErrorResponse}},
)
async def get_analysis_status(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> dict:
    """Retourne le statut d'une analyse (issue #356).

    Statuts possibles : ``pending``, ``completed``, ``failed``.
    """
    status = store.get_status(analysis_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable")
    entry = store.get(analysis_id)
    result: dict = {"analysis_id": analysis_id, "status": status}
    if status == "failed" and entry and entry.get("error"):
        result["error"] = entry["error"]
    return result
