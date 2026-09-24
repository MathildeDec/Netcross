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

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

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

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
# Singleton pour éviter B008 (File() in argument defaults).
_FILE_REQUIRED = File(default=..., description="Fichier pcap/pcapng à analyser")

app = FastAPI(
    title="Netcross API",
    description="Analyse croisée de captures réseau — service REST",
    version="1.0.0",
)


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Health check du service."""
    logger.debug("health()")
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
) -> AnalysisSummary:
    """Upload d'un fichier pcap, lancement de l'analyse.

    Le fichier est temporairement écrit sur disque pour que tshark puisse
    le lire, puis supprimé. L'analyse complète (correlation + sécurité) est
    exécutée et le rapport est stocké en mémoire.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")

    # Écrire le fichier uploadé sur disque (tshark lit des fichiers, pas des streams)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

        logger.exception("erreur de parsing: exc")
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
async def get_analysis(analysis_id: str) -> JSONResponse:
    """Récupère le rapport complet d'une analyse (JSON).

    Le rapport est sérialisé en dict JSON directement (sans passer par
    generate_json_report qui écrit sur disque).
    """
    logger.debug("get_analysis(analysis_id={analysis_id})")
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
async def get_security_report(analysis_id: str) -> SecurityReport:
    """Récupère les constats de sécurité d'une analyse."""
    logger.debug("get_security_report(analysis_id={analysis_id})")
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
async def list_analyses() -> dict:
    """Liste les IDs d'analyses disponibles."""
    logger.debug("list_analyses()")
    return {"analyses": store.list_ids()}
