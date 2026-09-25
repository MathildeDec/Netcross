"""
netcross_api.app -- application FastAPI pour exposer les analyses Netcross
(issue #209).

Endpoints :
    POST /captures          — upload d'un pcap, lance l'analyse
    POST /captures/multi    — upload de plusieurs pcaps, analyse croisée (#354)
    GET  /analyses/{id}     — rapport complet (JSON)
    GET  /analyses/{id}/security — constats de sécurité
    GET  /health            — health check

Le service dépend de netcross_core (analyse) et netcross_report (sérialisation
JSON). FastAPI/uvicorn sont en dépendance optionnelle (extra ``api``).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import fields, is_dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from netcross_api.models import (
    AnalysisSummary,
    ErrorResponse,
    HealthResponse,
    MultiAnalysisSummary,
    SecurityFinding,
    SecurityReport,
    SegmentLoss,
)
from netcross_api.store import store
from netcross_core import analyse, correlate, parse_capture
from netcross_core.logging_config import get_logger
from netcross_core.security.findings import apply_security_findings, scan_capture_exploits

logger = get_logger(__name__)
# Singleton pour éviter B008 (File() in argument defaults).
_FILE_REQUIRED = File(default=..., description="Fichier pcap/pcapng à analyser")
_FILES_REQUIRED = File(default=..., description="Fichiers pcap/pcapng à analyser")
_LABEL_FORM = Form(default="capture", description="Étiquette du point de capture (ex: lan)")
_LABELS_FORM = Form(default="", description="Étiquettes séparées par virgule (ex: lan,wan,dc)")
_POINTS_ORDER_FORM = Form(default="", description="Ordre des points séparé par virgule (ex: lan,wan,dc)")

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
    label: str = _LABEL_FORM,
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


def _parse_labels(labels: str, file_count: int) -> list[str]:
    """Étiquettes des captures, une par fichier, dans l'ordre des fichiers.

    Issue #354 : une étiquette manquante ou dupliquée est refusée (400)
    plutôt que remplacée en silence par ``point-N`` -- l'ordre des points et
    les segments de la réponse en dépendent.
    """
    label_list = [lbl.strip() for lbl in labels.split(",")] if labels.strip() else []
    if len(label_list) != file_count or not all(label_list):
        raise HTTPException(
            status_code=400,
            detail=f"labels doit donner une étiquette non vide par fichier ({file_count} attendue(s), "
            f"{len([lbl for lbl in label_list if lbl])} reçue(s))",
        )
    doublons = sorted({lbl for lbl in label_list if label_list.count(lbl) > 1})
    if doublons:
        raise HTTPException(status_code=400, detail=f"Étiquettes dupliquées : {', '.join(doublons)}")
    return label_list


def _parse_points_order(points_order: str, label_list: list[str]) -> list[str] | None:
    """Ordre amont -> aval des points, ou None pour le déduire (comme la CLI
    sans ``--order``). S'il est fourni, il doit citer chaque étiquette une
    fois et une seule : un point inconnu ou oublié fausserait les segments."""
    if not points_order.strip():
        return None
    order = [p.strip() for p in points_order.split(",") if p.strip()]
    inconnus = [p for p in order if p not in label_list]
    manquants = [lbl for lbl in label_list if lbl not in order]
    if inconnus or manquants or len(order) != len(set(order)):
        detail = "points_order doit citer chaque étiquette exactement une fois"
        if inconnus:
            detail += f" ; inconnue(s) : {', '.join(inconnus)}"
        if manquants:
            detail += f" ; absente(s) : {', '.join(manquants)}"
        raise HTTPException(status_code=400, detail=detail)
    return order


def segment_losses(report) -> list[SegmentLoss]:
    """Pertes et délai par segment de ``report.pairs`` (issue #354).

    Même définition que ``netcross_report.path_metrics`` (pertes au point
    aval, taux = pertes / paquets vus à ce point), recalculée ici parce que
    la couche API ne dépend pas de netcross_report (contrat import-linter).
    """
    segments = []
    for upstream, downstream in report.pairs:
        loss = int(report.loss_count.get(downstream, 0))
        seen = int(report.seen_count.get(downstream, 0))
        lat = report.latency.get((upstream, downstream), [])
        segments.append(
            SegmentLoss(
                segment=f"{upstream} -> {downstream}",
                upstream=upstream,
                downstream=downstream,
                loss_count=loss,
                loss_pct=round(100.0 * loss / seen, 3) if seen else None,
                seen_downstream=seen,
                off_path_count=int(report.off_path_count.get(downstream, 0)),
                latency_samples=len(lat),
                latency_avg_ms=round(sum(lat) / len(lat), 3) if lat else None,
            )
        )
    return segments


@app.post(
    "/captures/multi",
    response_model=MultiAnalysisSummary,
    status_code=201,
    tags=["captures"],
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
)
async def upload_multi_capture(
    files: list[UploadFile] = _FILES_REQUIRED,
    labels: str = _LABELS_FORM,
    points_order: str = _POINTS_ORDER_FORM,
    _auth: None = Depends(_verify_api_key),
) -> MultiAnalysisSummary:
    """Upload de plusieurs captures étiquetées, analyse croisée entre points.

    Issue #354 : équivalent de ``netcross -f LAN=lan.pcap -f DC=dc.pcap
    --order LAN,DC``. ``labels`` donne une étiquette par fichier (dans
    l'ordre des fichiers) ; ``points_order`` (facultatif) fixe l'ordre
    amont -> aval, sinon il est déduit du trafic. La réponse détaille les
    pertes et le délai de chaque segment.
    """
    if not files or len(files) < 2:
        raise HTTPException(status_code=400, detail="Au moins 2 fichiers sont requis pour l'analyse multi-points")
    label_list = _parse_labels(labels, len(files))
    order_list = _parse_points_order(points_order, label_list)

    all_packets = []
    tmp_paths: list[tuple[str, str]] = []
    try:
        for file, label in zip(files, label_list, strict=True):
            if not file.filename:
                raise HTTPException(status_code=400, detail=f"Nom de fichier manquant pour {label}")
            content = await file.read()
            if len(content) > _MAX_UPLOAD_BYTES:
                max_mb = _MAX_UPLOAD_BYTES // 1024 // 1024
                raise HTTPException(status_code=413, detail=f"Fichier {label} trop volumineux (max {max_mb} Mo)")
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(content)
                tmp_paths.append((label, tmp.name))
            try:
                pkts = parse_capture(label, tmp.name)
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Erreur de parsing pour {label}: {exc}") from exc
            if not pkts:
                raise HTTPException(status_code=400, detail=f"Aucun paquet trouvé dans la capture {label}")
            all_packets.extend(pkts)

        flows = correlate(all_packets)
        report = analyse(flows, points_order=order_list, all_packets=all_packets)

        # CVE-2 : scanner les exploits sur chaque fichier
        detections = []
        for label, tmp_path in tmp_paths:
            detections.extend(scan_capture_exploits(label, tmp_path))
        apply_security_findings(report, all_packets, detections=detections)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erreur d'analyse: {exc}") from exc
    finally:
        for _label, tp in tmp_paths:
            Path(tp).unlink(missing_ok=True)

    analysis_id = store.add(
        report,
        metadata={"files": [f.filename for f in files], "labels": label_list, "points_order": order_list},
    )

    return MultiAnalysisSummary(
        analysis_id=analysis_id,
        point_count=len(report.points),
        packet_count=len(all_packets),
        security_finding_count=len(report.security_findings),
        points=list(report.points),
        order_source="points_order" if order_list else "auto",
        segments=segment_losses(report),
    )


def _jsonable(value):
    """Rend un champ de Report sérialisable en JSON.

    Les dictionnaires par segment (``latency``, ``qos_change``...) ont des
    clés tuple (amont, aval), refusées par JSON : dès deux points, l'ancien
    ``dict(val)`` faisait échouer GET /analyses/{id} (issue #354). Elles
    deviennent « amont -> aval », le libellé des constats et des segments.
    """
    if hasattr(value, "items"):
        return {(" -> ".join(map(str, k)) if isinstance(k, tuple) else str(k)): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@app.get(
    "/analyses/{analysis_id}",
    tags=["analyses"],
    responses={404: {"model": ErrorResponse}},
)
async def get_analysis(analysis_id: str, _auth: None = Depends(_verify_api_key)) -> JSONResponse:
    """Récupère le rapport complet d'une analyse (JSON).

    Le rapport est sérialisé en dict JSON directement (sans passer par
    generate_json_report qui écrit sur disque) ; les clés par segment
    deviennent « amont -> aval » (voir ``_jsonable``).
    """
    logger.debug("get_analysis(analysis_id={})", analysis_id)
    report = store.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Analyse {analysis_id} introuvable")

    doc: dict = {f.name: _jsonable(getattr(report, f.name)) for f in fields(report)}
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
    logger.debug("get_security_report(analysis_id={})", analysis_id)
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
    logger.debug("list_analyses()")
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
