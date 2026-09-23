"""Tests du module netcross_api (issue #209).

Couvre les endpoints FastAPI : health, upload/analyse, get_analysis,
get_security_report, list_analyses.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netcross_api.app import app, store
from netcross_api.store import AnalysesStore
from netcross_api.models import HealthResponse, AnalysisSummary, SecurityFinding, SecurityReport, ErrorResponse


@pytest.fixture
def client():
    """Client de test FastAPI avec un store isole."""
    import netcross_api.app as app_mod  # noqa: F401 -- provoque l'import
    import sys
    # netcross_api/__init__.py reexporte `app` (FastAPI), donc
    # `netcross_api.app` est l'instance, pas le module. On recupere le
    # vrai module via sys.modules.
    real_mod = sys.modules["netcross_api.app"]
    original_store = real_mod.store
    real_mod.store = AnalysesStore()
    client = TestClient(app)
    yield client
    real_mod.store = original_store


@pytest.fixture
def api_store():
    """Store isole pour les tests unitaires."""
    import netcross_api.store as store_mod
    original = store_mod.store
    store_mod.store = AnalysesStore()
    yield store_mod.store
    store_mod.store = original


def test_health_endpoint(client):
    """GET /health retourne status=ok et version."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_list_analyses_vide(client):
    """GET /analyses retourne une liste vide au demarrage."""
    resp = client.get("/analyses")
    assert resp.status_code == 200
    assert resp.json() == {"analyses": []}


def test_get_analysis_inexistante(client):
    """GET /analyses/{id} avec un ID inexistant retourne 404."""
    resp = client.get("/analyses/inexistant")
    assert resp.status_code == 404
    assert "inexistant" in resp.json()["detail"].lower() or "introuvable" in resp.json()["detail"].lower()


def test_get_security_report_inexistant(client):
    """GET /analyses/{id}/security avec un ID inexistant retourne 404."""
    resp = client.get("/analyses/inexistant/security")
    assert resp.status_code == 404


def test_upload_sans_fichier(client):
    """POST /captures sans fichier retourne 422 (FastAPI validation)."""
    resp = client.post("/captures")
    assert resp.status_code == 422


def test_health_response_model():
    """HealthResponse a les bons champs par defaut."""
    h = HealthResponse()
    assert h.status == "ok"
    assert h.version == "1.0.0"


def test_analysis_summary_model():
    """AnalysisSummary a les bons champs par defaut."""
    s = AnalysisSummary(analysis_id="test123")
    assert s.analysis_id == "test123"
    assert s.status == "completed"
    assert s.point_count == 0
    assert s.packet_count == 0
    assert s.security_finding_count == 0


def test_security_finding_model():
    """SecurityFinding a les bons champs par defaut."""
    f = SecurityFinding()
    assert f.severity == ""
    assert f.category == ""
    assert f.detail == ""
    assert f.point is None


def test_security_report_model():
    """SecurityReport a les bons champs par defaut."""
    r = SecurityReport(analysis_id="test")
    assert r.analysis_id == "test"
    assert r.findings == []
    assert r.service_fingerprints == []
    assert r.lateral_movement_events == []
    assert r.dga_alerts == []
    assert r.fast_flux_alerts == []


def test_error_response_model():
    """ErrorResponse a le bon champ."""
    e = ErrorResponse(detail="erreur test")
    assert e.detail == "erreur test"


def test_store_add_et_get(api_store):
    """AnalysesStore.add() retourne un ID et get() retrouve le rapport."""
    from netcross_core.models import Report
    r = Report()
    analysis_id = api_store.add(r, metadata={"filename": "test.pcap"})
    assert isinstance(analysis_id, str)
    assert len(analysis_id) == 12
    entry = api_store.get(analysis_id)
    assert entry is not None
    assert entry["report"] is r
    assert entry["metadata"]["filename"] == "test.pcap"


def test_store_get_inexistant(api_store):
    """AnalysesStore.get() retourne None pour un ID inexistant."""
    assert api_store.get("inexistant") is None


def test_store_get_report_inexistant(api_store):
    """AnalysesStore.get_report() retourne None pour un ID inexistant."""
    assert api_store.get_report("inexistant") is None


def test_store_exists(api_store):
    """AnalysesStore.exists() retourne True/False correctement."""
    from netcross_core.models import Report
    r = Report()
    analysis_id = api_store.add(r)
    assert api_store.exists(analysis_id) is True
    assert api_store.exists("inexistant") is False


def test_store_list_ids(api_store):
    """AnalysesStore.list_ids() retourne la liste des IDs."""
    from netcross_core.models import Report
    r1 = Report()
    r2 = Report()
    id1 = api_store.add(r1)
    id2 = api_store.add(r2)
    ids = api_store.list_ids()
    assert id1 in ids
    assert id2 in ids
    assert len(ids) == 2


def test_store_get_report(api_store):
    """AnalysesStore.get_report() retourne le rapport."""
    from netcross_core.models import Report
    r = Report()
    analysis_id = api_store.add(r)
    assert api_store.get_report(analysis_id) is r
