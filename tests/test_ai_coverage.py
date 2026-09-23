"""Tests des modules netcross_ai (issue #246, couverture).

Couvre les fonctions non-ML : Baseline, FlowAnomaly, FlowPrediction,
is_feature_vector, export/load_training_set, _explain.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from netcross_ai.anomaly import (
    Baseline,
    BaselineError,
    FlowAnomaly,
    BASELINE_SCHEMA,
    _explain,
)
from netcross_ai.flow_classifier import (
    is_feature_vector,
    export_training_set,
    load_training_set,
    FlowPrediction,
    TrainingSetError,
    TRAINING_SCHEMA,
    SUGGESTED_LABELS,
    sample_vector,
)
from netcross_ai.features import FEATURE_NAMES, flow_features, flow_key


# --- Baseline ---------------------------------------------------------------

def _sample_flow():
    """Flux minimal pour les tests."""
    return {
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "sport": 50000,
        "dport": 80,
        "proto": "TCP",
        "packets": 10,
        "bytes": 5000,
        "duration_ms": 1000.0,
        "classification": "normal",
    }


def _sample_vectors(n=25):
    """Genere n vecteurs de caracteristiques valides (11 features)."""
    return [[float(i), float(i + 1), float(i % 5), float(i * 2), 10.0, 1000.0, 1.0, 0.0, 0.0, 5.0, 500.0] for i in range(n)]


def test_baseline_from_flows():
    """Baseline.from_flows() cree des vecteurs depuis des flux."""
    flows = [_sample_flow()]
    b = Baseline.from_flows(flows, label="test")
    assert b.label == "test"
    assert len(b.vectors) == 1
    assert len(b.vectors[0]) == len(FEATURE_NAMES)


def test_baseline_merge():
    """Baseline.merge() fusionne deux baselines."""
    b1 = Baseline([[1.0] * len(FEATURE_NAMES)], "a")
    b2 = Baseline([[2.0] * len(FEATURE_NAMES)], "b")
    merged = b1.merge(b2)
    assert len(merged.vectors) == 2
    assert merged.label == "a"


def test_baseline_merge_label_vide():
    """Baseline.merge() garde le label non vide."""
    b1 = Baseline([[1.0] * len(FEATURE_NAMES)], "")
    b2 = Baseline([[2.0] * len(FEATURE_NAMES)], "b")
    merged = b1.merge(b2)
    assert merged.label == "b"


def test_baseline_to_dict():
    """Baseline.to_dict() produit un dict valide."""
    b = Baseline([[1.0] * len(FEATURE_NAMES)], "test", "2024-01-01T00:00:00+00:00")
    d = b.to_dict()
    assert d["schema"] == BASELINE_SCHEMA
    assert d["features"] == list(FEATURE_NAMES)
    assert d["label"] == "test"
    assert d["created_at"] == "2024-01-01T00:00:00+00:00"
    assert d["vectors"] == [[1.0] * len(FEATURE_NAMES)]


def test_baseline_save_load(tmp_path):
    """Baseline.save() puis Baseline.load() round-trip."""
    b = Baseline(_sample_vectors(25), "test", "2024-01-01T00:00:00+00:00")
    path = tmp_path / "baseline.json"
    b.save(path)
    loaded = Baseline.load(path)
    assert loaded.label == "test"
    assert loaded.vectors == b.vectors


def test_baseline_from_dict_valid():
    """Baseline.from_dict() valide un document correct."""
    data = {
        "schema": BASELINE_SCHEMA,
        "features": list(FEATURE_NAMES),
        "label": "test",
        "created_at": "2024-01-01",
        "vectors": _sample_vectors(25),
    }
    b = Baseline.from_dict(data)
    assert b.label == "test"
    assert len(b.vectors) == 25


def test_baseline_from_dict_wrong_schema():
    """Baseline.from_dict() refuse un mauvais schema."""
    with pytest.raises(BaselineError, match="baseline"):
        Baseline.from_dict({"schema": "wrong", "features": list(FEATURE_NAMES), "vectors": []})


def test_baseline_from_dict_wrong_features():
    """Baseline.from_dict() refuse des features differentes."""
    with pytest.raises(BaselineError, match="caracteristiques"):
        Baseline.from_dict({
            "schema": BASELINE_SCHEMA,
            "features": ["wrong"],
            "vectors": [],
        })


def test_baseline_from_dict_invalid_vectors():
    """Baseline.from_dict() refuse des vecteurs invalides."""
    with pytest.raises(BaselineError, match="vecteurs"):
        Baseline.from_dict({
            "schema": BASELINE_SCHEMA,
            "features": list(FEATURE_NAMES),
            "vectors": ["not_a_list"],
        })


def test_baseline_from_dict_non_dict():
    """Baseline.from_dict() refuse un non-dict."""
    with pytest.raises(BaselineError, match="baseline"):
        Baseline.from_dict("not_a_dict")


def test_baseline_load_file_not_found():
    """Baseline.load() echoue sur un fichier inexistant."""
    with pytest.raises(BaselineError, match="illisible"):
        Baseline.load("/nonexistent/baseline.json")


def test_baseline_load_invalid_json(tmp_path):
    """Baseline.load() echoue sur un JSON invalide."""
    path = tmp_path / "bad.json"
    path.write_text("not json")
    with pytest.raises(BaselineError, match="illisible"):
        Baseline.load(path)


def test_baseline_created_at_default():
    """Baseline a un created_at par defaut."""
    b = Baseline([[1.0] * len(FEATURE_NAMES)])
    assert b.created_at != ""


# --- FlowAnomaly ------------------------------------------------------------

def test_flow_anomaly_to_dict():
    """FlowAnomaly.to_dict() produit un dict correct."""
    a = FlowAnomaly(
        flow="A->B:80",
        score=0.85,
        is_anomaly=True,
        classification="tunnel",
        reasons=["packets = 100 (baseline 50 +/- 10)"],
    )
    d = a.to_dict()
    assert d["flow"] == "A->B:80"
    assert d["score"] == 0.85
    assert d["is_anomaly"] is True
    assert d["classification"] == "tunnel"
    assert d["reasons"] == ["packets = 100 (baseline 50 +/- 10)"]


# --- _explain ---------------------------------------------------------------

def test_explain_no_anomaly():
    """_explain() retourne une liste vide si pas d'anomalie."""
    means = [50.0] * len(FEATURE_NAMES)
    stds = [10.0] * len(FEATURE_NAMES)
    vector = [50.0] * len(FEATURE_NAMES)  # z=0 pour tous
    reasons = _explain(vector, means, stds)
    assert reasons == []


def test_explain_with_anomaly():
    """_explain() retourne les raisons pour les z >= 3."""
    means = [50.0] * len(FEATURE_NAMES)
    stds = [10.0] * len(FEATURE_NAMES)
    vector = [100.0] + [50.0] * (len(FEATURE_NAMES) - 1)  # z=5 pour le premier
    reasons = _explain(vector, means, stds)
    assert len(reasons) == 1
    assert FEATURE_NAMES[0] in reasons[0]


# --- is_feature_vector ------------------------------------------------------

def test_is_feature_vector_valid():
    """is_feature_vector() accepte un vecteur valide."""
    v = [1.0] * len(FEATURE_NAMES)
    assert is_feature_vector(v) is True


def test_is_feature_vector_wrong_length():
    """is_feature_vector() refuse un vecteur trop court."""
    assert is_feature_vector([1.0]) is False


def test_is_feature_vector_non_list():
    """is_feature_vector() refuse un non-list."""
    assert is_feature_vector("not_a_list") is False


def test_is_feature_vector_with_bool():
    """is_feature_vector() refuse les booleens."""
    v = [1.0] * (len(FEATURE_NAMES) - 1) + [True]
    assert is_feature_vector(v) is False


def test_is_feature_vector_with_nan():
    """is_feature_vector() refuse NaN."""
    v = [1.0] * (len(FEATURE_NAMES) - 1) + [float("nan")]
    assert is_feature_vector(v) is False


def test_is_feature_vector_with_inf():
    """is_feature_vector() refuse inf."""
    v = [1.0] * (len(FEATURE_NAMES) - 1) + [float("inf")]
    assert is_feature_vector(v) is False


# --- export/load_training_set -----------------------------------------------

def test_export_training_set(tmp_path):
    """export_training_set() ecrit un fichier JSON valide."""
    flows = [_sample_flow()]
    path = tmp_path / "training.json"
    count = export_training_set(flows, path)
    assert count == 1
    data = json.loads(path.read_text())
    assert data["schema"] == TRAINING_SCHEMA
    assert data["labels_suggeres"] == list(SUGGESTED_LABELS)
    assert len(data["samples"]) == 1


def test_load_training_set_valid(tmp_path):
    """load_training_set() charge un fichier valide."""
    flows = [_sample_flow()]
    path = tmp_path / "training.json"
    export_training_set(flows, path)
    samples = load_training_set(path)
    assert len(samples) == 1
    assert samples[0][1] == "normal"


def test_load_training_set_file_not_found():
    """load_training_set() echoue sur un fichier inexistant."""
    with pytest.raises(TrainingSetError, match="illisible"):
        load_training_set("/nonexistent/training.json")


def test_load_training_set_invalid_json(tmp_path):
    """load_training_set() echoue sur un JSON invalide."""
    path = tmp_path / "bad.json"
    path.write_text("not json")
    with pytest.raises(TrainingSetError, match="illisible"):
        load_training_set(path)


def test_load_training_set_wrong_schema(tmp_path):
    """load_training_set() refuse un mauvais schema."""
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"schema": "wrong", "samples": []}))
    with pytest.raises(TrainingSetError, match="jeu"):
        load_training_set(path)


def test_load_training_set_invalid_sample(tmp_path):
    """load_training_set() refuse un exemple invalide."""
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({
        "schema": TRAINING_SCHEMA,
        "samples": [{"bad": "sample"}],
    }))
    with pytest.raises(TrainingSetError, match="invalide"):
        load_training_set(path)


def test_load_training_set_with_features(tmp_path):
    """load_training_set() charge un exemple avec vecteur de features."""
    data = {
        "schema": TRAINING_SCHEMA,
        "samples": [{
            "features": [1.0] * len(FEATURE_NAMES),
            "label": "tunnel",
        }],
    }
    path = tmp_path / "training.json"
    path.write_text(json.dumps(data))
    samples = load_training_set(path)
    assert len(samples) == 1
    assert samples[0][1] == "tunnel"


# --- sample_vector ----------------------------------------------------------

def test_sample_vector_from_list():
    """sample_vector() retourne le vecteur tel quel pour une liste."""
    v = [1.0] * len(FEATURE_NAMES)
    assert sample_vector(v) == v


def test_sample_vector_from_flow():
    """sample_vector() calcule le vecteur depuis un flux."""
    flow = _sample_flow()
    v = sample_vector(flow)
    assert len(v) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in v)


# --- FlowPrediction ---------------------------------------------------------

def test_flow_prediction_to_dict():
    """FlowPrediction.to_dict() produit un dict correct."""
    p = FlowPrediction(
        flow="A->B:80",
        label="tunnel",
        confidence=0.92,
        rule_classification="normal",
    )
    d = p.to_dict()
    assert d["flow"] == "A->B:80"
    assert d["label"] == "tunnel"
    assert d["confidence"] == 0.92
    assert d["rule_classification"] == "normal"
