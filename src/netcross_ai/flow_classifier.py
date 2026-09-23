"""Classification de flux avec score de confiance (foret aleatoire).

Jeu d'entrainement : JSON ``netcross.ai.training/1`` -- une liste
d'exemples ``{"flow": {...stats FLOW-4...}, "label": "tunnel"}``. Il se
constitue avec ``--ai-training-export`` (flux de la capture pre-etiquetes par
les regles FLOW-4), que l'analyste corrige et complete (tunnel, c2,
exfiltration...). Comme la baseline, aucun modele pickle : reentraine a
chaque chargement, graine fixe.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from netcross_ai.features import flow_features, flow_key
from netcross_ai.optional import require_ml

TRAINING_SCHEMA = "netcross.ai.training/1"
MIN_SAMPLES = 10
SUGGESTED_LABELS = ("normal", "interactif", "transfert", "obfusque", "tunnel", "c2", "exfiltration")


class TrainingSetError(ValueError):
    """Jeu d'entrainement invalide."""


def export_training_set(flows: list[dict], path: str | Path) -> int:
    """Ecrit les flux pre-etiquetes (classification FLOW-4) a relire/corriger."""
    samples = [{"flow": f, "label": f.get("classification") or "normal"} for f in flows]
    data = {"schema": TRAINING_SCHEMA, "labels_suggeres": list(SUGGESTED_LABELS), "samples": samples}
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return len(samples)


def load_training_set(path: str | Path) -> list[tuple[dict, str]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrainingSetError(f"jeu d'entrainement illisible ({path}) : {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != TRAINING_SCHEMA:
        raise TrainingSetError(f"{path} n'est pas un jeu {TRAINING_SCHEMA}.")
    samples = []
    for i, item in enumerate(data.get("samples") or []):
        if not (isinstance(item, dict) and isinstance(item.get("flow"), dict) and item.get("label")):
            raise TrainingSetError(f"{path} : exemple {i} invalide (attendu {{'flow': {{...}}, 'label': '...'}}).")
        samples.append((item["flow"], str(item["label"])))
    return samples


@dataclass
class FlowPrediction:
    flow: str
    label: str
    confidence: float
    rule_classification: str

    def to_dict(self) -> dict:
        return {
            "flow": self.flow,
            "label": self.label,
            "confidence": self.confidence,
            "rule_classification": self.rule_classification,
        }


class FlowClassifier:
    def __init__(self, samples: list[tuple[dict, str]]):
        require_ml("La classification de flux")
        labels = Counter(label for _f, label in samples)
        if len(samples) < MIN_SAMPLES or len(labels) < 2:
            raise TrainingSetError(
                f"jeu d'entrainement insuffisant : {len(samples)} exemple(s), {len(labels)} classe(s) "
                f"({MIN_SAMPLES} exemples et 2 classes minimum)."
            )
        from sklearn.ensemble import RandomForestClassifier

        self.labels = dict(labels)
        self._model = RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced")
        self._model.fit([flow_features(f) for f, _l in samples], [label for _f, label in samples])

    def predict(self, flows: list[dict]) -> list[FlowPrediction]:
        if not flows:
            return []
        probas = self._model.predict_proba([flow_features(f) for f in flows])
        classes = list(self._model.classes_)
        out = []
        for flow, row in zip(flows, probas):
            best = max(range(len(classes)), key=lambda i: row[i])
            out.append(
                FlowPrediction(
                    flow=flow_key(flow),
                    label=str(classes[best]),
                    confidence=round(float(row[best]), 3),
                    rule_classification=str(flow.get("classification", "")),
                )
            )
        return out
