"""
netcross_core.compliance -- evaluateur minimal de conformite, huitieme et
neuvieme objets de contrat de la Session 0 (FEATURES.md section 13.3) :
`ReferenceProfile`/`ComplianceResult` (netcross_core.expert_model).

Volontairement MINIMAL (voir docstring de expert_model.py pour la
justification complete) : chaque metrique du registre `_METRIC_FUNCS` est
une agregation EXPLICITE et deja triviale a partir de champs `Report`
existants (jamais un `getattr(report, ref.metric)` direct -- la plupart
des champs `Report` sont des dict par point/segment, pas des scalaires
directement comparables a un seuil). Le statut ne distingue que CONFORME/
VIOLATION/INDETERMINE -- pas de nuance DEVIATION, explicitement la
matiere de la Session 7 dediee ("conformite", section 13.3).
"""

from __future__ import annotations

import operator as _operator

from netcross_core.expert_model import ComplianceResult, ReferenceProfile


def _metric_pmtud_blackhole_total(report) -> float:
    """Nombre total de noirs PMTUD detectes, tous segments confondus."""
    return float(sum(report.pmtud_blackhole.values()))


def _metric_loss_rate_pct(report) -> float:
    """Taux de perte global (%), agrege sur tous les points -- somme des
    pertes / somme des paquets vus, pas une moyenne des taux par point
    (qui ponderait a tort un point a faible volume comme un point a fort
    volume)."""
    seen = sum(report.seen_count.values())
    if not seen:
        return 0.0
    return sum(report.loss_count.values()) / seen * 100.0


# Registre des metriques evaluables -- voir ReferenceProfile.metric.
# Ajouter une metrique = ajouter une entree ici, aucune autre modification
# necessaire (evaluate_compliance() reste generique).
_METRIC_FUNCS = {
    "pmtud_blackhole_total": _metric_pmtud_blackhole_total,
    "loss_rate_pct": _metric_loss_rate_pct,
}

_OPERATORS = {
    "<=": _operator.le,
    "<": _operator.lt,
    ">=": _operator.ge,
    ">": _operator.gt,
    "==": _operator.eq,
}

# Referentiels par defaut, fournis a titre d'exemple minimal et reel --
# pas une liste exhaustive (voir Session 7 pour un vrai catalogue de
# referentiels/profils, section 13.3).
DEFAULT_REFERENCES = [
    ReferenceProfile(
        id="pmtud-no-blackhole",
        metric="pmtud_blackhole_total",
        operator="<=",
        threshold=0.0,
        unit="occurrence(s)",
        source="RFC 1191 (IPv4) / RFC 8201 (IPv6) -- un chemin PMTUD sain ne doit jamais rester bloque silencieusement",
    ),
    ReferenceProfile(
        id="loss-rate-max-1pct",
        metric="loss_rate_pct",
        operator="<=",
        threshold=1.0,
        unit="%",
        source="Bonne pratique operationnelle courante (pas une RFC) -- seuil de perte tolere pour un lien en bon etat",
    ),
]


def evaluate_compliance(report, references=None) -> list[ComplianceResult]:
    """Evalue `report` contre `references` (par defaut DEFAULT_REFERENCES
    ci-dessus). Une metrique absente de `_METRIC_FUNCS` produit un
    ComplianceResult a `INDETERMINE` plutot qu'une exception -- un
    referentiel mal configure ne doit jamais faire planter l'analyse."""
    if references is None:
        references = DEFAULT_REFERENCES
    results = []
    for ref in references:
        func = _METRIC_FUNCS.get(ref.metric)
        op = _OPERATORS.get(ref.operator)
        if func is None or op is None:
            results.append(ComplianceResult(ref, None, "INDETERMINE"))
            continue
        observed = func(report)
        status = "CONFORME" if op(observed, ref.threshold) else "VIOLATION"
        results.append(ComplianceResult(ref, observed, status))
    return results
