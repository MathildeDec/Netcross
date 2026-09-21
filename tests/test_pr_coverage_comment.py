"""Tests de scripts/pr_coverage_comment.py (couverture incrementale par PR).

Le script publie un commentaire sur la PR via l'API GitHub -- reseaux
systematiquement exclus des tests (meme convention que le reste du
projet) : on teste la construction du commentaire et la lecture des
totaux, pas les appels REST.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _charger_module():
    """Charge scripts/pr_coverage_comment.py comme module (pas de package)."""
    chemin = REPO_ROOT / "scripts" / "pr_coverage_comment.py"
    spec = importlib.util.spec_from_file_location("pr_coverage_comment", chemin)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_coverage_comment"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pcc():
    return _charger_module()


TOTAUX_REFERENCE = {
    "percent_covered": 76.742,
    "covered_lines": 9391,
    "num_statements": 12255,
    "covered_branches": 4322,
    "num_branches": 4728,
}


def _ecrire_rapport(tmp_path, totaux, nom):
    chemin = tmp_path / nom
    chemin.write_text(json.dumps({"totals": totaux}), encoding="utf-8")
    return chemin


def test_marqueur_present_le_commentaire_est_identifiable(pcc):
    commentaire = pcc._construire_commentaire(TOTAUX_REFERENCE, TOTAUX_REFERENCE)
    assert pcc.MARQUEUR in commentaire


def test_construire_commentaire_valeurs_et_delta(pcc):
    base = dict(TOTAUX_REFERENCE, percent_covered=76.742, covered_lines=9391, covered_branches=4322)
    pr = dict(TOTAUX_REFERENCE, percent_covered=77.051, covered_lines=9431, covered_branches=4361)
    commentaire = pcc._construire_commentaire(pr, base)
    assert "| Couverture | 76.7 % | 77.1 % | +0.3 pt |" in commentaire
    assert "| Instructions couvertes | 9391/12255 | 9431/12255 | +40 |" in commentaire
    assert "| Branches couvertes | 4322/4728 | 4361/4728 | +39 |" in commentaire
    assert "76,7 %" in commentaire  # rappel de la base de reference #224


def test_construire_commentaire_delta_negatif(pcc):
    pr = dict(TOTAUX_REFERENCE, percent_covered=75.0)
    commentaire = pcc._construire_commentaire(pr, TOTAUX_REFERENCE)
    assert "-1.7 pt" in commentaire


def test_lire_totaux_lit_le_rapport_coverage(pcc, tmp_path):
    chemin = _ecrire_rapport(tmp_path, TOTAUX_REFERENCE, "coverage-test.json")
    assert pcc._lire_totaux(str(chemin)) == TOTAUX_REFERENCE


def test_lire_totaux_fichier_absent_message_clair(pcc):
    with pytest.raises(FileNotFoundError):
        pcc._lire_totaux("/inexistant/coverage.json")
