#!/usr/bin/env python3
"""pr_coverage_comment.py -- publie le commentaire de couverture d'une PR.

Suite de l'issue #224 (suivi de couverture en CI) : le workflow
.github/workflows/pr-coverage.yml execute pytest --cov deux fois (ref de
fusion de la PR, puis SHA de base de `dev`) et passe les deux rapports
JSON de coverage.py a ce script, qui publie ou met a jour un commentaire
sur la PR avec la couverture totale et le delta vs la base.

Appel :
    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo \
    python3 scripts/pr_coverage_comment.py \
        --pr-json coverage-pr.json \
        --base-json coverage-base.json \
        --pr-number 123

Volontairement stdlib seule (urllib), meme modele que le reste du
projet (voir scripts/generate_class_diagram.py). Aucun seuil bloquant :
la decision de calibrer --cov-fail-under reste a une issue de suivi.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

# Marqueur HTML invisible qui identifie le commentaire de couverture a
# mettre a jour (plutot qu'a dupliquer) d'un push a l'autre.
MARQUEUR = "<!-- netcross:couverture-pr -->"

API = "https://api.github.com"


def _lire_totaux(chemin: str) -> dict:
    """Extrait les totaux d'un rapport JSON de coverage.py."""
    with open(chemin, encoding="utf-8") as f:
        return json.load(f)["totals"]


def _pct(valeur: float) -> str:
    """76.7421... -> '76.7 %'."""
    return f"{valeur:.1f} %"


def _delta(pr: float, base: float) -> str:
    """Difference en points de pourcentage, signee, 1 decimale."""
    return f"{pr - base:+.1f} pt"


def _construire_commentaire(totaux_pr: dict, totaux_base: dict) -> str:
    """Construit le corps du commentaire de couverture (Markdown)."""
    lignes = [
        MARQUEUR,
        "## Couverture de tests (delta vs `dev`)",
        "",
        "| Métrique | Base (`dev`) | PR | Δ |",
        "|---|---|---|---|",
        "| Couverture | "
        f"{_pct(totaux_base['percent_covered'])} | "
        f"{_pct(totaux_pr['percent_covered'])} | "
        f"{_delta(totaux_pr['percent_covered'], totaux_base['percent_covered'])} |",
        "| Instructions couvertes | "
        f"{totaux_base['covered_lines']}/{totaux_base['num_statements']} | "
        f"{totaux_pr['covered_lines']}/{totaux_pr['num_statements']} | "
        f"{totaux_pr['covered_lines'] - totaux_base['covered_lines']:+d} |",
        "| Branches couvertes | "
        f"{totaux_base['covered_branches']}/{totaux_base['num_branches']} | "
        f"{totaux_pr['covered_branches']}/{totaux_pr['num_branches']} | "
        f"{totaux_pr['covered_branches'] - totaux_base['covered_branches']:+d} |",
        "",
        "Aucun seuil bloquant (voir #224) : la base de référence du 2026-09-21 est de 76,7 %.",
    ]
    return "\n".join(lignes)


def _appel_api(chemin: str, token: str, methode: str = "GET", corps: str | None = None) -> dict:
    """Appel REST GitHub minimal (urllib, pas de dependance tierce)."""
    requete = urllib.request.Request(
        f"{API}{chemin}",
        data=corps.encode() if corps else None,
        method=methode,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(requete) as reponse:
        return json.loads(reponse.read())


def _publier(repo: str, pr: int, corps: str, token: str) -> str:
    """Met a jour le commentaire existant (marqueur) ou en cree un."""
    commentaires = _appel_api(f"/repos/{repo}/issues/{pr}/comments?per_page=100", token)
    for c in commentaires:
        if MARQUEUR in c.get("body", ""):
            _appel_api(
                f"/repos/{repo}/issues/comments/{c['id']}",
                token,
                methode="PATCH",
                corps=json.dumps({"body": corps}),
            )
            return f"commentaire existant mis a jour ({c['html_url']})"
    cree = _appel_api(
        f"/repos/{repo}/issues/{pr}/comments",
        token,
        methode="POST",
        corps=json.dumps({"body": corps}),
    )
    return f"commentaire cree ({cree['html_url']})"


def main(argv: list[str]) -> int:
    parseur = argparse.ArgumentParser(description=__doc__)
    parseur.add_argument("--pr-json", required=True, help="rapport coverage.py de la PR")
    parseur.add_argument("--base-json", required=True, help="rapport coverage.py de la base")
    parseur.add_argument("--pr-number", required=True, type=int)
    arguments = parseur.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("GITHUB_TOKEN et GITHUB_REPOSITORY sont requis", file=sys.stderr)
        return 2

    corps = _construire_commentaire(
        _lire_totaux(arguments.pr_json),
        _lire_totaux(arguments.base_json),
    )
    print(_publier(repo, arguments.pr_number, corps, token))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
