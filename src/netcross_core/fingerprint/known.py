"""
netcross_core.fingerprint.known -- base de correspondances empreinte ->
nom d'outil (issue #143, critere d'acceptation "base de fingerprints
connus chargeable").

Format du fichier JSON (`known_fingerprints.json`, a cote de ce module) :
{"ja4": {"<empreinte JA4>": "<nom d'outil>", ...},
 "hassh": {"<empreinte HASSH>": "<nom d'outil>", ...}}

Les valeurs livrees ici sont un point de depart illustratif (curl,
Chrome, OpenSSH...), PAS une base exhaustive ni verifiee contre du
trafic reel (voir la reserve de `tls_ja4.compute_ja4` sur la conformite
exacte du calcul JA4) -- a completer/corriger au fil de captures reelles
confrontees a une base publique (ex: ja4db.com) ou generees soi-meme
(`openssl s_client`, `curl -v`, un client OpenSSH connu...).

`load_known_fingerprints` accepte un chemin de fichier alternatif (une
base maintenue par l'utilisateur, plus a jour ou plus large) ; sans
argument elle charge le fichier livre avec le projet.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DEFAULT_PATH = Path(__file__).with_name("known_fingerprints.json")


@lru_cache(maxsize=8)
def _load_cached(path: str) -> dict[str, dict[str, str]]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {"ja4": data.get("ja4", {}), "hassh": data.get("hassh", {})}


def load_known_fingerprints(path: str | Path | None = None) -> dict[str, dict[str, str]]:
    """Charge la base {"ja4": {...}, "hassh": {...}}. Renvoie une base
    vide (jamais d'exception) si `path` est absent ou illisible -- une
    base de fingerprints manquante ne doit jamais faire echouer l'analyse,
    seulement priver l'analyste de l'identification lisible de l'outil."""
    try:
        return _load_cached(str(path or _DEFAULT_PATH))
    except (OSError, json.JSONDecodeError):
        return {"ja4": {}, "hassh": {}}


def identify_tool(
    fingerprint_type: str, fingerprint: str, known: dict[str, dict[str, str]] | None = None
) -> str | None:
    """Nom d'outil connu pour `fingerprint` ("ja4" ou "hassh"), None si
    absent de la base (charge la base livree par defaut si `known` n'est
    pas fourni -- eviter de la recharger a chaque paquet quand on traite
    une capture entiere, voir `fingerprint.report`)."""
    known = known if known is not None else load_known_fingerprints()
    return known.get(fingerprint_type, {}).get(fingerprint)
