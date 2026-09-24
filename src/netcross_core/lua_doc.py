"""
netcross_core.lua_doc -- banque SQLite locale de l'API Lua Wireshark
(issue #387, rattachee a #331).

Chargee depuis le JSON produit par tools/extract_lua_api.py (#386) via
scripts/build_lua_db.py. Meme convention que netcross_core.security.cve_db :
sqlite3 de la bibliotheque standard, aucune dependance reseau au runtime,
un fichier .db local.

Schema :
- ``meta(cle, valeur)`` : version_wireshark, date_generation, source --
  permet de savoir a quelle release correspond la banque ;
- ``classes(id, nom, description)`` ;
- ``methodes(id, classe_id, nom, signature, description, depuis_version)`` ;
- ``parametres(id, methode_id, nom, type, optionnel, description, ordre)`` ;
- ``retours(id, methode_id, type, description)`` ;
- ``exemples(id, methode_id, code)`` ;
- ``recherche`` : index FTS5 (classe, nom, signature, description) pour la
  recherche libre.

Le chargement est idempotent : la base est videe puis rechargee, ce qui
permet de la regenerer proprement a chaque nouvelle version de Wireshark.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

SCHEMA_VERSION = "1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    cle TEXT PRIMARY KEY,
    valeur TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS methodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    classe_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    nom TEXT NOT NULL,
    signature TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    depuis_version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS parametres (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    nom TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT '',
    optionnel INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    ordre INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS retours (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS exemples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    methode_id INTEGER NOT NULL REFERENCES methodes(id) ON DELETE CASCADE,
    code TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_methodes_classe ON methodes(classe_id);
CREATE INDEX IF NOT EXISTS idx_methodes_nom ON methodes(nom);
CREATE INDEX IF NOT EXISTS idx_parametres_methode ON parametres(methode_id, ordre);
CREATE INDEX IF NOT EXISTS idx_retours_methode ON retours(methode_id);
CREATE INDEX IF NOT EXISTS idx_exemples_methode ON exemples(methode_id);
CREATE VIRTUAL TABLE IF NOT EXISTS recherche USING fts5(
    classe, nom, signature, description,
    methode_id UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);
"""

_TABLES = ("recherche", "exemples", "retours", "parametres", "methodes", "classes", "meta")


@dataclass(frozen=True, slots=True)
class Parametre:
    """Un argument de methode."""

    nom: str
    type: str
    optionnel: bool
    description: str


@dataclass(frozen=True, slots=True)
class Methode:
    """Fiche complete d'une methode (ou fonction globale)."""

    classe: str
    nom: str
    signature: str
    description: str
    depuis_version: str
    parametres: list[Parametre] = field(default_factory=list)
    retours: list[str] = field(default_factory=list)
    exemples: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ResultatRecherche:
    """Une reponse de la recherche plein texte."""

    classe: str
    nom: str
    signature: str
    description: str
    methode_id: int


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Ouvre (et cree si besoin) la banque Lua."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def load_json(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, int]:
    """Charge le JSON de #386 dans la base (remplace le contenu existant).

    Retourne les compteurs inseres par table.
    """
    counts = {"classes": 0, "methodes": 0, "parametres": 0, "retours": 0, "exemples": 0}
    with conn:
        for table in _TABLES:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 -- noms de tables constants

        meta = {
            "version_wireshark": str(data.get("version_wireshark", "")),
            "date_generation": str(data.get("date_generation", "")),
            "source": str(data.get("source", "")),
            "schema_version": SCHEMA_VERSION,
        }
        conn.executemany("INSERT INTO meta(cle, valeur) VALUES (?, ?)", meta.items())

        for cls_name, cls_info in sorted(data.get("classes", {}).items()):
            cur = conn.execute(
                "INSERT INTO classes(nom, description) VALUES (?, ?)",
                (cls_name, cls_info.get("description", "")),
            )
            classe_id = cur.lastrowid
            counts["classes"] += 1
            for m in cls_info.get("methodes", []):
                cur = conn.execute(
                    "INSERT INTO methodes(classe_id, nom, signature, description, depuis_version) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        classe_id,
                        m.get("nom", ""),
                        m.get("signature", ""),
                        m.get("description", ""),
                        m.get("depuis_version", ""),
                    ),
                )
                methode_id = cur.lastrowid
                counts["methodes"] += 1
                for ordre, a in enumerate(m.get("arguments", [])):
                    conn.execute(
                        "INSERT INTO parametres(methode_id, nom, type, optionnel, description, ordre) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            methode_id,
                            a.get("nom", ""),
                            a.get("type", ""),
                            int(bool(a.get("optionnel", False))),
                            a.get("description", ""),
                            ordre,
                        ),
                    )
                    counts["parametres"] += 1
                for r in m.get("retours", []):
                    conn.execute(
                        "INSERT INTO retours(methode_id, type, description) VALUES (?, '', ?)",
                        (methode_id, r),
                    )
                    counts["retours"] += 1
                for code in m.get("exemples", []):
                    conn.execute("INSERT INTO exemples(methode_id, code) VALUES (?, ?)", (methode_id, code))
                    counts["exemples"] += 1
                conn.execute(
                    "INSERT INTO recherche(classe, nom, signature, description, methode_id) VALUES (?, ?, ?, ?, ?)",
                    (cls_name, m.get("nom", ""), m.get("signature", ""), m.get("description", ""), methode_id),
                )
    logger.info(
        "Banque Lua chargee : {} classes, {} methodes (Wireshark {})",
        counts["classes"],
        counts["methodes"],
        meta["version_wireshark"],
    )
    return counts


def load_json_file(conn: sqlite3.Connection, json_path: str | Path) -> dict[str, int]:
    """Charge un fichier JSON produit par tools/extract_lua_api.py."""
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    return load_json(conn, data)


def get_meta(conn: sqlite3.Connection) -> dict[str, str]:
    """Retourne les metadonnees (version Wireshark, date de generation...)."""
    return dict(conn.execute("SELECT cle, valeur FROM meta").fetchall())


def list_classes(conn: sqlite3.Connection) -> list[str]:
    """Liste les noms de classes, tries."""
    return [r[0] for r in conn.execute("SELECT nom FROM classes ORDER BY nom")]


def _fts_query(terme: str) -> str:
    """Transforme un texte libre en requete FTS5 sure (prefixe sur chaque mot)."""
    mots = [m.replace('"', "") for m in terme.split()]
    return " ".join(f'"{m}"*' for m in mots if m)


def search(conn: sqlite3.Connection, terme: str, limit: int = 20) -> list[ResultatRecherche]:
    """Recherche plein texte (FTS5) sur classe, nom, signature et description."""
    query = _fts_query(terme)
    if not query:
        return []
    rows = conn.execute(
        "SELECT classe, nom, signature, description, methode_id FROM recherche "
        "WHERE recherche MATCH ? ORDER BY rank LIMIT ?",
        (query, limit),
    ).fetchall()
    return [ResultatRecherche(r[0], r[1], r[2], r[3], int(r[4])) for r in rows]


def _load_methode(conn: sqlite3.Connection, row: tuple[Any, ...]) -> Methode:
    methode_id, classe, nom, signature, description, depuis = row
    params = [
        Parametre(r[0], r[1], bool(r[2]), r[3])
        for r in conn.execute(
            "SELECT nom, type, optionnel, description FROM parametres WHERE methode_id = ? ORDER BY ordre",
            (methode_id,),
        )
    ]
    retours = [
        r[0] for r in conn.execute("SELECT description FROM retours WHERE methode_id = ? ORDER BY id", (methode_id,))
    ]
    exemples = [r[0] for r in conn.execute("SELECT code FROM exemples WHERE methode_id = ? ORDER BY id", (methode_id,))]
    return Methode(classe, nom, signature, description, depuis, params, retours, exemples)


_METHODE_SELECT = (
    "SELECT m.id, c.nom, m.nom, m.signature, m.description, m.depuis_version "
    "FROM methodes m JOIN classes c ON c.id = m.classe_id "
)


def get_class(conn: sqlite3.Connection, nom: str) -> list[Methode] | None:
    """Fiche complete d'une classe (insensible a la casse), ou None si inconnue."""
    row = conn.execute("SELECT id FROM classes WHERE nom = ? COLLATE NOCASE", (nom,)).fetchone()
    if row is None:
        return None
    rows = conn.execute(_METHODE_SELECT + "WHERE m.classe_id = ? ORDER BY m.id", (row[0],)).fetchall()
    return [_load_methode(conn, r) for r in rows]


def get_methode(conn: sqlite3.Connection, methode_id: int) -> Methode | None:
    """Fiche complete d'une methode par identifiant."""
    row = conn.execute(_METHODE_SELECT + "WHERE m.id = ?", (methode_id,)).fetchone()
    return _load_methode(conn, row) if row else None
