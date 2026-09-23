"""
netcross_core.config -- chargement de configuration depuis .netcross.toml
(issue #170).

Permet de ne plus tout passer par arguments CLI : un fichier de
configuration TOML à la racine du projet (ou spécifié via --config)
définit les valeurs par défaut.

Sections supportées :

    [analysis]
    points_order = ["LAN", "WAN"]
    bucket_seconds = 1.0
    rtp_clock_rate = 8000

    [output]
    format = "text"          # text | json | pdf | csv
    output_path = ""
    json_report = ""
    security_report = ""

    [security]
    enable = true

    [parallel]
    workers = 0              # 0 = auto (os.cpu_count())

Usage :

    from netcross_core.config import load_config, NetcrossConfig

    cfg = load_config()                     # cherche .netcross.toml
    cfg = load_config("/path/to/cfg.toml")  # fichier explicite
    print(cfg.analysis.points_order)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
# tomllib est dans la stdlib depuis Python 3.11.
# Pour 3.9-3.10, tomli est un fallback optionnel.
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    logger.exception("exception ModuleNotFoundError")
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        logger.exception("exception ModuleNotFoundError")
        tomllib = None  # type: ignore[assignment]


@dataclass
class AnalysisConfig:
    """Configuration de l'analyse."""

    points_order: list[str] = field(default_factory=list)
    bucket_seconds: float = 1.0
    rtp_clock_rate: int = 8000


@dataclass
class OutputConfig:
    """Configuration de la sortie."""

    format: str = "text"
    output_path: str = ""
    json_report: str = ""
    security_report: str = ""


@dataclass
class SecurityConfig:
    """Configuration de la sécurité."""

    enable: bool = True


@dataclass
class ParallelConfig:
    """Configuration de la parallélisation."""

    workers: int = 0  # 0 = auto


@dataclass
class NetcrossConfig:
    """Configuration globale de Netcross chargée depuis .netcross.toml."""

    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    parallel: ParallelConfig = field(default_factory=ParallelConfig)

    # Métadonnées
    source_path: str | None = None


def _parse_bool(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1", "on")
    return bool(val)


def load_config(config_path: str | Path | None = None) -> NetcrossConfig:
    """Charge la configuration depuis un fichier .netcross.toml.

    Si ``config_path`` est None, cherche dans l'ordre :
    1. Variable d'environnement ``NETCROSS_CONFIG``
    2. ``.netcross.toml`` dans le répertoire courant
    3. ``~/.netcross.toml`` (config utilisateur)

    Retourne une ``NetcrossConfig`` avec les valeurs par défaut si aucun
    fichier n'est trouvé (pas d'erreur).
    """
    if tomllib is None:
        return NetcrossConfig()

    path = _find_config(config_path)
    if path is None or not path.exists():
        return NetcrossConfig()

    with path.open("rb") as f:
        data = tomllib.load(f)

    cfg = NetcrossConfig(source_path=str(path))

    # [analysis]
    analysis = data.get("analysis", {})
    cfg.analysis.points_order = list(analysis.get("points_order", []))
    cfg.analysis.bucket_seconds = float(analysis.get("bucket_seconds", 1.0))
    cfg.analysis.rtp_clock_rate = int(analysis.get("rtp_clock_rate", 8000))

    # [output]
    output = data.get("output", {})
    cfg.output.format = str(output.get("format", "text"))
    cfg.output.output_path = str(output.get("output_path", ""))
    cfg.output.json_report = str(output.get("json_report", ""))
    cfg.output.security_report = str(output.get("security_report", ""))

    # [security]
    security = data.get("security", {})
    cfg.security.enable = _parse_bool(security.get("enable", True))

    # [parallel]
    parallel = data.get("parallel", {})
    cfg.parallel.workers = int(parallel.get("workers", 0))

    return cfg


def _find_config(config_path: str | Path | None) -> Path | None:
    """Trouve le fichier de configuration à charger."""
    if config_path is not None:
        return Path(config_path)

    # 1. Variable d'environnement
    env_path = os.environ.get("NETCROSS_CONFIG")
    if env_path:
        return Path(env_path)

    # 2. .netcross.toml dans le répertoire courant
    cwd_path = Path.cwd() / ".netcross.toml"
    if cwd_path.exists():
        return cwd_path

    # 3. ~/.netcross.toml
    home_path = Path.home() / ".netcross.toml"
    if home_path.exists():
        return home_path

    return None
