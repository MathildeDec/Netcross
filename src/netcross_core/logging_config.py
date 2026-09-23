"""
netcross_core.logging_config -- configuration centrale du logging (issue #245).

Configure loguru avec un format structuré et un niveau configurable via la
variable d'environnement ``NETCROSS_LOG_LEVEL`` (défaut : INFO).

Usage dans les modules :

    from netcross_core.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("demarrage de l'analyse")
    logger.debug("paquet reçu : src={} dst={}", pkt.src, pkt.dst)

Ne configure le handler qu'une seule fois (idempotent) -- un module qui
importe ``get_logger`` peut le faire sans risque de doubler les handlers.
"""

from __future__ import annotations

import os
import sys


_CONFIGURED = False
_logger = None


def _get_loguru():
    """Import lazy de loguru pour etre fork-safe."""
    global _logger
    if _logger is not None:
        return _logger
    try:
        from loguru import logger as lu
        _logger = lu
        return _logger
    except Exception:
        return None


def configure_logging(level: str | None = None) -> None:
    """Configure loguru (idempotent). Level depuis NETCROSS_LOG_LEVEL ou paramètre."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    if level is None:
        level = os.environ.get("NETCROSS_LOG_LEVEL", "INFO").upper()

    lu = _get_loguru()
    if lu is not None:
        try:
            lu.remove()
            lu.add(
                sys.stderr,
                level=level,
                format=(
                    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
                    "<level>{level: <8}</level> | "
                    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                    "<level>{message}</level>"
                ),
            )
        except Exception:
            pass
    _CONFIGURED = True


class _NullLogger:
    """Logger de repli si loguru est indisponible ou corrompu (apres fork)."""
    def __getattr__(self, _name: str):
        return lambda *a, **kw: None


def get_logger(name: str):
    """Retourne un logger loguru configuré pour le module ``name``.

    Fork-safe : retourne un logger nul si loguru est corrompu
    (typiquement apres un fork() dans un ProcessPoolExecutor).
    """
    global _CONFIGURED
    if not _CONFIGURED:
        configure_logging()
    lu = _get_loguru()
    if lu is None:
        return _NullLogger()
    try:
        return lu.bind(name=name)
    except Exception:
        return _NullLogger()
