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

from loguru import logger as _logger

_CONFIGURED = False


def configure_logging(level: str | None = None) -> None:
    """Configure loguru (idempotent). Level depuis NETCROSS_LOG_LEVEL ou paramètre."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    if level is None:
        level = os.environ.get("NETCROSS_LOG_LEVEL", "INFO").upper()

    _logger.remove()
    _logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
    )
    _CONFIGURED = True


def get_logger(name: str):
    """Retourne un logger loguru configuré pour le module ``name``."""
    if not _CONFIGURED:
        configure_logging()
    return _logger.bind(name=name)
