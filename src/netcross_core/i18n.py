"""Runtime helpers for Netcross gettext translations."""

from __future__ import annotations

import gettext as _gettext
import locale as _locale
from pathlib import Path
from typing import Callable

DOMAIN = "netcross"
LOCALE_DIR = Path(__file__).resolve().parents[2] / "lang"

_translate: Callable[[str], str] = lambda message: message
_ntranslate: Callable[[str, str, int], str] = lambda singular, plural, count: singular if count == 1 else plural


def _normalise_locale(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(".", 1)[0].replace("-", "_")


def resolve_locale(requested: str | None = None) -> str | None:
    """Return an explicit locale or the current system locale without encoding."""
    if requested:
        return _normalise_locale(requested)
    try:
        current, _encoding = _locale.getlocale()
    except ValueError:
        return None
    return _normalise_locale(current)


def install(locale_name: str | None = None, *, localedir: Path | str = LOCALE_DIR) -> None:
    """Install Netcross translations, falling back to original messages safely."""
    global _translate, _ntranslate
    languages = [resolved] if (resolved := resolve_locale(locale_name)) else None
    translations = _gettext.translation(
        DOMAIN,
        localedir=str(localedir),
        languages=languages,
        fallback=True,
    )
    _translate = translations.gettext
    _ntranslate = translations.ngettext


def gettext(message: str) -> str:
    """Translate one user-visible message."""
    return _translate(message)


def ngettext(singular: str, plural: str, count: int) -> str:
    """Translate a plural user-visible message."""
    return _ntranslate(singular, plural, count)


_ = gettext
