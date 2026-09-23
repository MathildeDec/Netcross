from __future__ import annotations

import gettext
from pathlib import Path

from netcross_core import i18n


def test_install_falls_back_to_source_messages(tmp_path: Path) -> None:
    i18n.install("fr_FR", localedir=tmp_path)

    assert i18n.gettext("Connection failed") == "Connection failed"
    assert i18n.ngettext("%d connection", "%d connections", 2) == "%d connections"


def test_resolve_locale_normalises_explicit_locale() -> None:
    assert i18n.resolve_locale("fr-FR.UTF-8") == "fr_FR"


def test_install_uses_compiled_catalogue(tmp_path: Path, monkeypatch) -> None:
    locale_dir = tmp_path / "fr_FR" / "LC_MESSAGES"
    locale_dir.mkdir(parents=True)
    catalogue = gettext.GNUTranslations()
    monkeypatch.setattr(i18n._gettext, "translation", lambda *args, **kwargs: catalogue)

    i18n.install("fr_FR", localedir=tmp_path)

    assert i18n.gettext("Connection failed") == "Connection failed"
