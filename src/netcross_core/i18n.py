"""
netcross_core.i18n -- internationalisation (issue #299).

Fournit `setup_gettext()` et l'alias `_()` pour marquer toutes les chaînes
utilisables par l'interface GTK4 et les rapports (PDF, JSON, HTML, texte).

Deux domaines de traduction :

- ``netcross-gtk4``  : interface graphique (app.py et modules netcross_gtk4).
- ``netcross-report`` : rapports (pdf.py, security_report.py, synthesis.py,
  rule_engine.py, triage.py, json_report.py, security_html.py, etc.).

Les fichiers .mo sont chargés depuis le répertoire ``locale/`` à la racine
du paquet installé. Si aucune traduction n'est trouvée, ``_()`` renvoie la
chaîne inchangée (le français codé en dur reste le fallback par défaut).

Usage dans les modules GTK4::

    from netcross_core.i18n import setup_gettext, _
    _ = setup_gettext("netcross-gtk4")
    label.set_text(_("Lancer l'analyse"))

Usage dans les modules de rapport::

    from netcross_core.i18n import setup_gettext, _
    _ = setup_gettext("netcross-report")
    Paragraph(_("Rapport de securite"), styles["H1b"])

Les CLIs utilisent le domaine ``netcross-cli``.
"""

from __future__ import annotations

import gettext as _gettext
import os
from pathlib import Path

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

# -- Constantes ---------------------------------------------------------------

# Répertoire des traductions : ``<paquet_installé>/locale/``.
# En mode développement (PYTHONPATH=src), on tombe sur ``src/locale/``.
_LOCALE_DIR = Path(__file__).resolve().parent.parent / "locale"

# Domaine par défaut (utilisé si un module ne précise pas le sien).
_DEFAULT_DOMAIN = "netcross"

# Cache des objets gettext.NullTranslation / GNUTranslation par domaine.
_translations: dict[str, _gettext.NullTranslations] = {}

# Domaine actif par module (pour que _() sache quel domaine consulter).
# En pratique, chaque module appelle setup_gettext() qui renvoie un _
# fermé sur son domaine. Le domaine global n'est utilisé que pour les
# cas où un module ne veut pas gérer son propre _.
_active_domain = _DEFAULT_DOMAIN


def _find_locale_dir() -> Path | None:
    """Cherche le répertoire locale/ dans l'ordre :
    1. variable d'environnement NETCROSS_LOCALE_DIR
    2. <paquet>/locale/ (installé ou src/)
    3. ./locale/ (répertoire courant)
    Retourne le premier qui existe, sinon None (gettext utilisera le
    NullTranslations par défaut).
    """
    env = os.environ.get("NETCROSS_LOCALE_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            return p
    pkg_locale = _LOCALE_DIR
    if pkg_locale.is_dir():
        return pkg_locale
    cwd_locale = Path.cwd() / "locale"
    if cwd_locale.is_dir():
        return cwd_locale
    return None


def _load_translation(domain: str) -> _gettext.NullTranslations:
    """Charge (ou récupère du cache) la traduction pour un domaine.
    Si aucun fichier .mo n'existe, renvoie NullTranslations (identité).
    """
    if domain in _translations:
        return _translations[domain]

    locale_dir = _find_locale_dir()
    if locale_dir is None:
        logger.debug("i18n: aucun répertoire locale/ trouvé, _() = identité")
        t = _gettext.NullTranslations()
    else:
        # Langue : NETCROSS_LANG si défini, sinon LANG (ex: fr_FR.UTF-8)
        lang = os.environ.get("NETCROSS_LANG") or os.environ.get("LANG", "")
        # Extraire le code langue (ex: "fr_FR.UTF-8" -> "fr_FR")
        lang = lang.split(".")[0] if lang else ""
        try:
            t = _gettext.translation(domain, localedir=str(locale_dir), languages=[lang] if lang else None)
            logger.debug("i18n: traduction '{}' chargée pour '{}' (lang={})", domain, locale_dir, lang)
        except FileNotFoundError:
            logger.debug("i18n: pas de .mo pour le domaine '{}' (lang={}), identité", domain, lang)
            t = _gettext.NullTranslations()

    _translations[domain] = t
    return t


def setup_gettext(domain: str = _DEFAULT_DOMAIN):
    """Initialise gettext pour un domaine et renvoie la fonction ``_()``.

    Le domaine correspond à un fichier ``locale/<lang>/LC_MESSAGES/<domain>.mo``.
    Chaque module appelle ``setup_gettext("netcross-gtk4")`` pour obtenir un
    ``_`` fermé sur son domaine.

    Si aucun fichier .mo n'existe, ``_()`` renvoie la chaîne inchangée.
    """
    translation = _load_translation(domain)

    def _(message: str, *args, **kwargs) -> str:
        return translation.gettext(message)

    # On attache aussi ngettext pour les pluriels
    def _n(singular: str, plural: str, n: int) -> str:
        return translation.ngettext(singular, plural, n)

    _.ngettext = _n  # type: ignore[attr-defined]
    return _


# Alias global pour les modules qui ne gèrent pas leur propre domaine.
# Utilise le domaine par défaut. Préférez setup_gettext() dans chaque module.
_ = setup_gettext(_DEFAULT_DOMAIN)
