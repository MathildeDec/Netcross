#!/usr/bin/env python3
"""Vérifie la cohérence des traductions i18n (issue #299).

Trois contrôles, exécutés dans cet ordre :

1. **Couverture .po** : chaque msgid d'un .pot doit avoir un msgstr non vide
   dans chaque .po (fr_FR et en_US). Échec si une traduction manque.

2. **Chaînes orphelines** : chaque msgid d'un .po doit exister dans le .pot.
   Avertissement (pas un échec) si un msgid n'est plus utilisé.

3. **Fichiers .mo à jour** : chaque .mo doit être plus récent que son .po.
   Échec si un .mo est périmé (le .po a été modifié sans recompiler).

Usage :
    python3 scripts/check_i18n.py          # exit 0 = OK, exit 1 = échec
    python3 scripts/check_i18n.py --verbose  # détails par fichier

Intégration CI : appeler ce script dans une étape de vérification.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# -- Configuration -----------------------------------------------------------

LOCALE_DIR = Path(__file__).resolve().parent.parent / "locale"

DOMAINS = ["netcross-gtk4", "netcross-report", "netcross-cli"]
LOCALES = ["fr_FR", "en_US"]


# -- Parsing .po / .pot ------------------------------------------------------

def parse_po_entries(filepath: Path) -> dict[str, str]:
    """Extrait les paires msgid -> msgstr d'un fichier .po/.pot.
    Retourne un dict {msgid: msgstr}. Le msgstr "" signifie non traduit.
    """
    if not filepath.exists():
        return {}

    content = filepath.read_text(encoding="utf-8")
    entries: dict[str, str] = {}

    # Pattern : msgid "..." suivi (éventuellement sur la ligne suivante) de msgstr "..."
    # Gère les msgid/msgstr sur une seule ligne chacun.
    pattern = re.compile(
        r'^msgid\s+"((?:[^"\\]|\\.)*)"\s*\n'
        r'^msgstr\s+"((?:[^"\\]|\\.)*)"',
        re.MULTILINE,
    )

    for m in pattern.finditer(content):
        msgid = m.group(1)
        msgstr = m.group(2)
        # Ignorer l'en-tête vide
        if msgid == "":
            continue
        entries[msgid] = msgstr

    return entries


# -- Contrôles ---------------------------------------------------------------

def check_po_coverage(domain: str, locale: str, pot_entries: dict[str, str], verbose: bool) -> list[str]:
    """Vérifie que tous les msgid du .pot ont un msgstr non vide dans le .po."""
    errors: list[str] = []
    po_path = LOCALE_DIR / locale / "LC_MESSAGES" / f"{domain}.po"
    po_entries = parse_po_entries(po_path)

    if not po_entries and pot_entries:
        errors.append(f"  {locale}/{domain}.po : fichier vide ou introuvable ({po_path})")
        return errors

    missing = []
    empty = []
    for msgid in pot_entries:
        if msgid not in po_entries:
            missing.append(msgid)
        elif po_entries[msgid] == "":
            empty.append(msgid)

    if missing:
        errors.append(f"  {locale}/{domain}.po : {len(missing)} msgid manquant(s) :")
        for msg in missing[:5]:
            errors.append(f"    - \"{msg[:60]}\"")
        if len(missing) > 5:
            errors.append(f"    ... et {len(missing) - 5} autre(s)")

    if empty:
        errors.append(f"  {locale}/{domain}.po : {len(empty)} msgstr vide(s) :")
        for msg in empty[:5]:
            errors.append(f"    - \"{msg[:60]}\"")
        if len(empty) > 5:
            errors.append(f"    ... et {len(empty) - 5} autre(s)")

    if verbose and not missing and not empty:
        total = len(pot_entries)
        print(f"  {locale}/{domain}.po : {total}/{total} traduits (100%)")

    return errors


def check_orphaned(domain: str, locale: str, pot_entries: dict[str, str], verbose: bool) -> list[str]:
    """Détecte les msgid présents dans le .po mais plus dans le .pot."""
    warnings: list[str] = []
    po_path = LOCALE_DIR / locale / "LC_MESSAGES" / f"{domain}.po"
    po_entries = parse_po_entries(po_path)

    orphans = [msgid for msgid in po_entries if msgid not in pot_entries]
    if orphans:
        warnings.append(f"  {locale}/{domain}.po : {len(orphans)} msgid orphelin(s) :")
        for msg in orphans[:5]:
            warnings.append(f"    - \"{msg[:60]}\"")
        if len(orphans) > 5:
            warnings.append(f"    ... et {len(orphans) - 5} autre(s)")

    return warnings


def check_mo_freshness(domain: str, locale: str, verbose: bool) -> list[str]:
    """Vérifie que le .mo est plus récent que le .po."""
    errors: list[str] = []
    po_path = LOCALE_DIR / locale / "LC_MESSAGES" / f"{domain}.po"
    mo_path = LOCALE_DIR / locale / "LC_MESSAGES" / f"{domain}.mo"

    if not po_path.exists():
        return errors
    if not mo_path.exists():
        errors.append(f"  {locale}/{domain}.mo : fichier .mo manquant ({mo_path})")
        return errors

    po_mtime = po_path.stat().st_mtime
    mo_mtime = mo_path.stat().st_mtime

    if mo_mtime < po_mtime:
        errors.append(f"  {locale}/{domain}.mo : .mo périmé (po={po_mtime:.0f} > mo={mo_mtime:.0f})")

    if verbose:
        status = "OK" if mo_mtime >= po_mtime else "PÉRIMÉ"
        print(f"  {locale}/{domain}.mo : {status}")

    return errors


# -- Rapport -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Vérification cohérence traductions i18n")
    parser.add_argument("--verbose", "-v", action="store_true", help="détails par fichier")
    args = parser.parse_args()

    all_errors: list[str] = []
    all_warnings: list[str] = []

    print("=== Vérification i18n (issue #299) ===\n")

    for domain in DOMAINS:
        pot_path = LOCALE_DIR / f"{domain}.pot"
        if not pot_path.exists():
            all_errors.append(f"  {domain}.pot : fichier .pot manquant")
            continue

        pot_entries = parse_po_entries(pot_path)
        print(f"Domaine '{domain}' : {len(pot_entries)} chaînes dans le .pot")

        for locale in LOCALES:
            # 1. Couverture
            errs = check_po_coverage(domain, locale, pot_entries, args.verbose)
            all_errors.extend(errs)

            # 2. Orphelins
            warns = check_orphaned(domain, locale, pot_entries, args.verbose)
            all_warnings.extend(warns)

            # 3. .mo freshness
            errs = check_mo_freshness(domain, locale, args.verbose)
            all_errors.extend(errs)

    # -- Résumé --
    print(f"\n--- Résumé ---")
    print(f"Erreurs   : {len(all_errors)}")
    print(f"Avertissements : {len(all_warnings)}")

    if all_errors:
        print("\n=== ERREURS ===")
        for e in all_errors:
            print(e)

    if all_warnings:
        print("\n=== AVERTISSEMENTS ===")
        for w in all_warnings:
            print(w)

    if not all_errors and not all_warnings:
        print("\nTout est en ordre. Toutes les traductions sont complètes et à jour.")

    # Exit code : 1 si erreurs, 0 sinon
    sys.exit(1 if all_errors else 0)


if __name__ == "__main__":
    main()
