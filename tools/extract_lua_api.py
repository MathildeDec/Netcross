#!/usr/bin/env python3
"""
Extraction de l'API Lua Wireshark vers JSON structuré (issue #386).

Source : https://www.wireshark.org/docs/wsdg_html_chunked/
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

from bs4 import BeautifulSoup, Tag

BASE_URL = "https://www.wireshark.org/docs/wsdg_html_chunked/"

PAGES = [
    ("lua_module_Dumper.html", ["Dumper", "PseudoHeader"]),
    ("lua_module_Field.html", ["Field", "FieldInfo"]),
    ("lua_module_Gui.html", ["ProgDlg", "TextWindow"]),
    ("lua_module_Listener.html", ["Listener"]),
    ("lua_module_Pinfo.html", ["Address", "Column", "Columns", "NSTime", "Pinfo", "PrivateTable"]),
    ("lua_module_Proto.html", ["Dissector", "DissectorTable", "Pref", "Prefs", "Proto", "ProtoExpert", "ProtoField"]),
    ("lua_module_Tree.html", ["TreeItem"]),
    ("lua_module_Tvb.html", ["ByteArray", "Tvb", "TvbRange"]),
    ("lua_module_File.html", ["CaptureInfo", "CaptureInfoConst", "File", "FileHandler", "FrameInfo", "FrameInfoConst"]),
    ("lua_module_Dir.html", ["Dir"]),
    ("lua_module_Int64.html", ["Int64", "UInt64"]),
    ("lua_module_Struct.html", ["Struct"]),
    ("wsluarm_modules.html", ["GlobalFunctions"]),
]

# Match: "13.6.1.1. ByteArray.new(args)" or "13.6.1.3. bytearray:__concat(args)"
METHOD_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+([\w]+)[.:]([\w_]+)\s*\(([^)]*)\)")
# Match: "13.1.1.1. get_version()" (global functions, no class prefix)
GLOBAL_FN_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(\w+)\s*\(([^)]*)\)")


def fetch_page(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "netcross-lua-extractor/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def get_section_content(h4: Tag) -> Tag | None:
    """Retourne le <div class='section'> parent direct."""
    parent = h4.parent
    while parent:
        if isinstance(parent, Tag) and parent.name == "div" and "section" in parent.get("class", []):
            return parent
        parent = parent.parent
    return None


def extract_version(text: str) -> str:
    """Extrait une version Wireshark depuis un texte (ex: 'Starting in version 1.11.3')."""
    m = re.search(r"version\s+([\d.]+)", text, re.IGNORECASE)
    return m.group(1) if m else ""


def extract_method(h4: Tag, class_name: str, method_name: str, args_raw: str, section_num: str, title: str) -> dict:
    """Extrait une méthode complète depuis son <h4>.
    La doc Wireshark place Arguments/Returns/Examples dans la section suivante.
    """
    section = get_section_content(h4)
    description = ""
    args = []
    returns = []
    examples = []

    if not section:
        return {
            "classe": class_name,
            "méthode": method_name,
            "signature": title,
            "description": "",
            "arguments": [],
            "retours": [],
            "exemples": [],
            "section": section_num,
        }

    # Description: <p> qui suivent le titlepage dans la section courante
    started = False
    for child in section.children:
        if not isinstance(child, Tag):
            continue
        cls = child.get("class", [])
        if child.name == "div" and "titlepage" in cls:
            started = True
            continue
        if not started:
            continue
        if child.name == "p":
            description += " " + clean(child.get_text())
        elif child.name == "pre":
            examples.append(child.get_text().strip())
        elif child.name in ("h5", "div"):
            break

    # Chercher Arguments/Returns/Examples dans la section suivante (souvent "Example")
    next_section = section.find_next_sibling("div", class_="section")
    if next_section:
        # Examples dans <pre>
        examples.extend(pre.get_text().strip() for pre in next_section.find_all("pre", recursive=False))

        # Arguments et Returns après les <h5>
        for h5 in next_section.find_all("h5", recursive=False):
            h5_text = clean(h5.get_text()).lower()
            if "argument" in h5_text:
                # Les <dl class="variablelist"> qui suivent ce <h5>
                for dl in h5.find_all_next("dl", class_="variablelist"):
                    if get_section_content(dl) != next_section:
                        break
                    for dt in dl.find_all("dt", recursive=False):
                        term = clean(dt.get_text())
                        dd = dt.find_next_sibling("dd")
                        desc = clean(dd.get_text()) if dd else ""
                        optional = "(optional)" in term.lower()
                        term_clean = re.sub(r"\s*\(optional\)\s*", "", term, flags=re.IGNORECASE).strip()
                        args.append(
                            {
                                "nom": term_clean,
                                "type": "",
                                "optionnel": optional,
                                "description": desc,
                            }
                        )
            elif "return" in h5_text:
                for p in h5.find_all_next("p"):
                    if get_section_content(p) != next_section:
                        break
                    text = clean(p.get_text())
                    if text:
                        returns.append(text)
            elif "example" in h5_text:
                for pre in h5.find_all_next("pre"):
                    if get_section_content(pre) != next_section:
                        break
                    examples.append(pre.get_text().strip())

        # Aussi chercher les <pre> directement dans la section suivante
        for pre in next_section.find_all("pre"):
            text = pre.get_text().strip()
            if text not in examples:
                examples.append(text)

    # Aussi chercher dans la section courante (au cas où)
    for h5 in section.find_all("h5", recursive=False):
        h5_text = clean(h5.get_text()).lower()
        if "argument" in h5_text:
            for dl in h5.find_all_next("dl", class_="variablelist"):
                if get_section_content(dl) != section:
                    break
                for dt in dl.find_all("dt", recursive=False):
                    term = clean(dt.get_text())
                    dd = dt.find_next_sibling("dd")
                    desc = clean(dd.get_text()) if dd else ""
                    optional = "(optional)" in term.lower()
                    term_clean = re.sub(r"\s*\(optional\)\s*", "", term, flags=re.IGNORECASE).strip()
                    args.append(
                        {
                            "nom": term_clean,
                            "type": "",
                            "optionnel": optional,
                            "description": desc,
                        }
                    )
        elif "return" in h5_text:
            for p in h5.find_all_next("p"):
                if get_section_content(p) != section:
                    break
                text = clean(p.get_text())
                if text and text not in returns:
                    returns.append(text)

    return {
        "classe": class_name,
        "méthode": method_name,
        "signature": title,
        "description": clean(description),
        "arguments": args,
        "retours": returns,
        "exemples": examples,
        "section": section_num,
        "depuis_version": extract_version(description),
    }


def extract_from_page(html: str, expected_classes: list[str]) -> list[dict]:
    """Extrait toutes les méthodes d'une page."""
    soup = BeautifulSoup(html, "html.parser")
    results = []

    # Trouver tous les <h4> qui contiennent des signatures de méthode
    for h4 in soup.find_all("h4"):
        title = clean(h4.get_text())
        if not title:
            continue

        # Essayer Class.method() ou class:method()
        match = METHOD_RE.match(title)
        if match:
            section_num = match.group(1)
            class_name = match.group(2)
            method_name = match.group(3)
            args_raw = match.group(4)
        else:
            # Essayer les fonctions globales
            match = GLOBAL_FN_RE.match(title)
            if not match:
                continue
            section_num = match.group(1)
            class_name = "GlobalFunctions"
            method_name = match.group(2)
            args_raw = match.group(3)

        entry = extract_method(h4, class_name, method_name, args_raw, section_num, title)
        results.append(entry)

    return results


def main():
    output_path = Path("data/lua_api.json")
    if len(sys.argv) > 2 and sys.argv[1] == "--output":
        output_path = Path(sys.argv[2])

    all_entries = []

    for page_name, classes in PAGES:
        url = BASE_URL + page_name
        print(f"Récupération de {page_name} (classes: {', '.join(classes)})...")
        try:
            html = fetch_page(url)
            entries = extract_from_page(html, classes)
            all_entries.extend(entries)
            print(f"  → {len(entries)} méthodes extraites")
        except Exception as e:
            print(f"  ✗ Erreur: {e}")

    output = {
        "version_wireshark": "4.3",
        "date_generation": "2026-09-24",
        "source": BASE_URL,
        "classes": {},
    }

    # Normaliser les noms de classe : fusionner instance (minuscule) et classe (majuscule)
    # Construire un mapping insensible à la casse
    proper_names = {}
    for entry in all_entries:
        cn = entry.get("classe", "")
        if cn and cn[0].isupper():
            proper_names[cn.lower()] = cn
    # Ajouter aussi les classes attendues des PAGES
    for _, classes in PAGES:
        for cls in classes:
            proper_names[cls.lower()] = cls

    def normalize_class(name: str) -> str:
        if name in proper_names.values():
            return name
        return proper_names.get(name.lower(), name)

    for entry in all_entries:
        cn = normalize_class(entry.get("classe", ""))
        if not cn:
            continue
        if cn not in output["classes"]:
            output["classes"][cn] = {"nom": cn, "description": "", "methodes": []}
        output["classes"][cn]["methodes"].append(
            {
                "nom": entry["méthode"],
                "signature": entry["signature"],
                "description": entry["description"],
                "arguments": entry["arguments"],
                "retours": entry["retours"],
                "exemples": entry["exemples"],
                "section": entry.get("section", ""),
                "depuis_version": entry.get("depuis_version", ""),
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    total = sum(len(c["methodes"]) for c in output["classes"].values())
    print(f"\nJSON écrit dans {output_path}")
    print(f"Total: {len(output['classes'])} classes, {total} méthodes")
    for cn, ci in sorted(output["classes"].items()):
        print(f"  {cn}: {len(ci['methodes'])} méthodes")


if __name__ == "__main__":
    main()
