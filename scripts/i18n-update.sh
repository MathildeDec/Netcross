#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANG_DIR="$ROOT/lang"
LOCALES_FILE="$LANG_DIR/locales.txt"
DOMAIN="netcross"
POT="$LANG_DIR/messages.pot"

for command in xgettext msgmerge msgfmt msginit; do
  command -v "$command" >/dev/null || { echo "gettext ($command) is required" >&2; exit 1; }
done

mkdir -p "$LANG_DIR"
mapfile -t SOURCES < <(find "$ROOT/src" -type f -name '*.py' -print | sort)
if ((${#SOURCES[@]} == 0)); then
  echo "No Python sources found under src/" >&2
  exit 1
fi

xgettext --language=Python --keyword=_ --keyword=ngettext:1,2 \
  --from-code=UTF-8 --package-name=Netcross --package-version=0 \
  --output="$POT" "${SOURCES[@]}"

while IFS= read -r locale || [[ -n "$locale" ]]; do
  [[ -z "$locale" || "$locale" == \#* ]] && continue
  po="$LANG_DIR/$locale.po"
  if [[ -f "$po" ]]; then
    msgmerge --update --backup=none "$po" "$POT"
  else
    msginit --no-translator --locale="$locale" --input="$POT" --output-file="$po"
  fi
  mo_dir="$LANG_DIR/$locale/LC_MESSAGES"
  mkdir -p "$mo_dir"
  msgfmt --check --output-file="$mo_dir/$DOMAIN.mo" "$po"
done < "$LOCALES_FILE"

echo "Updated gettext catalogues for $(grep -cvE '^(#|$)' "$LOCALES_FILE") locales."
