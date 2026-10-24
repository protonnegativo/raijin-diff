#!/usr/bin/env bash
# Reproducible token benchmark: reading two runs of a Raijin tool (or their diff -u) vs raijin-diff.
#
# usage: bench/run.sh [workdir]
#        FIXTURES=1 bench/run.sh [workdir]   rebuild bench/fixtures from the sibling tools first
# needs: go, python3 with tiktoken (pip install tiktoken), diff; FIXTURES=1 also needs the sibling repos
#        (raijin-scan, raijin-probe, raijin-subs, raijin-crawl) next to this one, or RAIJIN_SRC=<dir>
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>
#
# Safety: nothing is scanned. The pairs are built from the engine output the sibling tools keep in their
# own fixtures, replayed with --input.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
SRC=${RAIJIN_SRC:-$(cd "$ROOT/.." && pwd)}
mkdir -p "$W"
echo "workdir: $W"

(cd "$ROOT" && go build -o "$W/raijin-diff" ./cmd/raijin-diff)

if [ "${FIXTURES:-}" = 1 ]; then
  for t in scan probe subs crawl; do
    (cd "$SRC/raijin-$t" && go build -o "$W/raijin-$t" "./cmd/raijin-$t")
  done
  python3 "$HERE/fixtures.py" "$SRC" "$W" "$HERE/fixtures"
fi

pretty() { python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), indent=2, ensure_ascii=False))' "$1"; }

scenario() {
  local name=$1
  local f=bench/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # What an agent reads without raijin-diff: both runs as the tool wrote them, or a diff -u of their
  # --pretty forms (diff -u of the compact one-line JSON is the two lines, nothing saved).
  cat "$ROOT/$f/old.json" "$ROOT/$f/new.json" > "$o/both.json"
  pretty "$ROOT/$f/old.json" > "$o/old.pretty.json"
  pretty "$ROOT/$f/new.json" > "$o/new.pretty.json"
  diff -u "$o/old.pretty.json" "$o/new.pretty.json" > "$o/diff-u.txt" || true
  (cd "$ROOT" && "$W/raijin-diff" "$f/old.json" "$f/new.json") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-diff" "$f/old.json" "$f/new.json" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-diff" "$f/old.json" "$f/new.json" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$ROOT/$f/old.json" "$ROOT/$f/new.json" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "old + new (both runs)=$o/both.json" \
    "new run only=$ROOT/$f/new.json" \
    "diff -u of --pretty=$o/diff-u.txt" \
    "raijin-diff JSON (default)=$o/raijin.json" \
    "raijin-diff --pretty=$o/raijin_pretty.json" \
    "raijin-diff --format table=$o/raijin_table.txt"
}

for d in "$HERE"/fixtures/*/; do scenario "$(basename "$d")"; done

# A rerun where nothing changed: the new gitlab.com run against itself.
o=$W/rerun
mkdir -p "$o"
f=bench/fixtures/subs-gitlab
(cd "$ROOT" && "$W/raijin-diff" "$f/new.json" "$f/new.json") > "$o/raijin.json"
echo; echo "## rerun, nothing changed (subs-gitlab new.json twice): $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
python3 "$HERE/verify.py" "$ROOT/$f/new.json" "$ROOT/$f/new.json" "$o/raijin.json"
"$PY" "$HERE/count_tokens.py" "new run only=$ROOT/$f/new.json" "raijin-diff JSON (default)=$o/raijin.json"
