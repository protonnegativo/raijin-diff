# ⚡ Raijin Diff

[![CI](https://github.com/protonnegativo/raijin-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/protonnegativo/raijin-diff/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/protonnegativo/raijin-diff)](https://github.com/protonnegativo/raijin-diff/releases/latest)
[![License: MIT](https://img.shields.io/github/license/protonnegativo/raijin-diff)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/protonnegativo/raijin-diff.svg)](https://pkg.go.dev/github.com/protonnegativo/raijin-diff)
[![Go Report Card](https://goreportcard.com/badge/github.com/protonnegativo/raijin-diff)](https://goreportcard.com/report/github.com/protonnegativo/raijin-diff)

**What changed between two runs of any Raijin tool: every new and resolved finding, every location added or removed, every status or severity that changed, and nothing else.**

`raijin-diff` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It reads two outputs of the same Raijin tool (`raijin-scan`, `raijin-probe`, `raijin-subs`, `raijin-ports`, `raijin-crawl`, ...) and returns the **Raijin Schema**: one compact JSON where the findings are the changes, ranked by severity, the groups are the group-level changes, and everything that did not change is counted, not listed. It runs no engine and sends no packets.

## Why not just read both runs, or `diff -u` them?

An agent that reruns a scan wants to know what is new. Reading both outputs costs both outputs, and the agent still has to compare them itself. `diff -u` of the pretty JSON is smaller, but it is a text diff: an added location shows up as one `+` line inside a list, often without the finding it belongs to in the 3 lines of context, a severity change is a `-`/`+` pair the agent has to pair up, and a probe URL whose status went from 200 to 403 is a removal in one finding and an addition in another, hundreds of lines apart.

Here is what an agent reads to learn what changed between two runs (tokens, `o200k_base`):

```
subs, gitlab.com: 824 names, 22 changes (a dangling CNAME, 2 IPs moved, names added and gone)
  raijin-diff   ▋                       1,144 tokens
  diff -u       █▉                      3,177 tokens
  old + new     ████████████████████   33,770 tokens

subs, shopify.com: 545 names, most behind one wildcard; 6 names new, 4 gone
  raijin-diff   ▋                         279 tokens
  diff -u       ██▎                     1,004 tokens
  old + new     ████████████████████    8,912 tokens

crawl, lab app: a new .env and SQL dump, /admin/ 403 -> 200, /graphql gone
  raijin-diff   ██▊                       308 tokens
  diff -u       ███████▊                  846 tokens
  old + new     ████████████████████    2,183 tokens

probe, 6 URLs: the admin panel now answers 403, a dead host came back
  raijin-diff   ██████████▎               344 tokens
  diff -u       ███████████████████▉      669 tokens
  old + new     ████████████████████      670 tokens
```

raijin-diff reads **29.5×** and **31.9×** fewer tokens than both subs runs, and **2.8×** and **3.6×** fewer than their `diff -u`. On the crawl it is **7.1×** smaller than both runs and **2.7×** smaller than `diff -u`. Each pair's bars are drawn to scale against the largest.

- **Nothing that changed is lost.** Every finding, group and location added or removed is listed, and so is every finding whose fields changed. `bench/verify.py` computes the changes on its own from the two inputs: 46 changes in the 5 pairs, none missing and none listed that is not a change.
- **Changes are explained.** A location that moved from one finding or group to another is one `changed` entry with the old values in `was`: `{"status":200, "was":{"id":"403-f84a6e68","status":403,...}}`, not a removal and an addition.
- **The important changes come first.** New and changed findings, ranked by severity, then the resolved ones.
- **A rerun with nothing new costs almost nothing.** The gitlab.com run diffed against itself is 110 tokens, against 16,992 for reading it again.
- **Unchanged items are counted, not listed.** The agent already has the new run, and `raw` points to it.

The gap is small on small outputs. On the 6-URL probe pair raijin-diff is only **1.9×** smaller than both runs and than `diff -u`, and on a 4-finding scan pair it is **1.4×** smaller than both runs and a little larger (309 tokens against 252) than reading the new run alone, which does not say what was resolved. raijin-diff writes each changed entry in full, with its fields, so the agent can act on it without opening the runs; that costs more than a bare line when there is little to leave out. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-diff/cmd/raijin-diff@latest
```

This installs the latest release.

### Versions

Releases are tagged automatically on every change. `raijin-diff --version` shows the release (`dev` plus the commit for a local build), and `raijin-mcp update` updates every Raijin tool at once.

Nothing else is needed: raijin-diff only reads JSON.

## Usage

```bash
raijin-diff old.json new.json                 # any two outputs of the same Raijin tool
raijin-diff old.json new.json --format table  # short human view
raijin-diff --max-bytes 0 old.json new.json   # no size limit

raijin-subs --scope scope.txt -d example.com > subs-$(date +%F).json
raijin-diff subs-2026-10-17.json subs-2026-10-24.json
```

Flags can go before or after the two files. The files must come from the same tool: comparing a raijin-scan run with a raijin-probe run, or a raijin-diff output with anything, is a usage error.

## Output

```json
{
  "schema_version": 1,
  "tool": "raijin-diff",
  "version": "v0.1.0",
  "target": "raijin-crawl: bench/fixtures/crawl-app/old.json -> bench/fixtures/crawl-app/new.json",
  "summary": "2 new, 1 resolved and 1 changed findings",
  "origin": "http://localhost:19501",
  "findings": [
    {"id": "200-a2adf96a", "change": "new", "severity": "high", "tags": ["file", "admin"], "route": "/backup/db.sql", "status": 200, "type": "application/sql", "via": ["robots.txt"]},
    {"id": "200-e5a7db04", "change": "new", "severity": "high", "tags": ["file"], "route": "/.env", "status": 200, "type": "text/plain", "via": ["robots.txt"]},
    {"id": "200-42d9ddaa", "change": "changed", "severity": "medium", "tags": ["admin"], "route": "/admin/", "status": 200, "was": {"id": "403-f84a6e68", "tags": ["admin", "auth"], "status": 403}},
    {"id": "400-2688534c", "change": "resolved", "severity": "low", "tags": ["api"], "route": "/graphql", "status": 400, "type": "application/json"}
  ],
  "groups": [],
  "omitted": {"unchanged_findings": 17, "unchanged_groups": 10, "unchanged_locations": 29},
  "raw": "/.../raijin-diff/bench/fixtures/crawl-app/new.json"
}
```

That is a real run on the `crawl-app` benchmark pair, with one entry per line here, the `raw` path shortened and `version` as a release binary prints it (a local build prints `dev-<commit>`); the tool writes it as one line. These raijin-crawl routes have no `locations` because their only URL is the route itself, as in raijin-crawl's own output.

Each finding and group is the entry as the tool wrote it, with every field it had, plus:

- **`change`**:
  - `new`: the old run did not have this finding or group; `locations` are all of its locations.
  - `added`: it was there before; `locations` are the ones it did not have.
  - `changed`: a finding whose fields changed (a template's severity went from medium to high), or locations that moved from one finding or group to another (a probe URL whose status went from 200 to 403, a name whose IP changed, a crawl route that stopped answering 403). The entry is the new one; `locations` are the ones the change applies to.
  - `resolved`: the new run no longer has this finding or group; the entry is the old one, with all the locations it had.
  - `removed`: it is still there, but no longer at these `locations`.
- **`was`**, on `changed` entries: the old value of every field that differs, `null` for a field the old entry did not have, and the old `id` when the locations moved. `"severity": null` in `was` means the location was in a group before; a `was` with a `severity` on a group entry means it was a finding.

What goes where:

- **`findings`**: the changes of findings, ranked: first `new`, `changed` and `added`, by severity (then confidence, then number of locations), then `resolved` and `removed`, by their old severity. A finding's location that moved into a group is ranked with the resolved ones.
- **`groups`**: the changes of groups (new and removed locations per group, groups that appeared or went away, locations that moved between groups).
- **`omitted`**: `unchanged_findings`, `unchanged_groups` and `unchanged_locations` count what did not change. They are not listed: the agent already has the new run, and **`raw`** is the path of the new run's file.
- **`origin`** is written when both raijin-crawl runs crawled the same origin, since their routes and locations are relative to it.

### Identity

Two entries are the same when the Raijin Schema says so:

- **A finding is its `id`** (the tool is the same in both runs). The Raijin tools build ids that stay the same while the finding does not change.
- **A group is its `id` and every other field but its `locations`**: for raijin-scan, the id and the variants; for raijin-ports, the id and the ports; for raijin-probe and raijin-subs, the id and the response or DNS answer.
- **A location is its exact string.** `https://a/.env [K=v]` and `https://a/.env [K=w]` are two locations, so an extracted value that changed is a removed location and an added one (or a `changed` entry, see below). An entry with a `route` and no `locations` has one location, the route (raijin-crawl's rule).

`count` and `new` are not compared: `count` is how many locations the tool's budget kept, and `new` is relative to that tool's `--state` file. Values are compared as JSON, so `&` and `&` are equal and a `--pretty` input works too.

A location that was in exactly one entry in the old run and in exactly one other entry in the new run **moved**, and it is one `changed` entry. raijin-probe, raijin-subs and raijin-crawl put each URL, name or route in one entry whose id holds its status or answer, so this is how a status or IP change shows up. When a location is in several entries in a run (a raijin-scan URL matched by two templates), it is not paired: it is listed as added and removed where it was added and removed.

### Lossless for change

Every added and removed finding, group and location is in the output, and so is every field change. Only the budget can cut, and every cut is counted:

- **Budget:** `--max-bytes` (16,000 by default; 0 means no limit) keeps the output bounded when two runs share little. It cuts in this order until the JSON fits:
  1. group locations;
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Resolved findings rank after every addition, so they are cut first. Every cut is counted in `omitted`, `budget.truncated` is set, and `next` says to rerun with `--max-bytes 0`: `raw` has only the new run, so what was cut from the resolved side is not in it. `--max-items` caps the number of findings (0, the default, keeps all).
- **Inputs that were cut:** if either run was cut by its own tool's budget (`budget.truncated`, or a `count` larger than the locations listed), what that tool cut cannot be compared, and an error of kind `truncated_input` says so, with a hint to rerun that tool with a higher `--max-bytes`.
- **Errors of the runs** are passed on as `input_error` (an engine that failed in the new run explains findings that look resolved). Two raijin-crawl runs of different origins give an `origin_changed` error.

Fields an agent can rebuild are left out to save tokens: `omitted`, `errors` and `next` when they are empty, `budget` when nothing was cut, `count` when every location is listed, and `locations` when the only one is the entry's `route`.

The JSON is compact (one line) by default; `--pretty` indents it. `--format table` prints a short human view: one line per finding change with its locations marked `+`, `-` or `~`, and one line per group change with its count.

The banner is **off by default**. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched). Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size (0: no limit); cuts are counted in `omitted` |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--banner` | false | print the banner to stderr |
| `--version` | | print the version |

raijin-diff has no `--scope`, `--input`, `--raw`, `--state` or engine path: it runs no engine and touches no target. The scope was applied by the tool that made each run.

`schema_version` (currently `1`) is the first field of every output. An input written with a newer `schema_version` than this build understands is refused with an error of `kind:"schema_version"` in the JSON on stdout, and nothing is compared; update raijin-diff.

Exit codes follow the Raijin rule: `0` when the diff worked (with or without changes); `2` for a structured error, with the JSON on stdout for the agent to tell apart by its `kind` (here, an input with a newer `schema_version`); `1` for a usage error, with a message on stderr and nothing on stdout (wrong number of files, a file that is missing or is not a Raijin output, two different tools, a raijin-diff output as input, an invalid flag). raijin-diff has no `--scope` and no engine, so it has no `kind:"scope"` error and no missing-engine error.

## Development

```bash
go test ./...
go vet ./...
bench/run.sh            # PY=<python with tiktoken>
```

raijin-diff depends only on the standard library and [raijin-core](https://github.com/protonnegativo/raijin-core), the shared Raijin Schema code. `bench/fixtures.py` rebuilds the benchmark pairs from the sibling tools' own fixtures (`FIXTURES=1 bench/run.sh`).

## Responsible use

raijin-diff only reads files. The runs it compares should come from targets you are authorized to test.
