# Token benchmark: reading two runs vs raijin-diff

How many tokens does an AI agent spend to learn what changed between two runs of a Raijin tool, and does raijin-diff lose any change? This benchmark takes pairs of real runs of the sibling tools, counts the tokens of each way to read the change, and checks that every change between the two runs is in the raijin-diff output.

Reproduce: `bench/run.sh` (set `PY=<python with tiktoken>`). It reads the pairs in `bench/fixtures`. `FIXTURES=1 bench/run.sh` rebuilds them first from the sibling repos (`raijin-scan`, `raijin-probe`, `raijin-subs`, `raijin-crawl` next to this one, or `RAIJIN_SRC=<dir>`); the rebuild is deterministic.

## Setup

- **Pairs.** Each sibling tool keeps the engine output of its own benchmark (its `raw` file) in its fixtures. `bench/fixtures.py` makes two copies of that engine output, applies realistic changes to one or both (drops the lines of some names or URLs, edits a field), and runs the sibling tool on each with `--input` and `--max-bytes 0`. So `old.json` and `new.json` are real outputs of the tool, and nothing in them is written by hand. The changes:
  - **subs-gitlab** (raijin-subs, gitlab.com, 820 then 824 names): 10 names are new (2 of them CNAMEs to third-party services, 5 that do not resolve), 6 are gone, 2 names moved to another IP, and one name with a CNAME into Cloudflare now gets NXDOMAIN, so raijin-subs reports it as a dangling CNAME (medium).
  - **subs-wildcard** (raijin-subs, shopify.com, 543 then 545 names, most behind the `*.shopify.com` wildcard): 6 names are new and 4 are gone.
  - **crawl-app** (raijin-crawl, the lab app of raijin-crawl's benchmark): a `.env` and a SQL dump appear, `/graphql` is gone, and `/admin/` answers 200 instead of 403.
  - **probe-sample** (raijin-probe, its 6-URL test sample): the admin panel now answers 403 like `c.example.com`, and `e.example.com`, which refused connections, serves the nginx welcome page.
  - **scan-sample** (raijin-scan, its test sample): a new critical CVE on `c`, the `.env` finding now also on `a`, the `.git/config` of `b` fixed, the `git-config` template raised from medium to high, and `a` now also detected as PHP.
- **Baselines**, what an agent reads without raijin-diff:
  - **old + new**: both runs as the tool wrote them (compact JSON).
  - **new run only**: the new run alone. It is cheaper, but it does not say what was resolved or what changed; it is listed for scale.
  - **`diff -u` of `--pretty`**: a unified diff (3 lines of context) of both runs indented the way `--pretty` does it. `diff -u` of the compact one-line JSON would be the two whole lines.
- **raijin-diff**: `raijin-diff old.json new.json` with the defaults (`--max-bytes 16000`, which no pair reached), plus `--pretty` and `--format table`.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.
- **Lossless check:** `bench/verify.py old.json new.json diff.json` computes the changes from the two inputs on its own, with the identity of the Raijin Schema (a finding is its id, a group is its id plus every field but its locations, a location is its exact string): every (entry, location) pair added or removed, and every finding whose fields changed. Then it reads the diff back and checks that each change is listed, that nothing listed is not a change, and that `omitted.unchanged_locations` is the number of locations that did not change.

## Results

| Pair | Changes | Missing | Not a change | old + new | new only | `diff -u` | **raijin-diff** | `--pretty` | `--format table` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| subs-gitlab | 22 | 0 | 0 | 33,770 | 16,992 | 3,183 | **1,135** | 1,601 | 301 |
| subs-wildcard | 10 | 0 | 0 | 8,912 | 4,466 | 1,010 | **270** | 380 | 28 |
| crawl-app | 5 | 0 | 0 | 2,183 | 1,116 | 852 | **299** | 472 | 117 |
| probe-sample | 4 | 0 | 0 | 670 | 294 | 675 | **335** | 497 | 130 |
| scan-sample | 5 | 0 | 0 | 433 | 252 | 582 | **300** | 450 | 136 |
| rerun, nothing changed (subs-gitlab new.json twice) | 0 | 0 | 0 | | 16,992 | | **101** | | |

Tokens, `o200k_base`. "Changes" are counted by `verify.py`: added and removed (entry, location) pairs, plus findings with changed fields. A moved location (a `changed` entry with an old id) counts as one added and one removed pair. 46 changes in the 5 pairs, none missing, none extra.

Against both runs, raijin-diff is **29.8×** (subs-gitlab), **33×** (subs-wildcard), **7.3×** (crawl-app), **2.0×** (probe-sample) and **1.4×** (scan-sample) smaller. Against `diff -u` it is **2.8×**, **3.7×**, **2.8×**, **2.0×** and **1.9×** smaller.

## What the numbers mean

- **The win grows with what did not change.** Two subs runs of 820 names share almost everything: raijin-diff lists 22 changes and counts 811 unchanged locations. On a 6-URL probe or a 4-finding scan there is little to leave out, and the diff costs about as much as one run.
- **On the smallest pair it is larger than the new run alone**: 300 tokens against 252 on scan-sample. raijin-diff writes each changed entry with all its fields (title, severity, CVSS, ...) and a `was` for the old values, so an agent can act on it without opening either run. The new run alone is cheaper but does not say that the `.git/config` of `b` was fixed or that `git-config` went from medium to high.
- **`diff -u` is a text diff, not a list of changes.** It is lossless as text, but in subs-gitlab the added name `grafana.cell-...` is a `+` line inside a `locations` list, and the finding it belongs to (`name-2cd3bd56`) is not in its 3 lines of context. The dangling CNAME is a new finding at the top of the file and a removed line in a group about 1,200 lines further down in the file; raijin-diff writes it as one `changed` entry with `"was":{"id":"cname-814cd73a","a":["172.65.164.33"],...}`. `diff -u` also repeats `target` and `summary`, which always differ.
- **A rerun with nothing new** costs 101 tokens: the summary `no changes`, the unchanged counts and the path of the new run.
- **`--format table`** is the cheapest, but it is a human view: group changes are one line each with their count, without the locations. The JSON is the lossless output.

## How each change shows up

From the pairs above (one entry per line, shortened only where marked):

```
crawl-app      {"id":"200-42d9ddaa","change":"changed","severity":"medium","tags":["admin"],"route":"/admin/","status":200,"was":{"id":"403-f84a6e68","tags":["admin","auth"],"status":403}}
probe-sample   {"id":"403-0f0d5a5e","change":"changed","title":"403 Forbidden","severity":"low",...,"was":{"id":"200-85283296","title":"Admin Login","severity":"medium","tags":["panel"],"status":200,...},"locations":["https://admin.example.com [192.0.2.12]"]}
scan-sample    {"id":"git-config","change":"changed","title":"Git Config - Detect","severity":"high","was":{"severity":"medium"},"locations":["https://a.example.com/.git/config"]}
scan-sample    {"id":"git-config","change":"removed","title":"Git Config - Detect","severity":"medium","locations":["https://b.example.com/.git/config"]}
subs-gitlab    {"id":"a-d81eb39e","change":"changed","a":["203.0.113.10"],"was":{"id":"a-d9ced00b","a":["104.18.39.11","172.64.148.245"],"aaaa":[...]},"locations":["levelup.gitlab.com"]}
subs-wildcard  {"id":"wildcard-24061878","change":"added","cname":["wc.shopify.com"],"a":["23.227.38.33"],"wildcard":"*.shopify.com","locations":["23-227-38-39.shopify.com",...6 names]}
```

## Limits

- The pairs are built from saved engine output, not from two live runs a week apart. The changes are the kinds a rerun produces (names that appear and go away, an IP that moves, a status that changes, a new file, a template update), applied to real engine output, and both sides are real runs of the tool.
- raijin-ports has no pair: its fixtures are naabu JSON plus nmap XML, and editing the XML by hand would be the only way to build one. raijin-diff reads raijin-ports output like any other (findings are services by id, groups are an id plus the port list), and `verify.py` on its two benchmark outputs (`noisy` and `findings`, diffed as if they were two runs) found 44 changes, 0 missing and 0 extra.
