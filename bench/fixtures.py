"""Builds the benchmark pairs: two runs of a sibling Raijin tool on the same target, the second one after
realistic changes (names added and removed, an IP that moved, a CNAME left dangling, a new backup file,
a status that changed, a new CVE).

The changes are made to the engine output each sibling tool keeps in its fixtures (its `raw`), and both
runs are real runs of the tool replaying that output with --input. Nothing in old.json or new.json is
written by hand.

usage: python fixtures.py <dir with the raijin-* repos> <dir with their binaries> <out dir>
"""
import json
import os
import subprocess
import sys

src, bins, out = sys.argv[1:4]


def lines(path):
    return open(path, encoding="utf-8").read().splitlines()


def write(path, ls):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(ls) + "\n")


def run(tool, d, raw, dest):
    # Run in the scenario dir, so target is the short raw file name, as in a run on a local file.
    with open(dest, "w") as f:
        subprocess.run([os.path.join(os.path.abspath(bins), tool), "--scope", "scope.txt", "--input", raw, "--max-bytes", "0"],
                       stdout=f, check=True, cwd=d)


def edit_jsonl(ls, host_of, drop=(), change=None):
    """Drops the lines whose host is in drop and passes the others through change(host, event)."""
    res = []
    for l in ls:
        if not l.startswith("{"):
            res.append(l)
            continue
        e = json.loads(l)
        h = host_of(e)
        if h in drop:
            continue
        if change:
            e = change(h, e)
        res.append(json.dumps(e, separators=(",", ":")))
    return res


def scenario(name, tool, scope_lines, old_lines, new_lines, ext=".jsonl"):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    scope = os.path.join(d, "scope.txt")
    write(scope, scope_lines)
    for side, ls in (("old", old_lines), ("new", new_lines)):
        raw = side + ".raw" + ext
        write(os.path.join(d, raw), ls)
        run(tool, d, raw, os.path.join(d, side + ".json"))
        os.remove(os.path.join(d, raw))
    os.remove(scope)


def subs_names(ls):
    """Names in raijin-subs raw (subfinder lines), in file order, and the dnsx answer of each."""
    names, answers = [], {}
    for l in ls:
        if not l.startswith("{"):
            continue
        e = json.loads(l)
        if "resolver" in e or "status_code" in e:
            answers[e["host"]] = e
        elif "host" in e and not e["host"].startswith("raijin-wc-"):
            names.append(e["host"])
    return names, answers


# 1. subs, shopify.com: a crowded wildcard. A week later 6 names are new and 4 are gone.
ls = lines(f"{src}/raijin-subs/bench/fixtures/wildcard/raw.jsonl")
names, answers = subs_names(ls)
resolving = [n for n in names if answers.get(n, {}).get("status_code") == "NOERROR"]
appeared = set(resolving[5::97][:6])
gone = set(resolving[11::89][:4]) - appeared
host = lambda e: e.get("host")
scenario("subs-wildcard", "raijin-subs", ["shopify.com", "*.shopify.com"],
         edit_jsonl(ls, host, drop=appeared), edit_jsonl(ls, host, drop=gone))

# 2. subs, gitlab.com: 10 names are new (2 of them third-party CNAMEs), 6 are gone, 2 names moved to
# another IP, and one CNAME to a third-party service now points at a name that does not resolve.
ls = lines(f"{src}/raijin-subs/bench/fixtures/findings/raw.jsonl")
names, answers = subs_names(ls)
cnamed = [n for n in names if answers.get(n, {}).get("cname") and answers[n].get("a")]
plain = [n for n in names if answers.get(n, {}).get("a") and not answers[n].get("cname")]
dead = [n for n in names if answers.get(n, {}).get("status_code") == "NXDOMAIN"]
appeared = set(cnamed[1:3] + plain[3:6] + dead[10:15])
dangling = cnamed[5]
moved = plain[8:10]
gone = set(plain[12:14] + dead[40:44]) - appeared


def gitlab_change(h, e):
    if "status_code" not in e:
        return e
    if h in moved:
        e["a"] = ["203.0.113.%d" % (10 + moved.index(h))]
        e.pop("aaaa", None)
    if h == dangling:
        e["status_code"] = "NXDOMAIN"
        e.pop("a", None)
        e.pop("aaaa", None)
    return e


scenario("subs-gitlab", "raijin-subs", ["gitlab.com", "*.gitlab.com"],
         edit_jsonl(ls, host, drop=appeared), edit_jsonl(ls, host, drop=gone, change=gitlab_change))

# 3. crawl, the lab app: a deploy adds a .env and a SQL dump (they were not there before), removes
# /graphql, and /admin/ now answers 200 instead of 403.
ls = lines(f"{src}/raijin-crawl/bench/fixtures/findings/raw.jsonl")
url = lambda e: e["request"]["endpoint"]
base = "http://localhost:19501"


def crawl_change(u, e):
    if u == base + "/admin/":
        e["response"]["status_code"] = 200
    return e


scenario("crawl-app", "raijin-crawl", ["localhost"],
         edit_jsonl(ls, url, drop={base + "/.env", base + "/backup/db.sql"}),
         edit_jsonl(ls, url, drop={base + "/graphql"}, change=crawl_change))

# 4. probe, the sample: the admin panel now answers 403 like c.example.com, and e.example.com, which
# refused connections, now serves the nginx welcome page.
ls = lines(f"{src}/raijin-probe/testdata/sample.jsonl")
ev = {json.loads(l)["url"]: l for l in ls if l.startswith("{")}


def probe_change(u, e):
    if u == "https://admin.example.com":
        c = json.loads(ev["https://c.example.com"])
        for k in ("title", "webserver", "tech", "words", "lines", "status_code", "content_length", "hash"):
            e[k] = c[k]
    if u == "https://e.example.com":
        a = json.loads(ev["https://a.example.com"])
        a.update(url=u, input="e.example.com", host="e.example.com", a=["192.0.2.15"])
        e = a
    return e


scenario("probe-sample", "raijin-probe", ["*.example.com"],
         ls, edit_jsonl(ls, lambda e: e.get("url"), change=probe_change))

# 5. scan, the sample: a new critical CVE on c, the .env now also exposed on a, the .git/config of b
# fixed, the git-config template raised from medium to high in a template update, and a now also
# detected as PHP.
ls = lines(f"{src}/raijin-scan/testdata/sample.jsonl")
extra = [
    {"template-id": "CVE-2021-44228", "host": "c.example.com", "matched-at": "https://c.example.com/api/login",
     "extracted-results": ["log4j"], "info": {"name": "Apache Log4j2 Remote Code Injection", "severity": "critical",
     "classification": {"cve-id": ["cve-2021-44228"], "cvss-score": 10}}},
    {"template-id": "exposed-env", "host": "a.example.com", "matched-at": "https://a.example.com/.env",
     "extracted-results": ["DB_PASSWORD=x"], "info": {"name": "Exposed .env", "severity": "high"}},
    {"template-id": "tech-detect", "matcher-name": "php", "host": "a.example.com", "matched-at": "https://a.example.com",
     "info": {"name": "Wappalyzer Technology Detection", "severity": "info"}},
]
new = [l.replace('"severity":"medium"', '"severity":"high"') if '"template-id":"git-config"' in l else l
       for l in ls if '"matched-at":"https://b.example.com/.git/config"' not in l] + [json.dumps(e, separators=(",", ":")) for e in extra]
scenario("scan-sample", "raijin-scan", ["*.example.com"], ls, new)
