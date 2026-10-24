"""Checks that a raijin-diff output lists every change between two Raijin outputs, and nothing else.

Identity, as in the Raijin Schema: a finding is its id, a group is its id plus every other field but its
locations (count and new are left out too), and a location is its exact string. An entry with a route
and no locations has one location, its route (raijin-crawl's rule). This script computes the changes on
its own, from the two inputs:

  - every (finding or group, location) pair in new and not in old: added;
  - every pair in old and not in new: removed;
  - every finding id in both runs whose fields differ: changed;
  - every finding or group with no locations at all that is only in one run: added or removed.

Then it reads the diff back. "new" and "added" entries cover their locations as added, "resolved" and
"removed" entries as removed. A "changed" entry with an old id in "was", or whose old fields make it
another group or turn a finding into a group (or back), covers each location as added to the new entry
and removed from the old one. Any other "changed" entry covers that finding's field change.

usage: python verify.py <old.json> <new.json> <diff.json>
"""
import json
import sys

SKIP = {"locations", "count", "new"}


def canon(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def is_finding(e):
    return "severity" in e


def key(e):
    if is_finding(e):
        return ("f", e["id"])
    return ("g", canon({k: v for k, v in e.items() if k not in SKIP}))


def locations(e):
    if "locations" in e:
        return e["locations"]
    if e.get("route"):
        return [e["route"]]
    return []


def attrs(e):
    return {k: v for k, v in e.items() if k not in SKIP}


def pairs(run):
    out, entries = set(), {}
    for e in run["findings"] + run["groups"]:
        k = key(e)
        entries.setdefault(k, e)
        locs = locations(e)
        if not locs:
            out.add((k, None))
        for l in locs:
            out.add((k, l))
    return out, entries


old, new, d = (json.load(open(p)) for p in sys.argv[1:4])
op, oe = pairs(old)
np_, ne = pairs(new)
want = {("+",) + p for p in np_ - op} | {("-",) + p for p in op - np_}
# an entry with no locations that is in both runs is not a change
want = {w for w in want if w[2] is not None or w[1] not in (oe if w[0] == "+" else ne)}
for k in oe.keys() & ne.keys():
    if k[0] == "f" and canon(attrs(oe[k])) != canon(attrs(ne[k])):
        want.add(("~", k, None))

got = set()
for e in d["findings"] + d["groups"]:
    change = e["change"]
    base = {k: v for k, v in e.items() if k not in ("change", "was")}
    locs = locations(base) or [None]
    k = key(base)
    if change in ("new", "added"):
        got |= {("+", k, l) for l in locs}
    elif change in ("resolved", "removed"):
        got |= {("-", k, l) for l in locs}
    elif change == "changed":
        oldbase = dict(base)
        for f, v in e.get("was", {}).items():
            if v is None:
                oldbase.pop(f, None)
            else:
                oldbase[f] = v
        ok = key(oldbase)
        if ok == k:
            got.add(("~", k, None))
        else:
            got |= {("+", k, l) for l in locs} | {("-", ok, l) for l in locs}
    else:
        got.add(("?", change, None))

missing, extra = want - got, got - want
adds = sum(1 for w in want if w[0] == "+")
rems = sum(1 for w in want if w[0] == "-")
chg = sum(1 for w in want if w[0] == "~")
print(f"{len(want)} changes ({adds} added and {rems} removed (entry, location) pairs, {chg} findings with changed fields): {len(missing)} missing from the diff, {len(extra)} listed but not a change",
      "(diff truncated by its budget)" if d.get("budget") else "")
# locations in the same entry in both runs; those of a finding whose fields changed are listed with it
unchanged = sum(1 for p in op & np_ if p[1] is not None and ("~", p[0], None) not in want)
counted = d.get("omitted", {}).get("unchanged_locations", 0)
print(f"unchanged locations: {unchanged} expected, {counted} counted in omitted.unchanged_locations")
for m in sorted(missing, key=str)[:5]:
    print("  MISSING", m)
for m in sorted(extra, key=str)[:5]:
    print("  EXTRA", m)
sys.exit(1 if missing or extra or unchanged != counted else 0)
