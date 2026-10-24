// Package diff compares two outputs of the same Raijin tool and returns what changed, in the Raijin
// Schema.
//
// It is lossless for change: every finding, group and location that was added or removed between the
// two runs is listed, and so is every finding whose attributes changed. What did not change is counted
// in omitted, not listed: the agent already has the new run's output, and raw points to it. A byte budget
// can cut, but every cut is counted in omitted.
//
// Identity follows the Raijin Schema: a finding is its id (the tool is the same in both runs), a group is
// its id plus every other field but its locations (for raijin-scan, the id and the variants), and a
// location is its exact string.
package diff

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-diff/internal/schema"
)

// Changes, written in each entry's "change" field.
const (
	// New is a finding or group that the old run did not have. Locations are all of its locations.
	New = "new"
	// Added lists the locations a finding or group has now and did not have before.
	Added = "added"
	// Changed is a finding whose fields changed, or locations that moved from one entry to another (a
	// probe URL whose status went from 200 to 403). "was" holds the old values of the fields that
	// differ, null for a field the old entry did not have, and the old id when the locations moved.
	Changed = "changed"
	// Resolved is a finding or group that the new run no longer has. Locations are all it had.
	Resolved = "resolved"
	// Removed lists the locations a finding or group no longer has.
	Removed = "removed"
)

var changeOrder = map[string]int{New: 0, Changed: 1, Added: 2, Resolved: 0, Removed: 2}

// Options control the size of the result.
type Options struct {
	// MaxItems caps the number of findings; 0 keeps all.
	MaxItems int
	// MaxBytes caps the size of the JSON; 0 means no limit.
	MaxBytes int
}

// Defaults keep every change and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000}
}

// Stats counts what changed and what did not, for the summary and omitted.
type Stats struct {
	NewFindings, ResolvedFindings, ChangedFindings int
	// AddedLocations and RemovedLocations are the locations of findings that exist in both runs.
	AddedLocations, RemovedLocations int
	GroupChanges                     int
	UnchangedFindings                int
	UnchangedGroups                  int
	UnchangedLocations               int
}

// node is one finding or group of one run.
type node struct {
	key   string
	entry schema.Entry
	locs  []string
}

// item is one entry of the diff before it is written.
type item struct {
	change  string
	entry   schema.Entry // the side the entry describes: new for additions, old for removals
	was     *schema.Entry
	locs    []string
	finding bool
	removal bool
	sev     string
	conf    string
}

// Diff compares old and new and returns the findings and groups that changed.
func Diff(old, cur *schema.Run) ([]schema.Entry, []schema.Entry, Stats) {
	oldNodes, oldOrder := index(old)
	newNodes, newOrder := index(cur)

	// A location that sat in exactly one entry in each run, a different one, moved: it is one
	// "changed" entry instead of a removal and an addition, so an agent sees what changed about it.
	oldAt, newAt := locationIndex(oldNodes), locationIndex(newNodes)
	type pair struct{ from, to string }
	moved := map[pair][]string{}
	var pairs []pair
	movedOut, movedIn := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, k := range oldOrder {
		for _, l := range oldNodes[k].locs {
			a, b := oldAt[l], newAt[l]
			if len(a) != 1 || len(b) != 1 || a[0] == b[0] {
				continue
			}
			p := pair{a[0], b[0]}
			if _, ok := moved[p]; !ok {
				pairs = append(pairs, p)
			}
			moved[p] = append(moved[p], l)
			add(movedOut, a[0], l)
			add(movedIn, b[0], l)
		}
	}

	var items []item
	var st Stats
	touched := map[string]bool{}
	for p := range moved {
		touched[p.from], touched[p.to] = true, true
	}
	keys := append([]string(nil), newOrder...)
	for _, k := range oldOrder {
		if newNodes[k] == nil {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		o, n := oldNodes[k], newNodes[k]
		switch {
		case o == nil:
			locs := minus(n.locs, movedIn[k], nil)
			if len(locs) > 0 || len(n.locs) == 0 {
				items = append(items, newItem(New, n, locs, nil, false))
			}
		case n == nil:
			locs := minus(o.locs, movedOut[k], nil)
			if len(locs) > 0 || len(o.locs) == 0 {
				items = append(items, newItem(Resolved, o, locs, nil, true))
			}
		default:
			oldSet, newSet := set(o.locs), set(n.locs)
			added := minus(n.locs, oldSet, movedIn[k])
			removed := minus(o.locs, newSet, movedOut[k])
			var common []string
			for _, l := range n.locs {
				if oldSet[l] {
					common = append(common, l)
				}
			}
			if was := wasFields(o.entry, n.entry); len(was.Fields) > 0 {
				items = append(items, newItem(Changed, n, common, &was, false))
				touched[k] = true
			} else {
				st.UnchangedLocations += len(common)
			}
			if len(added) > 0 {
				items = append(items, newItem(Added, n, added, nil, false))
				touched[k] = true
			}
			if len(removed) > 0 {
				items = append(items, newItem(Removed, o, removed, nil, true))
				touched[k] = true
			}
			if !touched[k] {
				if n.entry.IsFinding() {
					st.UnchangedFindings++
				} else {
					st.UnchangedGroups++
				}
			}
		}
	}
	for _, p := range pairs {
		o, n := oldNodes[p.from], newNodes[p.to]
		was := wasFields(o.entry, n.entry)
		it := newItem(Changed, n, moved[p], &was, false)
		if !it.finding && o.entry.IsFinding() {
			// A finding's location that is now in a group: it went away as a finding.
			it.finding, it.removal = true, true
			it.sev, it.conf = o.entry.String("severity"), o.entry.String("confidence")
		}
		items = append(items, it)
	}

	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.removal != b.removal {
			return !a.removal
		}
		if a.finding {
			if ra, rb := schema.SeverityRank[a.sev], schema.SeverityRank[b.sev]; ra != rb {
				return ra > rb
			}
			if ra, rb := schema.ConfidenceRank[a.conf], schema.ConfidenceRank[b.conf]; ra != rb {
				return ra > rb
			}
		}
		if len(a.locs) != len(b.locs) {
			return len(a.locs) > len(b.locs)
		}
		if changeOrder[a.change] != changeOrder[b.change] {
			return changeOrder[a.change] < changeOrder[b.change]
		}
		return a.entry.String("id") < b.entry.String("id")
	})

	findings, groups := []schema.Entry{}, []schema.Entry{}
	for _, it := range items {
		if !it.finding {
			groups = append(groups, it.write())
			st.GroupChanges++
			continue
		}
		findings = append(findings, it.write())
		switch it.change {
		case New:
			st.NewFindings++
		case Resolved:
			st.ResolvedFindings++
		case Changed:
			st.ChangedFindings++
		case Added:
			st.AddedLocations += len(it.locs)
		case Removed:
			st.RemovedLocations += len(it.locs)
		}
	}
	return findings, groups, st
}

func newItem(change string, n *node, locs []string, was *schema.Entry, removal bool) item {
	return item{change: change, entry: n.entry, was: was, locs: locs, finding: n.entry.IsFinding(), removal: removal,
		sev: n.entry.String("severity"), conf: n.entry.String("confidence")}
}

// write returns the entry as raijin-diff prints it: id, change, the tool's fields, was, locations.
func (it item) write() schema.Entry {
	src := it.entry
	out := schema.Entry{}
	if id, ok := src.Get("id"); ok {
		out.Set("id", id)
	}
	out.Set("change", it.change)
	for _, f := range src.Fields {
		if f.Key == "id" || skip[f.Key] {
			continue
		}
		out.Set(f.Key, f.Value)
	}
	if it.was != nil {
		b, _ := it.was.MarshalJSON()
		out.Set("was", json.RawMessage(b))
	}
	route := src.String("route")
	switch {
	case route != "" && len(it.locs) == 1 && it.locs[0] == route:
		// raijin-crawl's rule: a route with no locations has one, the route itself.
	case len(it.locs) > 0 || route != "":
		out.Set("locations", nonNil(it.locs))
	}
	return out
}

// skip are the fields that are not part of an entry's identity or attributes: locations are compared one
// by one, count is how many the tool's budget kept, and new is relative to that tool's --state.
var skip = map[string]bool{"locations": true, "count": true, "new": true}

// wasFields returns the old values of the fields that differ between o and n (null when o lacks one).
func wasFields(o, n schema.Entry) schema.Entry {
	was := schema.Entry{}
	for _, f := range o.Fields {
		if skip[f.Key] {
			continue
		}
		if v, ok := n.Get(f.Key); !ok || !bytes.Equal(v, f.Value) {
			was.Set(f.Key, f.Value)
		}
	}
	for _, f := range n.Fields {
		if skip[f.Key] {
			continue
		}
		if _, ok := o.Get(f.Key); !ok {
			was.Set(f.Key, json.RawMessage("null"))
		}
	}
	return was
}

// Key is an entry's identity: a finding is its id, a group is its id and every other field but the
// locations. Entries of one run with the same key are one entry.
func Key(e schema.Entry) string {
	if e.IsFinding() {
		return "f\x00" + e.String("id")
	}
	var parts []string
	for _, f := range e.Fields {
		if !skip[f.Key] {
			parts = append(parts, f.Key+"\x01"+string(f.Value))
		}
	}
	sort.Strings(parts)
	return "g\x00" + strings.Join(parts, "\x00")
}

// Locations returns an entry's locations, and true when the location is implicit (raijin-crawl's route).
func Locations(e schema.Entry) ([]string, bool) {
	if _, ok := e.Get("locations"); ok {
		return e.Strings("locations"), false
	}
	if r := e.String("route"); r != "" {
		return []string{r}, true
	}
	return nil, false
}

func index(r *schema.Run) (map[string]*node, []string) {
	nodes := map[string]*node{}
	var order []string
	for _, list := range [][]schema.Entry{r.Findings, r.Groups} {
		for _, e := range list {
			k := Key(e)
			locs, _ := Locations(e)
			n, ok := nodes[k]
			if !ok {
				n = &node{key: k, entry: e}
				nodes[k] = n
				order = append(order, k)
			}
			seen := set(n.locs)
			for _, l := range locs {
				if !seen[l] {
					seen[l] = true
					n.locs = append(n.locs, l)
				}
			}
		}
	}
	return nodes, order
}

func locationIndex(nodes map[string]*node) map[string][]string {
	at := map[string][]string{}
	for k, n := range nodes {
		for _, l := range n.locs {
			at[l] = append(at[l], k)
		}
	}
	return at
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Resolved findings rank after every addition, so they go
// before any addition does. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res)
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		locs, _ := Locations(*g)
		if _, ok := g.Get("locations"); !ok {
			continue
		}
		before := size(g)
		res.Omitted["locations"] += len(locs)
		setLocations(g, nil, len(locs))
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		locs, _ := Locations(*f)
		if len(locs) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(locs) - 1
		setLocations(f, locs[:1], len(locs))
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

// setLocations replaces an entry's locations; count is written when it is more than the locations kept.
func setLocations(e *schema.Entry, locs []string, count int) {
	e.Delete("locations")
	e.Delete("count")
	if len(locs) > 0 {
		e.Set("locations", locs)
	}
	if count > len(locs) {
		e.Set("count", count)
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func set(l []string) map[string]bool {
	s := make(map[string]bool, len(l))
	for _, x := range l {
		s[x] = true
	}
	return s
}

// minus returns the strings of l that are in none of the sets, in order.
func minus(l []string, sets ...map[string]bool) []string {
	var out []string
outer:
	for _, x := range l {
		for _, s := range sets {
			if s[x] {
				continue outer
			}
		}
		out = append(out, x)
	}
	return out
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
