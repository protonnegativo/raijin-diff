package diff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-diff/internal/schema"
)

func parse(t *testing.T, s string) *schema.Run {
	t.Helper()
	r, err := schema.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func js(t *testing.T, v any) string {
	t.Helper()
	b, err := schema.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func find(entries []schema.Entry, id, change string) *schema.Entry {
	for i := range entries {
		if entries[i].String("id") == id && entries[i].String("change") == change {
			return &entries[i]
		}
	}
	return nil
}

const scanOld = `{"tool":"raijin-scan","findings":[
 {"id":"git-config","title":"Git Config","severity":"medium","locations":["https://a/.git/config","https://b/.git/config"]},
 {"id":"old-bug","title":"Old","severity":"low","locations":["https://a/old"]}],
 "groups":[{"id":"tech-detect","variants":["nginx"],"locations":["https://a","https://b"]}]}`

const scanNew = `{"tool":"raijin-scan","findings":[
 {"id":"exposed-env","title":"Env","severity":"high","locations":["https://c/.env [K=v]"]},
 {"id":"git-config","title":"Git Config","severity":"medium","locations":["https://a/.git/config","https://c/.git/config"]}],
 "groups":[{"id":"tech-detect","variants":["nginx"],"locations":["https://a","https://b","https://c"]}]}`

func TestEveryAddedAndRemovedItemIsListed(t *testing.T) {
	f, g, st := Diff(parse(t, scanOld), parse(t, scanNew))
	if e := find(f, "exposed-env", New); e == nil || js(t, e.Strings("locations")) != `["https://c/.env [K=v]"]` {
		t.Errorf("new finding missing or without its locations: %s", js(t, f))
	}
	if e := find(f, "git-config", Added); e == nil || js(t, e.Strings("locations")) != `["https://c/.git/config"]` {
		t.Errorf("added location missing: %s", js(t, f))
	}
	if e := find(f, "git-config", Removed); e == nil || js(t, e.Strings("locations")) != `["https://b/.git/config"]` {
		t.Errorf("removed location missing: %s", js(t, f))
	}
	if e := find(f, "old-bug", Resolved); e == nil || js(t, e.Strings("locations")) != `["https://a/old"]` {
		t.Errorf("resolved finding missing: %s", js(t, f))
	}
	if e := find(g, "tech-detect", Added); e == nil || js(t, e.Strings("locations")) != `["https://c"]` {
		t.Errorf("added group location missing: %s", js(t, g))
	}
	if st.UnchangedLocations != 3 || st.UnchangedFindings != 0 {
		t.Errorf("unchanged: %+v", st)
	}
}

func TestUnchangedIsCountedNotListed(t *testing.T) {
	f, g, st := Diff(parse(t, scanOld), parse(t, scanOld))
	if len(f) != 0 || len(g) != 0 {
		t.Errorf("same run should list nothing: %s %s", js(t, f), js(t, g))
	}
	if st.UnchangedFindings != 2 || st.UnchangedGroups != 1 || st.UnchangedLocations != 5 {
		t.Errorf("unchanged counts: %+v", st)
	}
}

func TestAdditionsRankBySeverityThenResolutions(t *testing.T) {
	f, _, _ := Diff(parse(t, scanOld), parse(t, scanNew))
	var order []string
	for _, e := range f {
		order = append(order, e.String("id")+":"+e.String("change"))
	}
	want := "exposed-env:new git-config:added git-config:removed old-bug:resolved"
	if got := strings.Join(order, " "); got != want {
		t.Errorf("order %q, want %q", got, want)
	}
}

func TestSeverityChangeIsAChange(t *testing.T) {
	old := `{"tool":"raijin-scan","findings":[{"id":"x","title":"X","severity":"medium","locations":["https://a/x","https://b/x"]}],"groups":[]}`
	cur := `{"tool":"raijin-scan","findings":[{"id":"x","title":"X","severity":"critical","locations":["https://a/x","https://b/x"]}],"groups":[]}`
	f, _, st := Diff(parse(t, old), parse(t, cur))
	e := find(f, "x", Changed)
	if e == nil {
		t.Fatalf("severity change not reported: %s", js(t, f))
	}
	if was, _ := e.Get("was"); string(was) != `{"severity":"medium"}` {
		t.Errorf("was = %s", was)
	}
	if len(e.Strings("locations")) != 2 || st.UnchangedLocations != 0 || st.ChangedFindings != 1 {
		t.Errorf("a changed finding lists the locations it changed at: %s %+v", js(t, e), st)
	}
}

func TestStatusChangeInProbeIsAChange(t *testing.T) {
	// raijin-probe's id holds the status, so a URL that went from 200 to 403 moved to another finding.
	old := `{"tool":"raijin-probe","findings":[{"id":"200-aaaa","title":"Admin","severity":"medium","tags":["panel"],"status":200,"locations":["https://admin [1.2.3.4]"]}],"groups":[]}`
	cur := `{"tool":"raijin-probe","findings":[{"id":"403-bbbb","title":"Forbidden","severity":"low","tags":["auth"],"status":403,"locations":["https://admin [1.2.3.4]"]}],"groups":[]}`
	f, _, _ := Diff(parse(t, old), parse(t, cur))
	if len(f) != 1 {
		t.Fatalf("one changed entry instead of new + resolved: %s", js(t, f))
	}
	e := f[0]
	was, _ := e.Get("was")
	if e.String("change") != Changed || e.String("id") != "403-bbbb" || !strings.Contains(string(was), `"id":"200-aaaa"`) || !strings.Contains(string(was), `"status":200`) {
		t.Errorf("changed entry: %s", js(t, e))
	}
}

func TestFindingThatBecameAGroupRanksWithResolutions(t *testing.T) {
	old := `{"tool":"raijin-probe","findings":[{"id":"200-aaaa","title":"Admin","severity":"medium","tags":["panel"],"locations":["https://x"]},
	 {"id":"403-cccc","severity":"low","tags":["auth"],"locations":["https://y"]}],"groups":[]}`
	cur := `{"tool":"raijin-probe","findings":[{"id":"403-dddd","severity":"low","tags":["auth"],"locations":["https://z"]}],"groups":[{"id":"200-eeee","title":"Welcome","locations":["https://x"]}]}`
	f, g, _ := Diff(parse(t, old), parse(t, cur))
	if len(g) != 0 {
		t.Errorf("the moved location is a finding change, not a group change: %s", js(t, g))
	}
	// additions first, then removals by their old severity: the medium panel before the low 403
	if len(f) != 3 || f[2].String("id") != "403-cccc" {
		t.Fatalf("findings: %s", js(t, f))
	}
	last := f[1]
	if last.String("change") != Changed || last.String("id") != "200-eeee" {
		t.Fatalf("finding that became a group should rank with resolutions: %s", js(t, f))
	}
	if was, _ := last.Get("was"); !strings.Contains(string(was), `"severity":"medium"`) {
		t.Errorf("was should hold the old severity: %s", was)
	}
	if f[0].String("id") != "403-dddd" {
		t.Errorf("additions first: %s", js(t, f))
	}
}

func TestLocationInSeveralEntriesIsNotPaired(t *testing.T) {
	// A scan URL matched by two templates: moving out of one is not a change of the other.
	old := `{"tool":"raijin-scan","findings":[{"id":"a","severity":"high","locations":["https://h"]},{"id":"b","severity":"low","locations":["https://h"]}],"groups":[]}`
	cur := `{"tool":"raijin-scan","findings":[{"id":"c","severity":"high","locations":["https://h"]}],"groups":[]}`
	f, _, _ := Diff(parse(t, old), parse(t, cur))
	if find(f, "c", New) == nil || find(f, "a", Resolved) == nil || find(f, "b", Resolved) == nil {
		t.Errorf("ambiguous location should be listed as new and resolved: %s", js(t, f))
	}
}

func TestGroupIdentityIsIDPlusVariants(t *testing.T) {
	old := `{"tool":"raijin-scan","findings":[],"groups":[{"id":"t","variants":["x"],"locations":["https://a","https://b"]},{"id":"t","variants":["y"],"locations":["https://c"]}]}`
	cur := `{"tool":"raijin-scan","findings":[],"groups":[{"id":"t","variants":["x"],"locations":["https://a"]},{"id":"t","variants":["y"],"locations":["https://c","https://d"]}]}`
	_, g, st := Diff(parse(t, old), parse(t, cur))
	if len(g) != 2 || js(t, g[0]) != `{"id":"t","change":"added","variants":["y"],"locations":["https://d"]}` ||
		js(t, g[1]) != `{"id":"t","change":"removed","variants":["x"],"locations":["https://b"]}` {
		t.Errorf("groups: %s", js(t, g))
	}
	if st.UnchangedLocations != 2 {
		t.Errorf("unchanged: %+v", st)
	}
}

func TestVariantChangeOfAGroupIsAChange(t *testing.T) {
	old := `{"tool":"raijin-scan","findings":[],"groups":[{"id":"t","variants":["nginx"],"locations":["https://a"]}]}`
	cur := `{"tool":"raijin-scan","findings":[],"groups":[{"id":"t","variants":["apache"],"locations":["https://a"]}]}`
	_, g, _ := Diff(parse(t, old), parse(t, cur))
	if len(g) != 1 || js(t, g[0]) != `{"id":"t","change":"changed","variants":["apache"],"was":{"variants":["nginx"]},"locations":["https://a"]}` {
		t.Errorf("groups: %s", js(t, g))
	}
}

func TestCrawlRouteIsTheImplicitLocation(t *testing.T) {
	old := `{"tool":"raijin-crawl","findings":[{"id":"403-a","severity":"medium","tags":["admin","auth"],"route":"/admin/","status":403}],"groups":[]}`
	cur := `{"tool":"raijin-crawl","findings":[{"id":"200-b","severity":"medium","tags":["admin"],"route":"/admin/","status":200},
	 {"id":"200-c","severity":"high","tags":["file"],"route":"/.env","status":200}],"groups":[]}`
	f, _, _ := Diff(parse(t, old), parse(t, cur))
	if len(f) != 2 {
		t.Fatalf("findings: %s", js(t, f))
	}
	if js(t, f[0]) != `{"id":"200-c","change":"new","severity":"high","tags":["file"],"route":"/.env","status":200}` {
		t.Errorf("new route keeps crawl's form, no locations: %s", js(t, f[0]))
	}
	if js(t, f[1]) != `{"id":"200-b","change":"changed","severity":"medium","tags":["admin"],"route":"/admin/","status":200,"was":{"id":"403-a","tags":["admin","auth"],"status":403}}` {
		t.Errorf("status change of a route: %s", js(t, f[1]))
	}
}

func TestEscapingCountAndNewDoNotMakeAChange(t *testing.T) {
	old := `{"tool":"raijin-crawl","findings":[{"id":"x","severity":"low","route":"/s","locations":["/s?a=1&b=2"],"new":true}],"groups":[]}`
	cur := `{"tool":"raijin-crawl","findings":[{"id":"x","severity":"low","route":"/s","locations":["/s?a=1&b=2"]}],"groups":[]}`
	f, g, st := Diff(parse(t, old), parse(t, cur))
	if len(f)+len(g) != 0 || st.UnchangedFindings != 1 {
		t.Errorf("escaping or --state's new flag reported as a change: %s", js(t, f))
	}
}

func TestEntryWithoutLocations(t *testing.T) {
	old := `{"tool":"raijin-x","findings":[],"groups":[]}`
	cur := `{"tool":"raijin-x","findings":[{"id":"x","severity":"low"}],"groups":[]}`
	f, _, _ := Diff(parse(t, old), parse(t, cur))
	if len(f) != 1 || js(t, f[0]) != `{"id":"x","change":"new","severity":"low"}` {
		t.Errorf("findings: %s", js(t, f))
	}
}

func TestFitCutsGroupsFirstAndCounts(t *testing.T) {
	var locs []string
	for i := 0; i < 200; i++ {
		locs = append(locs, strings.Repeat("h", 20)+string(rune('a'+i%26))+strings.Repeat("x", i%7))
	}
	b, _ := json.Marshal(locs)
	cur := `{"tool":"raijin-x","findings":[{"id":"f","severity":"high","locations":` + string(b) + `}],"groups":[{"id":"g","locations":` + string(b) + `}]}`
	f, g, _ := Diff(parse(t, `{"tool":"raijin-x","findings":[],"groups":[]}`), parse(t, cur))
	res := schema.Result{Findings: f, Groups: g, Budget: schema.Budget{MaxBytes: 2000}}
	Fit(&res, 2000)
	if !res.Budget.Truncated || size(res) > 2000 {
		t.Fatalf("not fitted: %d bytes", size(res))
	}
	if len(res.Findings) != 1 || res.Omitted["findings"] != 0 {
		t.Errorf("the finding should stay: %v", res.Omitted)
	}
	if c, _ := res.Findings[0].Get("count"); len(res.Findings[0].Strings("locations")) != 1 || string(c) == "" {
		t.Errorf("finding keeps one location and its count: %s", js(t, res.Findings[0]))
	}
	if res.Omitted["locations"]+res.Omitted["groups"] == 0 {
		t.Errorf("cuts must be counted: %v", res.Omitted)
	}
}
