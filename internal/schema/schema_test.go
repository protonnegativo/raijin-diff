package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntryKeepsFieldOrderAndDoesNotEscape(t *testing.T) {
	in := `{"id":"x","severity":"low","route":"/s","locations":["/s?a=1&b=2","http://d -> https://d/"],"cvss":9.8}`
	var e Entry
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatal(err)
	}
	b, _ := Marshal(e)
	want := `{"id":"x","severity":"low","route":"/s","locations":["/s?a=1&b=2","http://d -> https://d/"],"cvss":9.8}`
	if string(b) != want {
		t.Errorf("got %s\nwant %s", b, want)
	}
}

func TestPrettyInputComparesEqual(t *testing.T) {
	var a, b Entry
	_ = json.Unmarshal([]byte(`{"id":"x","a":["1","2"],"n":{"k":1}}`), &a)
	_ = json.Unmarshal([]byte("{\n  \"id\": \"x\",\n  \"a\": [\n    \"1\",\n    \"2\"\n  ],\n  \"n\": {\"k\": 1}\n}"), &b)
	x, _ := Marshal(a)
	y, _ := Marshal(b)
	if string(x) != string(y) {
		t.Errorf("%s != %s", x, y)
	}
}

func TestResultOmitsWhatCanBeRebuilt(t *testing.T) {
	r := Result{Tool: "raijin-diff", Version: "0.1.0", Findings: []Entry{}, Groups: []Entry{}, Omitted: map[string]int{}, Budget: Budget{MaxBytes: 16000}}
	b, _ := Marshal(r)
	s := string(b)
	for _, k := range []string{"omitted", "errors", "next", "budget", "raw", "origin"} {
		if strings.Contains(s, `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, s)
		}
	}
	if !strings.Contains(s, `"findings":[]`) || !strings.Contains(s, `"groups":[]`) {
		t.Errorf("findings and groups are always written: %s", s)
	}
	r.Budget.Truncated = true
	b, _ = Marshal(r)
	if !strings.Contains(string(b), `"budget":{"max_items":0,"max_bytes":16000,"truncated":true}`) {
		t.Errorf("budget should be written when something was cut: %s", b)
	}
}

func TestParseRejectsNonRaijin(t *testing.T) {
	for _, in := range []string{`not json`, `{"findings":[]}`, `[1,2]`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
}

func TestSetAndDelete(t *testing.T) {
	var e Entry
	e.Set("a", 1)
	e.Set("b", []string{"x"})
	e.Set("a", 2)
	e.Delete("b")
	if b, _ := Marshal(e); string(b) != `{"a":2}` {
		t.Errorf("got %s", b)
	}
	if e.IsFinding() {
		t.Error("no severity: a group")
	}
}
