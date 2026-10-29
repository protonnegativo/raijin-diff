package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	oldRun = "../../testdata/probe-old.json"
	newRun = "../../testdata/probe-new.json"
)

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{oldRun, newRun}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if v["tool"] != "raijin-diff" || !strings.HasSuffix(v["raw"].(string), "probe-new.json") {
		t.Errorf("tool or raw: %v", v)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--banner", oldRun, newRun}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-diff "+version()) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, pretty, errb bytes.Buffer
	if code := run([]string{oldRun, newRun}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	// flags after the files work too
	if code := run([]string{oldRun, newRun, "--pretty"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestStatusChangeIsReported(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{oldRun, newRun}, &out, &errb)
	s := out.String()
	if !strings.Contains(s, `"change":"changed"`) || !strings.Contains(s, `"was":{"id":"200-85283296"`) || !strings.Contains(s, "https://admin.example.com") {
		t.Errorf("the admin panel's 200 -> 403 should be a change: %s", s)
	}
}

func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	diffOut := filepath.Join(dir, "diff.json")
	var o bytes.Buffer
	run([]string{oldRun, newRun}, &o, &bytes.Buffer{})
	os.WriteFile(diffOut, o.Bytes(), 0o600)
	notJSON := filepath.Join(dir, "x.json")
	os.WriteFile(notJSON, []byte("httpx text"), 0o600)
	for name, args := range map[string][]string{
		"one file":       {oldRun},
		"three files":    {oldRun, newRun, newRun},
		"different tool": {"../../testdata/scan-old.json", newRun},
		"missing file":   {oldRun, filepath.Join(dir, "nope.json")},
		"not raijin":     {oldRun, notJSON},
		"diff of diffs":  {diffOut, diffOut},
		"bad format":     {"--format", "xml", oldRun, newRun},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		if out.Len() != 0 {
			t.Errorf("%s: nothing on stdout on a usage error, got %q", name, out.String())
		}
	}
}

func TestTruncatedInputIsReported(t *testing.T) {
	dir := t.TempDir()
	cut := filepath.Join(dir, "cut.json")
	os.WriteFile(cut, []byte(`{"tool":"raijin-probe","findings":[{"id":"x","severity":"low","locations":["https://a"],"count":5}],"groups":[],"omitted":{"locations":4},"budget":{"max_items":0,"max_bytes":100,"truncated":true}}`), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{oldRun, cut}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"kind":"truncated_input"`) || !strings.Contains(out.String(), "omitted 4 locations") {
		t.Errorf("truncated input should be an error with a hint: %s", out.String())
	}
}

func TestBudgetCutsAreCounted(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"--max-bytes", "900", oldRun, newRun}, &out, &errb)
	var v struct {
		Findings []struct{ Locations []string }
		Groups   []json.RawMessage
		Omitted  map[string]int
		Budget   struct{ Truncated bool }
		Next     []string
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	// Fit never cuts the top finding's first location, so the output may stay over the budget only
	// when that is all that is left (the absolute raw path, which depends on the checkout, counts too).
	floor := len(v.Findings) == 1 && len(v.Findings[0].Locations) <= 1 && len(v.Groups) == 0
	if (len(out.Bytes()) > 901 && !floor) || !v.Budget.Truncated || v.Omitted["groups"]+v.Omitted["locations"]+v.Omitted["findings"] == 0 || len(v.Next) == 0 {
		t.Errorf("budget: %d bytes %s", len(out.Bytes()), out.String())
	}
}

func TestTable(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"--format", "table", oldRun, newRun}, &out, &errb)
	if !strings.Contains(out.String(), "LOW      changed  403-0f0d5a5e (1)") || !strings.Contains(out.String(), "~ https://admin.example.com") {
		t.Errorf("table: %s", out.String())
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--version"}, &out, &bytes.Buffer{}); code != 0 || out.String() != "raijin-diff "+version()+"\n" {
		t.Errorf("version: %d %q", code, out.String())
	}
}

func TestRefusesNewerSchemaVersion(t *testing.T) {
	newer := filepath.Join(t.TempDir(), "newer.json")
	if err := os.WriteFile(newer, []byte(`{"schema_version":2,"tool":"raijin-probe","findings":[],"groups":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{newer, newRun}, {oldRun, newer}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d, want 2 for a newer schema_version", args, code)
		}
		if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
			t.Fatalf("%v: stdout must start with the envelope, got %q", args, out.String())
		}
		var v struct {
			SchemaVersion int    `json:"schema_version"`
			Tool          string `json:"tool"`
			Errors        []struct{ Kind, Hint string }
		}
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatalf("%v: stdout is not JSON: %v: %s", args, err, out.String())
		}
		if v.SchemaVersion != 1 || v.Tool != "raijin-diff" || len(v.Errors) != 1 || v.Errors[0].Kind != "schema_version" ||
			!strings.Contains(v.Errors[0].Hint, "unsupported schema_version 2") || !strings.Contains(v.Errors[0].Hint, "versions 0 to 1") {
			t.Errorf("%v: got %s", args, out.String())
		}
	}
}

func TestAcceptsInputWithAndWithoutSchemaVersion(t *testing.T) {
	cur := filepath.Join(t.TempDir(), "v1.json")
	if err := os.WriteFile(cur, []byte(`{"schema_version":1,"tool":"raijin-probe","findings":[],"groups":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{oldRun, cur}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
	}
}
