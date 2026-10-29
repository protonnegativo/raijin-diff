// Command raijin-diff compares two runs of the same Raijin tool and returns only what changed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/protonnegativo/raijin-diff/internal/banner"
	"github.com/protonnegativo/raijin-diff/internal/diff"
	"github.com/protonnegativo/raijin-diff/internal/schema"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", diff.Defaults().MaxBytes, "maximum size of the JSON output (0: no limit); cuts are counted in omitted")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-diff [flags] old.json new.json\n\nold.json and new.json are two outputs of the same Raijin tool (raijin-scan, raijin-probe, ...).\n\n")
		fs.PrintDefaults()
	}
	// Flags may come before, between or after the two files.
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			return 1
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if *showBanner {
		banner.Write(stderr, "raijin-diff", version(), useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-diff", version())
		return 0
	}
	if len(files) != 2 {
		fs.Usage()
		return 1
	}
	if *format != "json" && *format != "table" {
		fmt.Fprintln(stderr, "raijin-diff: --format must be json or table")
		return 1
	}
	old, err := load(files[0])
	if err != nil {
		return refuse(stdout, stderr, err, *format, *pretty)
	}
	cur, err := load(files[1])
	if err != nil {
		return refuse(stdout, stderr, err, *format, *pretty)
	}
	if old.Tool != cur.Tool {
		fmt.Fprintf(stderr, "raijin-diff: %s is a %s run and %s is a %s run; compare two runs of the same tool\n", files[0], old.Tool, files[1], cur.Tool)
		return 1
	}

	res := schema.Result{
		Tool:    "raijin-diff",
		Version: version(),
		Target:  cur.Tool + ": " + files[0] + " -> " + files[1],
		Omitted: map[string]int{},
		Budget:  schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	if abs, err := filepath.Abs(files[1]); err == nil {
		res.Raw = abs
	}
	for i, r := range []*schema.Run{old, cur} {
		if cut := truncated(r); cut != "" {
			res.Errors = append(res.Errors, schema.Error{Kind: "truncated_input", Hint: files[i] + " was cut by " + r.Tool + "'s budget (" + cut + "), so what it cut is not compared; rerun " + r.Tool + " with a higher --max-bytes"})
		}
		for _, e := range r.Errors {
			res.Errors = append(res.Errors, schema.Error{Kind: "input_error", Hint: files[i] + ": " + e.Kind + ": " + e.Hint})
		}
	}
	switch {
	case old.Origin == cur.Origin:
		res.Origin = cur.Origin
	default:
		res.Errors = append(res.Errors, schema.Error{Kind: "origin_changed", Hint: fmt.Sprintf("the runs crawled different origins (%s, then %s); routes and locations are relative to each, and are compared as written", old.Origin, cur.Origin)})
	}

	findings, groups, st := diff.Diff(old, cur)
	res.Findings, res.Groups = findings, groups
	for k, v := range map[string]int{"unchanged_findings": st.UnchangedFindings, "unchanged_groups": st.UnchangedGroups, "unchanged_locations": st.UnchangedLocations} {
		if v > 0 {
			res.Omitted[k] = v
		}
	}
	if *maxItems > 0 && len(res.Findings) > *maxItems {
		res.Omitted["findings"] += len(res.Findings) - *maxItems
		res.Findings = res.Findings[:*maxItems]
		res.Budget.Truncated = true
	}
	res.Summary = summary(st)
	diff.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		res.Next = append(res.Next, "rerun with --max-bytes 0 --max-items 0 for the full diff (raw has only the new run)")
		diff.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// refuse reports an input it cannot read. An input written with a newer schema_version than this build
// understands is a structured error in a result on stdout with exit code 2, which an agent can act on (raijin-mcp
// returns that JSON as the error); any other problem is a message on stderr with exit code 1.
func refuse(stdout, stderr io.Writer, err error, format string, pretty bool) int {
	var ve *schema.VersionError
	if !errors.As(err, &ve) {
		fmt.Fprintln(stderr, "raijin-diff:", err)
		return 1
	}
	res := schema.Result{
		Tool:    "raijin-diff",
		Version: version(),
		Summary: "input refused, nothing compared",
		Errors:  []schema.Error{{Kind: "schema_version", Hint: err.Error()}},
	}
	write(stdout, &res, format, pretty)
	return 2
}

func load(path string) (*schema.Run, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := schema.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Tool == "raijin-diff" {
		return nil, fmt.Errorf("%s is a raijin-diff output; compare two runs of a tool, not two diffs", path)
	}
	return r, nil
}

// truncated says what a run's budget cut, or "" when nothing was cut.
func truncated(r *schema.Run) string {
	cut := r.Budget != nil && r.Budget.Truncated
	for _, list := range [][]schema.Entry{r.Findings, r.Groups} {
		for _, e := range list {
			if c, ok := e.Get("count"); ok {
				var n int
				_ = json.Unmarshal(c, &n)
				locs, _ := diff.Locations(e)
				if n > len(locs) {
					cut = true
				}
			}
		}
	}
	if !cut {
		return ""
	}
	var parts []string
	for _, k := range []string{"findings", "groups", "locations"} {
		if n := r.Omitted[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if len(parts) == 0 {
		return "truncated"
	}
	return "omitted " + strings.Join(parts, ", ")
}

// summary names only what changed; the unchanged counts are in omitted.
func summary(st diff.Stats) string {
	var parts []string
	var fs []string
	for _, c := range []struct {
		n    int
		word string
	}{{st.NewFindings, "new"}, {st.ResolvedFindings, "resolved"}, {st.ChangedFindings, "changed"}} {
		if c.n > 0 {
			fs = append(fs, fmt.Sprintf("%d %s", c.n, c.word))
		}
	}
	if len(fs) > 0 {
		parts = append(parts, and(fs)+" "+plural(st.NewFindings+st.ResolvedFindings+st.ChangedFindings, "finding"))
	}
	switch {
	case st.AddedLocations > 0 && st.RemovedLocations > 0:
		parts = append(parts, fmt.Sprintf("%d %s added to and %d removed from existing findings", st.AddedLocations, plural(st.AddedLocations, "location"), st.RemovedLocations))
	case st.AddedLocations > 0:
		parts = append(parts, fmt.Sprintf("%d %s added to existing findings", st.AddedLocations, plural(st.AddedLocations, "location")))
	case st.RemovedLocations > 0:
		parts = append(parts, fmt.Sprintf("%d %s removed from existing findings", st.RemovedLocations, plural(st.RemovedLocations, "location")))
	}
	if st.GroupChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d group %s", st.GroupChanges, plural(st.GroupChanges, "change")))
	}
	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, "; ")
}

func and(l []string) string {
	if len(l) == 1 {
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var marks = map[string]string{diff.New: "+", diff.Added: "+", diff.Changed: "~", diff.Resolved: "-", diff.Removed: "-"}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			change := f.String("change")
			locs, _ := diff.Locations(f)
			sev := f.String("severity")
			if sev == "" {
				sev = "group"
			}
			fmt.Fprintf(w, "%-8s %-8s %s (%d)\n", strings.ToUpper(sev), change, f.String("id"), len(locs))
			if was, ok := f.Get("was"); ok {
				fmt.Fprintf(w, "         was %s\n", was)
			}
			for _, l := range locs {
				fmt.Fprintf(w, "         %s %s\n", marks[change], l)
			}
		}
		for _, g := range res.Groups {
			locs, _ := diff.Locations(g)
			fmt.Fprintf(w, "group    %-8s %s (%s%d)\n", g.String("change"), g.String("id"), marks[g.String("change")], len(locs))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	b, _ := schema.Marshal(res)
	if pretty {
		var buf bytes.Buffer
		if json.Indent(&buf, b, "", "  ") == nil {
			b = buf.Bytes()
		}
	}
	w.Write(append(b, '\n'))
}
