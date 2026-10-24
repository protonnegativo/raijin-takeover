// Command raijin-takeover runs dnsx on a list of names, matches every CNAME against a table of
// takeover-prone providers and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/protonnegativo/raijin-takeover/internal/banner"
	"github.com/protonnegativo/raijin-takeover/internal/dnsx"
	"github.com/protonnegativo/raijin-takeover/internal/httpcheck"
	"github.com/protonnegativo/raijin-takeover/internal/reduce"
	"github.com/protonnegativo/raijin-takeover/internal/schema"
	"github.com/protonnegativo/raijin-takeover/internal/scope"
	"github.com/protonnegativo/raijin-takeover/internal/state"
)

const version = "0.1.0"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-takeover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var domains, inputs multi
	fs.Var(&domains, "d", "name to check (repeatable)")
	list := fs.String("l", "", "file with one name per line (or subfinder JSONL)")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	httpCheck := fs.Bool("http", false, "fetch the page of each candidate whose provider is recognised by its HTTP body (off by default: DNS only)")
	httpConnect := fs.String("http-connect", "", "dial this host:port for every HTTP check, with the name in the Host header (for labs)")
	httpTimeout := fs.Int("http-timeout", 10, "seconds per HTTP check")
	rate := fs.Int("rate", 0, "DNS queries per second (dnsx -rl)")
	threads := fs.Int("threads", 0, "concurrent DNS queries (dnsx -t)")
	resolvers := fs.String("resolvers", "", "DNS resolvers, a file or comma-separated list (dnsx -r)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for dnsx's full JSONL output and the HTTP checks (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read existing dnsx JSONL (and saved HTTP checks, name lists) instead of running dnsx (repeatable)")
	dnsxBin := fs.String("dnsx", "dnsx", "path to the dnsx binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-takeover --scope scope.txt (-d name | -l names.txt | --input dnsx.jsonl) [flags] [-- extra dnsx args]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-takeover", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-takeover", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-takeover: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-takeover: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-takeover",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed

	if *list != "" {
		b, err := os.ReadFile(*list)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-takeover:", err)
			return 1
		}
		names, err := dnsx.ParseNames(bytes.NewReader(b))
		if err != nil {
			fmt.Fprintln(stderr, "raijin-takeover:", err)
			return 1
		}
		domains = append(domains, names...)
	}

	var names []string
	var records []dnsx.Record
	var checks []httpcheck.Check
	code := 0
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// raw is opened when something runs (dnsx, or the HTTP check on a replay).
	var raw *os.File
	openRaw := func() error {
		if raw != nil {
			return nil
		}
		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-takeover-*.jsonl")
			if err != nil {
				return err
			}
			f.Close()
			*rawPath = f.Name()
		}
		f, err := os.Create(*rawPath)
		if err != nil {
			return err
		}
		raw = f
		res.Raw = *rawPath
		return nil
	}
	defer func() {
		if raw != nil {
			raw.Close()
		}
	}()

	if len(inputs) > 0 {
		for _, in := range inputs {
			b, err := os.ReadFile(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-takeover:", err)
				return 1
			}
			n, err1 := dnsx.ParseNames(bytes.NewReader(b))
			r, err2 := dnsx.Parse(bytes.NewReader(b))
			c, err3 := httpcheck.Parse(bytes.NewReader(b))
			if err := errors.Join(err1, err2, err3); err != nil {
				fmt.Fprintln(stderr, "raijin-takeover:", err)
				return 1
			}
			names = append(names, n...)
			records = append(records, r...)
			checks = append(checks, c...)
		}
		names = append(names, domains...)
		// A replay never runs dnsx: names without a dnsx record were not resolved, unless the input has
		// dnsx records, in which case dnsx ran and returned nothing for them.
		opt.Resolved = len(records) > 0
		res.Target = strings.Join(inputs, ", ")
	} else {
		names = inScope(domains, sc, res.Omitted)
		if len(names) == 0 {
			fmt.Fprintln(stderr, "raijin-takeover: no names in scope")
			return 1
		}
		res.Target = targetSummary(names, res.Omitted["out_of_scope"])
		if err := openRaw(); err != nil {
			fmt.Fprintln(stderr, "raijin-takeover:", err)
			return 1
		}
		var stderrTail string
		records, stderrTail, err = dnsx.Run(ctx, names, dnsx.Options{
			Binary: *dnsxBin, Rate: *rate, Threads: *threads, Resolvers: *resolvers, Extra: fs.Args(), Raw: raw,
		})
		switch {
		case errors.Is(err, dnsx.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install dnsx (go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest) or pass --dnsx <path>; the names below are not resolved"})
			opt.Resolved = false
			code = 2
		case err != nil:
			res.Errors = append(res.Errors, engineError(err, stderrTail))
		}
	}

	httpChecked := 0
	if *httpCheck {
		// Only the candidates: names whose CNAME points into a claimable provider recognised by its page.
		targets := reduce.HTTPTargets(names, records, checks, opt)
		if len(targets) > 0 {
			if err := openRaw(); err != nil {
				fmt.Fprintln(stderr, "raijin-takeover:", err)
				return 1
			}
			more := httpcheck.Run(ctx, targets, httpcheck.Options{
				Timeout: time.Duration(*httpTimeout) * time.Second, Connect: *httpConnect,
				UserAgent: "raijin-takeover/" + version, Raw: raw,
			})
			checks = append(checks, more...)
			httpChecked = len(more)
		}
	}

	findings, groups, omitted, allLocations := reduce.Reduce(names, records, checks, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, allLocations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, opt.Resolved, httpChecked, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		src := append([]string(nil), inputs...)
		if res.Raw != "" {
			src = append(src, res.Raw)
		}
		if len(src) > 0 {
			hint += " or read " + strings.Join(src, ", ") + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return code
}

func engineError(err error, stderrTail string) schema.Error {
	hint := err.Error()
	if stderrTail != "" {
		hint += ": " + stderrTail
	}
	return schema.Error{Kind: "engine_error", Hint: hint}
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

// inScope is what dnsx resolves: every name that is in scope, once. Names outside it are counted and
// never sent to a resolver.
func inScope(names []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = reduce.Normalize(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if !sc.Allowed(n) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, n)
	}
	return out
}

func targetSummary(names []string, skipped int) string {
	s := fmt.Sprintf("%d names", len(names))
	if len(names) == 1 {
		s = names[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, resolved bool, httpChecked, newCount int) string {
	names, live := map[string]bool{}, map[string]bool{}
	count := func(a schema.Answer, locs []string) {
		for _, n := range locs {
			names[n] = true
			if a.Status == "" {
				live[n] = true
			}
		}
	}
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
		count(f.Answer, f.Locations)
	}
	for _, g := range res.Groups {
		count(g.Answer, g.Locations)
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d names", len(names))
	if resolved {
		s += fmt.Sprintf(", %d resolve", len(live))
	} else {
		s += " (not resolved)"
	}
	s += fmt.Sprintf(", %d takeover candidates", len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if httpChecked > 0 {
		s += fmt.Sprintf(", %d checked over HTTP", httpChecked)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s (%d)%s\n", strings.ToUpper(f.Severity), f.Title, max(f.Count, len(f.Locations)), mark)
			fmt.Fprintf(w, "         %s\n", describe(f.Answer))
			if f.Claim != "" {
				fmt.Fprintf(w, "         claim: %s\n", f.Claim)
			}
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d)\n", describe(g.Answer), max(g.Count, len(g.Locations)))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of an answer for the table: the status, the CNAME target, the provider,
// the IPs and the HTTP check.
func describe(a schema.Answer) string {
	var parts []string
	if a.Status != "" {
		parts = append(parts, a.Status)
	}
	if len(a.CNAME) > 0 {
		parts = append(parts, "-> "+a.CNAME[len(a.CNAME)-1])
	}
	if a.Provider != "" {
		parts = append(parts, "["+a.Provider+"]")
	}
	ips := append(append([]string(nil), a.A...), a.AAAA...)
	if len(ips) > 2 {
		ips = append(ips[:2], fmt.Sprintf("+%d", len(ips)-2))
	}
	if len(ips) > 0 {
		parts = append(parts, strings.Join(ips, " "))
	}
	if a.HTTP != "" {
		parts = append(parts, "http "+a.HTTP)
	}
	return strings.Join(parts, " ")
}
