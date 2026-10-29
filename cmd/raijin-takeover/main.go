// Command raijin-takeover runs dnsx on a list of names, matches every CNAME against a table of
// takeover-prone providers and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	coreschema "github.com/protonnegativo/raijin-core/schema"
	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-core/state"
	"github.com/protonnegativo/raijin-takeover/internal/banner"
	"github.com/protonnegativo/raijin-takeover/internal/dnsx"
	"github.com/protonnegativo/raijin-takeover/internal/httpcheck"
	"github.com/protonnegativo/raijin-takeover/internal/reduce"
	"github.com/protonnegativo/raijin-takeover/internal/schema"
)

// releaseVersion is set at link time for a release build:
// go build -ldflags "-X main.releaseVersion=v1.2.3". It stays empty otherwise. It is a separate
// variable because -X does not set a variable that is initialized by a function call.
var releaseVersion string

// version is the release this binary was built from; see buildVersion.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion returns releaseVersion when the build set it, the module version for a binary installed
// with go install ...@vX.Y.Z or @latest, and "dev" with the VCS revision (and +dirty) for a local go build.
func buildVersion(info *debug.BuildInfo, ok bool) string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	v := "dev"
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		v += "-" + rev
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is the --version output: the release and the tested engine versions.
func versionLine() string {
	line := "raijin-takeover " + version
	if engines, err := dnsx.Engines(); err == nil && engines["dnsx"].Version != "" {
		line += " (tested with dnsx " + engines["dnsx"].Version + ")"
	}
	return line
}

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
	fs.Var(&domains, "d", "name to check (repeatable; default: every host the scope names)")
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
		fmt.Fprintf(stderr, "usage: raijin-takeover --scope scope.txt [-d name | -l names.txt | --input dnsx.jsonl] [flags] [-- extra dnsx args]\n\nWith no targets it checks every host the scope names.\n\nExit codes: 0 ok; 1 wrong usage; 2 structured error (invalid scope, dnsx missing), the JSON on stdout says which.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-takeover", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-takeover: --scope is required")
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
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		// An invalid scope is an error an agent can fix: every bad line, structured, before anything runs.
		res.Target = *scopeFile
		res.Summary = "invalid scope file, nothing scanned"
		res.Errors = append(res.Errors, scope.SchemaErrors(err)...)
		write(stdout, &res, *format, *pretty)
		return 2
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
		if len(domains) == 0 {
			// no names given: check every name the scope names (IPs and ranges are not names)
			targets, wildcards, _ := sc.Targets()
			for _, t := range targets {
				if net.ParseIP(t) == nil {
					names = append(names, t)
				}
			}
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+" --raw subs.jsonl, then raijin-takeover --scope "+*scopeFile+" -l subs.jsonl to cover "+w+" (-l reads raijin-subs' raw JSONL directly)")
			}
		} else {
			names = inScope(domains, sc, res.Omitted)
		}
		if len(names) == 0 {
			if len(res.Next) > 0 {
				res.Summary = "the scope names no single host to scan"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			fmt.Fprintln(stderr, "raijin-takeover: no names in scope")
			return 1
		}
		res.Target = targetSummary(names, res.Omitted["out_of_scope"])
		if err := openRaw(); err != nil {
			fmt.Fprintln(stderr, "raijin-takeover:", err)
			return 1
		}
		engines, _ := dnsx.Engines()
		if path, err := exec.LookPath(*dnsxBin); err == nil {
			// Never blocks the run: an untested or known-bad version is a warning, an unknown one is silent.
			v := dnsx.Version(ctx, path)
			if b, bad := dnsx.KnownBad(v); bad {
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_version", Hint: dnsx.KnownBadHint(v, b, engines["dnsx"])})
			} else if dnsx.Untested(v, engines["dnsx"].Version) {
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_version", Hint: dnsx.VersionHint(v, engines["dnsx"])})
			}
		}
		var stderrTail string
		var format dnsx.Format
		records, format, stderrTail, err = dnsx.Run(ctx, names, dnsx.Options{
			Binary: *dnsxBin, Rate: *rate, Threads: *threads, Resolvers: *resolvers, Extra: fs.Args(), Raw: raw,
		})
		switch {
		case errors.Is(err, dnsx.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install dnsx (go install " + engines["dnsx"].Go + "@v" + engines["dnsx"].Version + ") or pass --dnsx <path>; the names below are not resolved, or run raijin-mcp update --pinned"})
			opt.Resolved = false
			code = 2
		case err != nil:
			res.Errors = append(res.Errors, engineError(err, stderrTail))
		}
		if format.Bad > 0 {
			// Not represented anywhere else: counted, not dropped silently.
			res.Omitted["unparsed"] += format.Bad
			res.Errors = append(res.Errors, formatError(format, *rawPath))
		}
		// With -rcode dnsx writes a line for every name, resolved or not. A name with no line is still
		// listed (NOANSWER), but dnsx lost its status: say so. Lines that did not parse are counted
		// above, and a dnsx that failed is an engine_error already.
		if err == nil {
			if missing := dnsx.Missing(names, records) - format.Bad; missing > 0 {
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: dnsx.MissingHint(missing, len(names), engines["dnsx"])})
			}
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
			newCount = state.Mark(st, res.Findings, allLocations,
				func(f *schema.Finding) string { return f.StateKey },
				func(f *schema.Finding) { f.New = true })
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

// formatError is the engine_format error for dnsx lines without a host and a status_code.
func formatError(f dnsx.Format, raw string) schema.Error {
	return schema.Error{Kind: "engine_format", Hint: fmt.Sprintf("%d of %d dnsx results had no host and status_code; the engine's output format may have changed. Read %s for the full output", f.Bad, f.Lines, raw)}
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
	_ = coreschema.Write(w, res, pretty)
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
