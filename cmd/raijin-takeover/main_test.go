package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/protonnegativo/raijin-takeover/internal/dnsx"
)

// tested is the dnsx version in engines.json, so the fakes keep answering it after a bump.
func tested(t *testing.T) string {
	t.Helper()
	e, err := dnsx.Engines()
	if err != nil || e["dnsx"].Version == "" {
		t.Fatalf("engines.json: %v", err)
	}
	return e["dnsx"].Version
}

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type output struct {
	Summary  string
	Findings []struct {
		ID, Severity, Confidence, Title, HTTP, Claim, Fingerprint string
		Locations                                                 []string
	}
	Groups []struct {
		ID, Status, HTTP string
		Locations        []string
	}
	Omitted map[string]int
	Errors  []struct{ Kind, Hint string }
	Raw     string
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
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
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-takeover "+version) {
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
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
	want := `"summary":"16 names, 10 resolve, 7 takeover candidates (2 high, 4 medium, 1 low), 9 groups"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary: %s", out.String())
	}
	if strings.Contains(out.String(), `"raw"`) {
		t.Errorf("a replay runs nothing and writes no raw file: %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-d", "www.example.org"}, &out, &errb); code != 1 {
		t.Errorf("no name in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--nope"}, &out, &errb); code != 1 {
		t.Errorf("unknown flag: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--input", "/nonexistent.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("missing input: exit %d, want 1", code)
	}
}

func TestMissingEngineExitsTwoAndListsEveryName(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "a.example.com", "-d", "b.example.com", "--dnsx", "/nonexistent/dnsx", "--raw", filepath.Join(t.TempDir(), "raw.jsonl")}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--dnsx") {
		t.Errorf("stdout = %s", out.String())
	}
	if len(v.Groups) != 1 || v.Groups[0].Status != "UNCHECKED" || len(v.Groups[0].Locations) != 2 {
		t.Errorf("every name is still listed, as UNCHECKED: %s", out.String())
	}
}

// fakeDnsx writes a shell script that answers like dnsx, so the live path runs offline. It fails if a
// name outside the scope reaches it, and records its arguments.
func fakeDnsx(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	body := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: ` + tested(t) + `" >&2; exit 0; }
echo "$@" > ` + argsFile + `
while [ "$1" != "-l" ]; do shift; done
while read -r n; do
  case "$n" in
    docs.example.com) echo "{\"host\":\"$n\",\"a\":[\"185.199.108.153\"],\"cname\":[\"acme-docs.github.io\"],\"status_code\":\"NOERROR\"}" ;;
    blog.example.com) echo "{\"host\":\"$n\",\"a\":[\"185.199.108.153\"],\"cname\":[\"acme-blog.github.io\"],\"status_code\":\"NOERROR\"}" ;;
    app.example.com) echo "{\"host\":\"$n\",\"cname\":[\"acme-app.azurewebsites.net\"],\"status_code\":\"NXDOMAIN\"}" ;;
    *.example.org) echo "out of scope name sent to dnsx: $n" >&2; exit 1 ;;
    *) echo "{\"host\":\"$n\",\"a\":[\"192.0.2.1\"],\"status_code\":\"NOERROR\"}" ;;
  esac
done < "$2"
`
	bin = filepath.Join(dir, "dnsx")
	if err := os.WriteFile(bin, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

// lab starts a local provider page server on the first free port in 19420-19449: docs.example.com
// shows the GitHub Pages "unclaimed" page, every other name a normal page.
func lab(t *testing.T) (addr string, hits *atomic.Int32) {
	t.Helper()
	var ln net.Listener
	for port := 19420; port <= 19449 && ln == nil; port++ {
		ln, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	}
	if ln == nil {
		t.Skip("no free port in 19420-19449")
	}
	n := &atomic.Int32{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Host == "docs.example.com" {
			w.WriteHeader(404)
			fmt.Fprint(w, "There isn't a GitHub Pages site here.")
			return
		}
		fmt.Fprint(w, "welcome")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), n
}

func TestLiveRunIsDNSOnlyByDefault(t *testing.T) {
	bin, argsFile := fakeDnsx(t)
	addr, hits := lab(t)
	raw := filepath.Join(t.TempDir(), "raw.jsonl")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "docs.example.com", "-d", "blog.example.com", "-d", "app.example.com", "-d", "www.example.com", "-d", "x.example.org",
		"--dnsx", bin, "--raw", raw, "--http-connect", addr, "--", "-retry", "2"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Errorf("no HTTP request without --http, got %d", hits.Load())
	}
	if v.Raw != raw || v.Omitted["out_of_scope"] != 1 || len(v.Errors) != 0 {
		t.Errorf("raw, scope or errors: %s", out.String())
	}
	if want := "4 names, 3 resolve, 3 takeover candidates (1 high, 2 medium), 1 groups"; v.Summary != want {
		t.Errorf("summary %q, want %q", v.Summary, want)
	}
	if f := v.Findings[1]; f.Confidence != "heuristic" || f.Fingerprint != "There isn't a GitHub Pages site here." {
		t.Errorf("an unchecked candidate is heuristic and carries the fingerprint: %+v", f)
	}
	args, _ := os.ReadFile(argsFile)
	if strings.Contains(string(args), "-cname") || !strings.HasSuffix(strings.TrimSpace(string(args)), "-retry 2") {
		t.Errorf("dnsx args: %s", args)
	}
}

func TestHTTPCheckAndReplay(t *testing.T) {
	bin, _ := fakeDnsx(t)
	addr, hits := lab(t)
	raw := filepath.Join(t.TempDir(), "raw.jsonl")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "docs.example.com", "-d", "blog.example.com", "-d", "app.example.com", "-d", "www.example.com",
		"--dnsx", bin, "--raw", raw, "--http", "--http-connect", addr}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	// only the two GitHub Pages names are fetched: app is NXDOMAIN, www has no CNAME
	if hits.Load() != 2 {
		t.Errorf("%d HTTP requests, want 2", hits.Load())
	}
	if want := "4 names, 3 resolve, 2 takeover candidates (2 high), 2 groups, 2 checked over HTTP"; v.Summary != want {
		t.Errorf("summary %q, want %q", v.Summary, want)
	}
	if f := v.Findings[1]; f.Title != "GitHub Pages fingerprint matched" || f.HTTP != "404 match" || f.Fingerprint != "" || f.Locations[0] != "docs.example.com" {
		t.Errorf("matched finding: %+v", f)
	}
	if g := v.Groups[0]; g.HTTP != "200 no match" || g.Locations[0] != "blog.example.com" || !strings.HasPrefix(g.ID, "in-use-") {
		t.Errorf("a page without the fingerprint is a resource in use: %+v", g)
	}
	b, _ := os.ReadFile(raw)
	if strings.Count(string(b), `"check":"http"`) != 2 || strings.Count(string(b), `"status_code"`) != 4 {
		t.Errorf("raw should hold dnsx's output and the checks: %s", b)
	}

	// replaying the raw file gives the same result without sending anything
	var again bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", raw, "--dnsx", "/nonexistent"}, &again, &errb); code != 0 {
		t.Fatalf("replay exit %d", code)
	}
	var r output
	json.Unmarshal(again.Bytes(), &r)
	if r.Summary != strings.TrimSuffix(v.Summary, ", 2 checked over HTTP") || hits.Load() != 2 {
		t.Errorf("replay summary %q (hits %d)", r.Summary, hits.Load())
	}
}

func TestHTTPCheckOnAReplayFetchesOnlyWhatIsNotChecked(t *testing.T) {
	addr, hits := lab(t)
	raw := filepath.Join(t.TempDir(), "checks.jsonl")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--http", "--http-connect", addr, "--raw", raw}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	// assets.example.com is the only candidate without a recorded check; the lab serves no fingerprint
	if hits.Load() != 1 || v.Raw != raw || !strings.Contains(v.Summary, "1 checked over HTTP") {
		t.Errorf("hits %d, %s", hits.Load(), out.String())
	}
	for _, f := range v.Findings {
		if strings.Contains(f.Title, "Amazon S3") {
			t.Errorf("assets.example.com showed no fingerprint and is no longer a candidate: %+v", f)
		}
	}
}

func TestBudgetCutsAndPointsToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--max-bytes", "1500"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 1501 {
		t.Errorf("output is %d bytes, want at most 1500", out.Len())
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	json.Unmarshal(out.Bytes(), &v)
	if !v.Budget.Truncated || v.Omitted["locations"] == 0 || len(v.Next) != 1 || !strings.Contains(v.Next[0], "testdata/sample.jsonl") {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--format", "table"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{
		"HIGH     Dangling CNAME to Azure App Service (1)",
		"         NXDOMAIN -> acme-app.azurewebsites.net [Azure App Service]",
		"         claim: create an Azure App Service named acme-app",
		"         app.example.com",
		"group    -> acme-blog.github.io [GitHub Pages] 185.199.108.153 http 200 no match (1)",
		"group    NXDOMAIN (1)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
}

func TestStateMarksNewFindings(t *testing.T) {
	st := filepath.Join(t.TempDir(), "run.state.json")
	args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--state", st}
	var first, second, errb bytes.Buffer
	run(args, &first, &errb)
	run(args, &second, &errb)
	if !strings.Contains(first.String(), ", 7 new\"") || !strings.Contains(second.String(), ", 0 new\"") {
		t.Errorf("first: %s\nsecond: %s", first.String(), second.String())
	}
}

// With only --scope, every name the scope names is checked and wildcards get a next step.
func TestScopeAloneChecksWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\nwww.example.org\n!skip.example.com\n10.0.0.0/30\n192.0.2.10\n172.16.0.0/16\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "names.txt")
	fake := filepath.Join(dir, "dnsx")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -l ] && cp \"$2\" " + got + "; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--dnsx", fake, "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "example.com,www.example.org" {
		t.Errorf("dnsx got names %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com --raw subs.jsonl, then raijin-takeover --scope "+scopePath+" -l subs.jsonl") {
		t.Errorf("next = %v", res.Next)
	}
}

// An old dnsx whose JSON renamed status_code: the run goes on, with both warnings and the same exit code.
func TestEngineVersionAndFormatWarnings(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "dnsx")
	// An older major version than the tested one is always a warning (a newer one may be known-bad).
	want := tested(t)
	major, _ := strconv.Atoi(strings.SplitN(want, ".", 2)[0])
	old := strconv.Itoa(major-1) + ".9.0"
	script := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: ` + old + `" >&2; exit 0; }
echo '{"host":"www.example.com","a":["192.0.2.1"],"status":"NOERROR"}'
echo 'not json'
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw.jsonl")
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "-d", "www.example.com", "--dnsx", fake, "--raw", raw}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 2 || v.Errors[0].Kind != "engine_version" || v.Errors[1].Kind != "engine_format" {
		t.Fatalf("errors: %+v", v.Errors)
	}
	if want := "dnsx " + old + " is not the tested " + want + "; results may be incomplete. Install the tested version: go install github.com/projectdiscovery/dnsx/cmd/dnsx@v" + want + ", or run raijin-mcp update"; v.Errors[0].Hint != want {
		t.Errorf("hint %q", v.Errors[0].Hint)
	}
	if want := "2 of 2 dnsx results had no host and status_code; the engine's output format may have changed. Read " + raw + " for the full output"; v.Errors[1].Hint != want {
		t.Errorf("hint %q", v.Errors[1].Hint)
	}
	if v.Omitted["unparsed"] != 2 {
		t.Errorf("omitted: %v", v.Omitted)
	}
}

// A local go build has no module version: "dev", the short revision and +dirty.
func TestBuildVersionFallback(t *testing.T) {
	cases := []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "true"}}}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "false"}}}, true, "dev-0123456789ab"},
		{&debug.BuildInfo{}, true, "dev"},
		{nil, false, "dev"},
	}
	for _, c := range cases {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion = %q, want %q", got, c.want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if want := "raijin-takeover " + version + " (tested with dnsx " + tested(t) + ")\n"; out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
}

// dnsx 1.3.x is the same major and newer than the tested version, but known-bad: it gets an
// engine_version warning, and the names it wrote no line for an engine_format error. They are still
// listed, as NOANSWER.
func TestKnownBadDnsxAndNamesWithoutALine(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "dnsx")
	// Like dnsx 1.3.1: no line for the NXDOMAIN name, even with -rcode.
	script := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: 1.3.1" >&2; exit 0; }
echo '{"host":"www.example.com","a":["192.0.2.1"],"status_code":"NOERROR"}'
`
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "-d", "www.example.com", "-d", "gone.example.com", "-d", "x.example.org",
		"--dnsx", fake, "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 2 || v.Errors[0].Kind != "engine_version" || v.Errors[1].Kind != "engine_format" {
		t.Fatalf("errors: %+v", v.Errors)
	}
	if h := v.Errors[0].Hint; !strings.HasPrefix(h, "dnsx 1.3.1 is a known-bad version (>=1.3.0): it drops names without records") {
		t.Errorf("engine_version hint %q", h)
	}
	// The out-of-scope name was never sent to dnsx, so it is not counted.
	want := "dnsx wrote no line for 1 of 2 names; dnsx 1.3.0+ drops names without records from -json even with -rcode (projectdiscovery/dnsx#1091). Install dnsx " + tested(t) +
		": go install github.com/projectdiscovery/dnsx/cmd/dnsx@v" + tested(t) + ", or run raijin-mcp update --pinned"
	if v.Errors[1].Hint != want {
		t.Errorf("engine_format hint %q\nwant %q", v.Errors[1].Hint, want)
	}
	listed := false
	for _, g := range v.Groups {
		for _, l := range g.Locations {
			listed = listed || (l == "gone.example.com" && g.Status == "NOANSWER")
		}
	}
	if !listed {
		t.Errorf("gone.example.com must still be listed, as NOANSWER: %s", out.String())
	}
}

// An invalid scope is an error an agent can fix: every bad line is reported at once, as JSON on stdout,
// and nothing runs (no dnsx, no raw file).
func TestInvalidScopeIsStructuredAndRunsNothing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.txt")
	body := "example.com\nexample.com:443\n10.0.0.7/24\n*example.com\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"--scope", p, "-d", "example.com", "--dnsx", "/nonexistent/dnsx"}, &out, &errb)
	if code == 0 {
		t.Fatalf("exit 0 with an invalid scope: %s", out.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,"tool":"raijin-takeover",`) {
		t.Errorf("output must be a result: %s", out.String())
	}
	var o output
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.Summary != "invalid scope file, nothing scanned" || len(o.Findings) != 0 || len(o.Groups) != 0 || o.Raw != "" {
		t.Errorf("nothing may run: %s", out.String())
	}
	if len(o.Errors) != 3 {
		t.Fatalf("want one error per invalid line (3), got %d: %s", len(o.Errors), out.String())
	}
	for i, want := range []string{"line 2", "line 3", "line 4"} {
		if o.Errors[i].Kind != "scope" || !strings.Contains(o.Errors[i].Hint, want) {
			t.Errorf("error %d = %+v, want kind scope and %q", i, o.Errors[i], want)
		}
	}
	if !strings.Contains(o.Errors[0].Hint, "port in rule") || !strings.Contains(o.Errors[1].Hint, "host bits") {
		t.Errorf("hints: %+v", o.Errors)
	}
	for _, e := range o.Errors {
		if strings.Contains(e.Kind, "engine") {
			t.Errorf("no engine ran, got %+v", e)
		}
	}
}

func TestUnreadableScopeIsStructured(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", filepath.Join(t.TempDir(), "missing.txt"), "-d", "example.com"}, &out, &errb)
	var o output
	if code == 0 || json.Unmarshal(out.Bytes(), &o) != nil || len(o.Errors) != 1 || o.Errors[0].Kind != "scope" {
		t.Errorf("exit %d, output %s", code, out.String())
	}
}

func TestReleaseVersionWinsOverBuildInfo(t *testing.T) {
	old := releaseVersion
	defer func() { releaseVersion = old }()
	releaseVersion = "v9.9.9"
	if got := buildVersion(&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want v9.9.9", got)
	}
}
