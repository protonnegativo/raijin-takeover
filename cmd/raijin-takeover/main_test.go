package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

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
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-takeover v"+version) {
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
