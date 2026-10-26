package dnsx

import (
	"strings"
	"testing"

	raijintakeover "github.com/protonnegativo/raijin-takeover"
)

func TestEngines(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	// raijin-takeover runs one engine: dnsx.
	if e := m["dnsx"]; ParseVersion(e.Version) != e.Version || e.Go == "" {
		t.Errorf("dnsx entry: %+v", e)
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		// dnsx v1.2.1 -version -duc, stderr with colors.
		"\n      _             __  __\n   __| | _ __   ___ \\ \\/ /\n\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: 1.2.1\n": "1.2.1",
		"[INF] Current Version: v1.3.0":           "1.3.0",
		"flag provided but not defined: -version": "",
		"": "",
	} {
		if got := ParseVersion(in); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUntested(t *testing.T) {
	for _, c := range []struct {
		installed string
		want      bool
	}{
		{"1.2.1", false}, {"1.2.5", false}, {"1.3.0", false},
		{"1.2.0", true}, {"1.1.9", true}, {"2.0.0", true}, {"0.9.0", true},
		{"", false},
	} {
		if got := Untested(c.installed, "1.2.1"); got != c.want {
			t.Errorf("Untested(%q, 1.2.1) = %v, want %v", c.installed, got, c.want)
		}
	}
}

func TestFormatCountsRenamedFields(t *testing.T) {
	f := &Format{}
	recs, err := parse(strings.NewReader(`{"host":"a.example.com","a":["192.0.2.1"],"status_code":"NOERROR"}
{"host":"b.example.com","a":["192.0.2.2"],"status":"NOERROR"}
[INF] something
`), f)
	if err != nil || len(recs) != 1 || f.Lines != 3 || f.Bad != 2 {
		t.Errorf("records %d, format %+v, err %v", len(recs), f, err)
	}
}

func TestInRangeAndKnownBad(t *testing.T) {
	for _, c := range []struct {
		v, r string
		want bool
	}{
		{"1.3.0", ">=1.3.0", true}, {"1.3.1", ">=1.3.0", true}, {"2.0.0", ">=1.3.0", true},
		{"1.2.1", ">=1.3.0", false}, {"1.2.9", ">=1.3.0", false},
		{"1.3.4", ">=1.3.0,<1.3.5", true}, {"1.3.5", ">=1.3.0,<1.3.5", false},
		{"1.3.5", "<=1.3.5", true}, {"1.3.5", ">1.3.5", false},
		{"", ">=1.3.0", false}, {"1.3.0", "", false}, {"1.3.0", "~1.3.0", false},
	} {
		if got := InRange(c.v, c.r); got != c.want {
			t.Errorf("InRange(%q, %q) = %v, want %v", c.v, c.r, got, c.want)
		}
	}
	// dnsx 1.3.x drops NXDOMAIN names from -json (projectdiscovery/dnsx#1091): known-bad although it is
	// the same major and newer than the tested 1.2.1, so Untested alone would not warn.
	if _, bad := KnownBad("1.3.1"); !bad || Untested("1.3.1", "1.2.1") {
		t.Error("dnsx 1.3.1 must be known-bad")
	}
	if _, bad := KnownBad("1.2.1"); bad {
		t.Error("dnsx 1.2.1 is not known-bad")
	}
}

// The drift job bumps engines.json only when the new dnsx passes its NXDOMAIN check. If it passes but
// is still in KnownBad, the fix has shipped: close the range in engines.go.
func TestTestedIsNotKnownBad(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	if b, bad := KnownBad(m["dnsx"].Version); bad {
		t.Errorf("engines.json tests dnsx %s, which KnownBad lists as %s; if it writes NXDOMAIN lines again, close the range in engines.go", m["dnsx"].Version, b.Range)
	}
}

func TestMissing(t *testing.T) {
	recs := []Record{{Host: "a.example.com", StatusCode: "NOERROR"}, {Host: "B.example.com.", StatusCode: "NXDOMAIN"}}
	if n := Missing([]string{"a.example.com", "b.example.com", "c.example.com", "C.example.com", ""}, recs); n != 1 {
		t.Errorf("Missing = %d, want 1", n)
	}
}

// raijin-mcp update reads "below" from engines.json, the tool reads KnownBad: an open range ">=X" is
// "below": "X", and a bound is only set for a known-bad range.
func TestBelowMatchesKnownBad(t *testing.T) {
	m, err := Engines()
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range m {
		want := ""
		if b, ok := raijintakeover.KnownBad[name]; ok && strings.HasPrefix(b.Range, ">=") && !strings.Contains(b.Range, ",") {
			want = strings.TrimPrefix(b.Range, ">=")
		}
		if e.Below != want {
			t.Errorf("engines.json %s below %q, want %q from KnownBad", name, e.Below, want)
		}
	}
}
