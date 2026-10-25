package dnsx

import (
	"strings"
	"testing"
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
