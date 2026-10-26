package dnsx

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	raijintakeover "github.com/protonnegativo/raijin-takeover"
)

// Engine is an engines.json entry: the tested version and the install source.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
	// Below is the bound of an open KnownBad range (">=1.3.0" is "below": "1.3.0"), for raijin-mcp
	// update, which installs only versions lower than it.
	Below string `json:"below,omitempty"`
}

// Engines parses the embedded engines.json.
func Engines() (map[string]Engine, error) {
	var m map[string]Engine
	err := json.Unmarshal(raijintakeover.EnginesJSON, &m)
	return m, err
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in a version command's output, or "" if there is none.
// dnsx -version writes its banner and "[INF] Current Version: 1.2.1" to stderr.
func ParseVersion(out string) string {
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

// Version runs "<bin> -version" with a 3s timeout and returns the parsed version, "" if unknown.
func Version(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-version", "-duc").CombinedOutput()
	return ParseVersion(string(out))
}

func parts(v string) []int {
	var p []int
	for _, s := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(s)
		p = append(p, n)
	}
	return p
}

// Untested reports whether the installed version needs a warning: a different major version, or older
// than the tested one. Newer minor or patch versions are left to the weekly drift job, and an unknown
// version is never a warning.
func Untested(installed, tested string) bool {
	if installed == "" || tested == "" {
		return false
	}
	a, b := parts(installed), parts(tested)
	if len(a) != 3 || len(b) != 3 || a[0] != b[0] {
		return len(a) == 3 && len(b) == 3
	}
	for i := 1; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// InRange reports whether version v is in r, comma-separated constraints that all hold (">=1.3.0",
// ">=1.3.0,<1.3.5"). A version or a constraint that does not parse is never in range.
func InRange(v, r string) bool {
	a := parts(v)
	if len(a) != 3 || r == "" {
		return false
	}
	for _, c := range strings.Split(r, ",") {
		c = strings.TrimSpace(c)
		op := strings.TrimRight(c, "0123456789.v")
		b := parts(strings.TrimPrefix(c[len(op):], "v"))
		if len(b) != 3 {
			return false
		}
		cmp := 0
		for i := 0; i < 3 && cmp == 0; i++ {
			if a[i] != b[i] {
				cmp = 1
				if a[i] < b[i] {
					cmp = -1
				}
			}
		}
		ok := false
		switch op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// KnownBad returns the regression of the installed dnsx version, if it is in raijintakeover.KnownBad.
func KnownBad(installed string) (raijintakeover.Bad, bool) {
	b, ok := raijintakeover.KnownBad["dnsx"]
	return b, ok && InRange(installed, b.Range)
}

// KnownBadHint is the engine_version hint for a dnsx version with a known regression.
func KnownBadHint(installed string, b raijintakeover.Bad, e Engine) string {
	return fmt.Sprintf("dnsx %s is a known-bad version (%s): %s; results are incomplete. Install the tested version: go install %s@v%s, or run raijin-mcp update --pinned",
		installed, b.Range, b.Why, e.Go, e.Version)
}

// MissingHint is the engine_format hint when dnsx wrote no line for missing of total names it was given.
func MissingHint(missing, total int, e Engine) string {
	return fmt.Sprintf("dnsx wrote no line for %d of %d names; dnsx 1.3.0+ drops names without records from -json even with -rcode (projectdiscovery/dnsx#1091). Install dnsx %s: go install %s@v%s, or run raijin-mcp update --pinned",
		missing, total, e.Version, e.Go, e.Version)
}

// VersionHint is the engine_version hint for an untested dnsx version.
func VersionHint(installed string, e Engine) string {
	return fmt.Sprintf("dnsx %s is not the tested %s; results may be incomplete. Install the tested version: go install %s@v%s, or run raijin-mcp update",
		installed, e.Version, e.Go, e.Version)
}
