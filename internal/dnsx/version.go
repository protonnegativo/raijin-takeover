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

// VersionHint is the engine_version hint for an untested dnsx version.
func VersionHint(installed string, e Engine) string {
	return fmt.Sprintf("dnsx %s is not the tested %s; results may be incomplete. Install the tested version: go install %s@v%s",
		installed, e.Version, e.Go, e.Version)
}
