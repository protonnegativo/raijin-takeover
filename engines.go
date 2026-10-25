// Package raijintakeover holds the engine versions this tool is tested with (engines.json), embedded
// so the binary can compare them with the installed engine.
package raijintakeover

import _ "embed"

// EnginesJSON is engines.json: per engine, the version the bench fixtures were produced with and
// where to install it from.
//
//go:embed engines.json
var EnginesJSON []byte

// Bad is a range of engine versions with a known regression that loses results.
type Bad struct {
	// Range is comma-separated constraints that all hold, each an operator (>=, >, <=, <) and X.Y.Z:
	// ">=1.3.0" while no fixed release exists, ">=1.3.0,<1.3.5" once one does.
	Range string
	// Why is what the regression does, for the engine_version hint.
	Why string
}

// KnownBad lists, per engine, the versions an engine_version error warns about even when they are the
// same major and newer than the tested one in engines.json.
//
// dnsx >=1.3.0: since projectdiscovery/dnsx#988 (v1.3.0), -json drops names that have no record of the
// requested type, even with -rcode, so NXDOMAIN names and dangling CNAMEs get no line at all. The fix
// is proposed in projectdiscovery/dnsx#1091; close the range when a release has it.
var KnownBad = map[string]Bad{
	"dnsx": {Range: ">=1.3.0", Why: "it drops names without records from -json even with -rcode (projectdiscovery/dnsx#1091)"},
}
