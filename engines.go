// Package raijintakeover holds the engine versions this tool is tested with (engines.json), embedded
// so the binary can compare them with the installed engine.
package raijintakeover

import _ "embed"

// EnginesJSON is engines.json: per engine, the version the bench fixtures were produced with and
// where to install it from.
//
//go:embed engines.json
var EnginesJSON []byte
