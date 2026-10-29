// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every name is listed, in a finding or in a group, and
// anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-takeover adds the DNS answer (status, cname, a, aaaa, provider) and the HTTP check result to
// findings and groups, and the claim hint and HTTP fingerprint to findings: they are what an agent reads
// to decide whether a dangling record can be taken over.
package schema

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core; the aliases keep
// the call sites unchanged. Finding and Group stay here: their fields are this tool's contract.
type (
	// Result is the top-level object raijin-takeover writes to stdout.
	Result = core.Result[Finding, Group]
	// Error is a problem during the run, with a hint about what to try next.
	Error = core.Error
	// Budget reports the output limits that were applied.
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

// Answer is what every name in a finding or group resolved to, plus the HTTP check when one ran. Zero
// values are left out: no status means NOERROR with at least one record, no cname means the name has no
// CNAME, no a or aaaa means no record of that type, no http means the name was not checked over HTTP.
type Answer struct {
	// Status is the DNS status when it is not NOERROR with records: NXDOMAIN, SERVFAIL, REFUSED...,
	// NODATA (NOERROR without A, AAAA or CNAME), NOANSWER (dnsx returned nothing for the name) or
	// UNCHECKED (dnsx did not run).
	Status string `json:"status,omitempty"`
	// CNAME is the chain, in the order the resolver returned it.
	CNAME []string `json:"cname,omitempty"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	// Provider is the service the CNAME chain points into, when it is in the fingerprint table.
	Provider string `json:"provider,omitempty"`
	// HTTP is the result of the --http check: "404 match", "200 no match" or "error: <reason>".
	HTTP string `json:"http,omitempty"`
}

// Finding is one takeover candidate (a CNAME into a service where names can be claimed, or a CNAME
// that ends in NXDOMAIN) with every name that has the same answer.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: dangling, fingerprint, no-address.
	Tags []string `json:"tags"`
	Answer
	// Claim says how the name would be claimed on the provider. It is a hint for the report, not an
	// instruction: never claim a name without authorization.
	Claim string `json:"claim,omitempty"`
	// Fingerprint is the text the provider's page shows for an unclaimed name. It is written when the
	// HTTP body decides the finding and the --http check did not run.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Locations are every name with this answer.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// StateKey is the internal key for --state; it is derived from the ID and not written.
	StateKey string `json:"-"`
	New      bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

// Group is one answer that is not a takeover candidate (names behind the same IPs, a provider where
// names cannot be claimed, names that do not resolve), with every name that has it.
type Group struct {
	ID string `json:"id"`
	Answer
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}
