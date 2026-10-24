// Package reduce turns raw dnsx results (and HTTP checks) into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every name given or resolved is kept, with its DNS status,
// CNAME chain, A and AAAA records and HTTP check. Names with the same answer collapse into one entry
// that lists every name. Only exact duplicates are dropped. A byte budget can cut, but every cut is
// counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-takeover/internal/dnsx"
	"github.com/protonnegativo/raijin-takeover/internal/fingerprint"
	"github.com/protonnegativo/raijin-takeover/internal/httpcheck"
	"github.com/protonnegativo/raijin-takeover/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	// Resolved is false when dnsx did not run: a name with no record is UNCHECKED instead of NOANSWER.
	Resolved bool
	InScope  func(name string) bool
}

// Defaults keep every finding. The byte cap is the one raijin-subs uses: a takeover run lists every
// name it was given, and 64,000 bytes holds about 2,000 names.
func Defaults() Options {
	return Options{MaxBytes: 64000, Resolved: true}
}

// The rules that make an answer a finding. Only answers whose CNAME chain is a takeover candidate are
// findings; everything else is a group.
//
//	dangling     the name has a CNAME and the chain ends in NXDOMAIN: high when the target is a provider
//	             where names can be claimed, medium when the provider is unknown (the target's domain
//	             may be free to register), low when the provider is known and not claimable (a stale
//	             record, not a takeover)
//	fingerprint  the CNAME points into a claimable provider whose takeover shows in the HTTP body and
//	             the name resolves: medium and heuristic until --http checks it; high when the body has
//	             the fingerprint; a group when it does not
//	no-address   the CNAME points into a claimable provider and the chain resolves to no address
//	             (NODATA, SERVFAIL...): medium, heuristic
var tagOrder = []string{"dangling", "fingerprint", "no-address"}

type cluster struct {
	key  string
	ans  schema.Answer
	locs map[string]bool
}

type nameInfo struct {
	answers []schema.Answer
	seen    map[string]bool // answer keys, for duplicates
	http    []string
}

// Reduce collapses the results into findings and groups: one entry per distinct answer, listing every
// name that has it. It also returns every location per finding state key, before any budget, for --state.
func Reduce(names []string, records []dnsx.Record, checks []httpcheck.Check, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	infos, order := collect(names, records, checks, opt, omitted)

	clusters := map[string]*cluster{}
	var keys []string
	for _, n := range order {
		info := infos[n]
		for _, a := range info.answers {
			https := info.http
			if len(https) == 0 {
				https = []string{""}
			}
			for _, h := range https {
				a := a
				a.HTTP = h
				key := answerKey(a)
				c, ok := clusters[key]
				if !ok {
					if p, _, ok := fingerprint.Match(a.CNAME); ok {
						a.Provider = p.Name
					}
					c = &cluster{key: key, ans: a, locs: map[string]bool{}}
					clusters[key] = c
					keys = append(keys, key)
				}
				c.locs[n] = true
			}
		}
	}

	findings := []schema.Finding{}
	groups := []schema.Group{}
	allLocations := map[string][]string{}
	for _, key := range keys {
		c := clusters[key]
		locs := sorted(c.locs)
		tags := Tags(c.ans)
		if len(tags) == 0 {
			groups = append(groups, schema.Group{ID: groupPrefix(c.ans) + "-" + hash(key)[:8], Answer: c.ans, Locations: locs, Count: len(locs)})
			continue
		}
		id := tags[0] + "-" + hash(key)[:8]
		f := schema.Finding{ID: id, Title: Title(c.ans, tags), Tags: tags, Answer: c.ans, Locations: locs, Count: len(locs), StateKey: hash(id)}
		f.Severity, f.Confidence = Severity(c.ans, tags)
		p, target, _ := fingerprint.Match(c.ans.CNAME)
		switch {
		case p.Claimable:
			f.Claim = p.ClaimHint(target)
		case p.Name == "":
			f.Claim = "the CNAME target " + c.ans.CNAME[len(c.ans.CNAME)-1] + " does not exist: check whether its domain can be registered"
		}
		if tags[0] == "fingerprint" && c.ans.HTTP == "" {
			f.Fingerprint = p.Body
		}
		allLocations[f.StateKey] = locs
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	// Names behind a known provider come first, then other names that resolve, then names that do not,
	// so the budget cuts dead names first.
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if ra, rb := groupRank(a.Answer), groupRank(b.Answer); ra != rb {
			return ra < rb
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// collect normalizes the names, drops what is out of scope, and merges each name's DNS answers and
// HTTP checks. Exact repeats are counted in omitted.duplicates.
func collect(names []string, records []dnsx.Record, checks []httpcheck.Check, opt Options, omitted map[string]int) (map[string]*nameInfo, []string) {
	infos := map[string]*nameInfo{}
	var order []string
	dropped := map[string]bool{}
	given := map[string]bool{}

	add := func(raw string) *nameInfo {
		n := Normalize(raw)
		if n == "" {
			return nil
		}
		if opt.InScope != nil && !opt.InScope(n) {
			if !dropped[n] {
				dropped[n] = true
				omitted["out_of_scope"]++
			}
			return nil
		}
		info, ok := infos[n]
		if !ok {
			info = &nameInfo{seen: map[string]bool{}}
			infos[n] = info
			order = append(order, n)
		}
		return info
	}

	for _, raw := range names {
		if add(raw) == nil {
			continue
		}
		n := Normalize(raw)
		if given[n] {
			omitted["duplicates"]++
		}
		given[n] = true
	}
	for _, rec := range records {
		if rec.Probe() {
			continue
		}
		info := add(rec.Host)
		if info == nil {
			continue
		}
		a := answer(rec)
		k := answerKey(a)
		if info.seen[k] {
			omitted["duplicates"]++
			continue
		}
		info.seen[k] = true
		info.answers = append(info.answers, a)
	}
	for _, c := range checks {
		info := add(c.Host)
		if info == nil {
			continue
		}
		o := c.Outcome()
		if info.seen["http:"+o] {
			omitted["duplicates"]++
			continue
		}
		info.seen["http:"+o] = true
		info.http = append(info.http, o)
	}
	for _, n := range order {
		if info := infos[n]; len(info.answers) == 0 {
			status := "NOANSWER"
			if !opt.Resolved {
				status = "UNCHECKED"
			}
			info.answers = []schema.Answer{{Status: status}}
		}
	}
	return infos, order
}

// HTTPTargets are the names the --http check fetches: those with an answer whose CNAME points into a
// claimable provider that is recognised by its HTTP body, that resolve, and that have no check yet.
func HTTPTargets(names []string, records []dnsx.Record, checks []httpcheck.Check, opt Options) []httpcheck.Target {
	infos, order := collect(names, records, checks, opt, map[string]int{})
	var out []httpcheck.Target
	for _, n := range order {
		info := infos[n]
		if len(info.http) > 0 {
			continue
		}
		for _, a := range info.answers {
			if p, _, ok := fingerprint.Match(a.CNAME); ok && p.Check == fingerprint.HTTP && a.Status == "" && hasAddress(a) {
				out = append(out, httpcheck.Target{Host: n, Provider: p.Name, Body: p.Body})
				break
			}
		}
	}
	return out
}

// Tags returns the rules an answer matches, in tagOrder. No tags means it goes to a group.
func Tags(a schema.Answer) []string {
	if len(a.CNAME) == 0 {
		return nil
	}
	if a.Status == "NXDOMAIN" {
		return []string{"dangling"}
	}
	p, _, _ := fingerprint.Match(a.CNAME)
	if !p.Claimable {
		return nil
	}
	if a.Status != "" || !hasAddress(a) {
		return []string{"no-address"}
	}
	if p.Check == fingerprint.HTTP && !strings.HasSuffix(a.HTTP, " no match") {
		return []string{"fingerprint"}
	}
	return nil
}

// Severity and confidence of a finding (see tagOrder).
func Severity(a schema.Answer, tags []string) (string, string) {
	p, _, known := fingerprint.Match(a.CNAME)
	switch tags[0] {
	case "dangling":
		switch {
		case p.Claimable:
			return "high", ""
		case known:
			return "low", ""
		}
		return "medium", ""
	case "fingerprint":
		if matched(a.HTTP) {
			return "high", ""
		}
		return "medium", "heuristic"
	}
	return "medium", "heuristic"
}

// Title is one line per finding.
func Title(a schema.Answer, tags []string) string {
	target := a.Provider
	if target == "" {
		target = a.CNAME[len(a.CNAME)-1]
	}
	switch tags[0] {
	case "dangling":
		p, _, known := fingerprint.Match(a.CNAME)
		if known && !p.Claimable {
			return "Dangling CNAME to " + target + " (not claimable)"
		}
		return "Dangling CNAME to " + target
	case "fingerprint":
		switch {
		case matched(a.HTTP):
			return target + " fingerprint matched"
		case strings.HasPrefix(a.HTTP, "error"):
			return "CNAME to " + target + ": HTTP check failed"
		}
		return "CNAME to " + target + ": check the HTTP fingerprint"
	}
	return "CNAME to " + target + " without an address"
}

func answer(rec dnsx.Record) schema.Answer {
	a := schema.Answer{
		Status: strings.ToUpper(strings.TrimSpace(rec.StatusCode)),
		A:      uniqueSorted(rec.A),
		AAAA:   uniqueSorted(rec.AAAA),
	}
	for _, c := range rec.CNAME {
		c = Normalize(c)
		if c != "" && (len(a.CNAME) == 0 || a.CNAME[len(a.CNAME)-1] != c) {
			a.CNAME = append(a.CNAME, c)
		}
	}
	if a.Status == "NOERROR" {
		a.Status = ""
		if len(a.A)+len(a.AAAA)+len(a.CNAME) == 0 {
			a.Status = "NODATA"
		}
	}
	return a
}

// answerKey is what makes two names the same: status, CNAME chain, A, AAAA and HTTP check.
func answerKey(a schema.Answer) string {
	b, _ := schema.Marshal([]any{a.Status, a.CNAME, a.A, a.AAAA, a.HTTP})
	return string(b)
}

// groupPrefix names why an answer is not a candidate:
//
//	in-use         a claimable provider, and the resource exists (the target resolves, or its page has
//	               no fingerprint)
//	not-claimable  a known provider where names cannot be claimed by others
//	cname          a CNAME to a target that is not in the table, and it resolves
//	a              no CNAME
//	<status>       the name does not resolve and has no CNAME (nxdomain, nodata, servfail, noanswer,
//	               unchecked...)
func groupPrefix(a schema.Answer) string {
	p, _, known := fingerprint.Match(a.CNAME)
	switch {
	case known && p.Claimable:
		return "in-use"
	case known:
		return "not-claimable"
	case a.Status != "":
		return strings.ToLower(a.Status)
	case len(a.CNAME) > 0:
		return "cname"
	}
	return "a"
}

func groupRank(a schema.Answer) int {
	switch {
	case a.Provider != "":
		return 0
	case a.Status == "":
		return 1
	}
	return 2
}

// matched is true when the HTTP check found the fingerprint ("404 match").
func matched(http string) bool {
	return !strings.HasPrefix(http, "error") && strings.HasSuffix(http, " match") && !strings.HasSuffix(http, " no match")
}

func hasAddress(a schema.Answer) bool {
	return len(a.A)+len(a.AAAA) > 0
}

// Normalize lowercases a name and removes the trailing dot and a leading "*.".
func Normalize(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	return strings.TrimPrefix(s, "*.")
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
