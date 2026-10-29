package reduce

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-takeover/internal/dnsx"
	"github.com/protonnegativo/raijin-takeover/internal/fingerprint"
	"github.com/protonnegativo/raijin-takeover/internal/httpcheck"
	"github.com/protonnegativo/raijin-takeover/internal/schema"
)

func load(t *testing.T) ([]string, []dnsx.Record, []httpcheck.Check) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	names, err := dnsx.ParseNames(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	records, err := dnsx.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	checks, err := httpcheck.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return names, records, checks
}

func inScope(t *testing.T) Options {
	t.Helper()
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	return opt
}

// entries maps every name to the entries (finding or group IDs) it is listed in.
func entries(findings []schema.Finding, groups []schema.Group) map[string][]string {
	out := map[string][]string{}
	for _, f := range findings {
		for _, l := range f.Locations {
			out[l] = append(out[l], f.ID)
		}
	}
	for _, g := range groups {
		for _, l := range g.Locations {
			out[l] = append(out[l], g.ID)
		}
	}
	return out
}

func rec(host, status string, a []string, cname ...string) dnsx.Record {
	return dnsx.Record{Host: host, StatusCode: status, A: a, CNAME: cname}
}

func TestReduce(t *testing.T) {
	names, records, checks := load(t)
	if len(names) != 1 || len(records) != 18 || len(checks) != 3 {
		t.Fatalf("parsed %d names, %d records and %d checks, want 1, 18 and 3 (the log line is skipped)", len(names), len(records), len(checks))
	}
	findings, groups, omitted, all := Reduce(names, records, checks, inScope(t))

	var got []string
	for _, f := range findings {
		got = append(got, f.Severity+":"+f.Confidence+":"+strings.Join(f.Tags, ",")+":"+f.Title+":"+strings.Join(f.Locations, ","))
	}
	want := []string{
		"high::dangling:Dangling CNAME to Azure App Service:app.example.com",
		"high::fingerprint:GitHub Pages fingerprint matched:docs.example.com",
		"medium::dangling:Dangling CNAME to gone.example.net:old.example.com",
		"medium:heuristic:fingerprint:CNAME to Amazon S3: check the HTTP fingerprint:assets.example.com",
		"medium:heuristic:fingerprint:CNAME to Shopify: HTTP check failed:shop.example.com",
		"medium:heuristic:no-address:CNAME to Heroku without an address:status.example.com",
		"low::dangling:Dangling CNAME to Amazon CloudFront (not claimable):cdn-old.example.com",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if f := findings[0]; f.Claim != "create an Azure App Service named acme-app" || f.Status != "NXDOMAIN" || f.Provider != "Azure App Service" || f.Fingerprint != "" {
		t.Errorf("dangling finding = %+v", f)
	}
	if f := findings[1]; f.HTTP != "404 match" || f.Fingerprint != "" || !strings.Contains(f.Claim, "acme-docs") {
		t.Errorf("a matched fingerprint is not repeated, the check is written: %+v", f)
	}
	if f := findings[2]; !strings.Contains(f.Claim, "gone.example.net does not exist") {
		t.Errorf("an unknown target gets the registration hint: %+v", f)
	}
	if f := findings[3]; f.Fingerprint != "The specified bucket does not exist" || f.HTTP != "" {
		t.Errorf("an unchecked candidate carries the fingerprint to look for: %+v", f)
	}
	if f := findings[4]; f.HTTP != "error: timeout" || f.Fingerprint != "" {
		t.Errorf("a failed check is written: %+v", f)
	}
	if f := findings[6]; f.Claim != "" {
		t.Errorf("a provider that is not claimable has no claim hint: %+v", f)
	}

	var gotGroups []string
	for _, g := range groups {
		gotGroups = append(gotGroups, strings.SplitN(g.ID, "-", 2)[0]+":"+g.Provider+":"+g.HTTP+":"+strings.Join(g.Locations, ","))
	}
	wantGroups := []string{
		"in:Azure App Service::web.example.com",
		"in:GitHub Pages:200 no match:blog.example.com",
		"not:Zendesk::help.example.com",
		"a:::api.example.com",
		"a:::www.example.com",
		"cname:::cdn.example.com",
		"noanswer:::missing.example.com",
		"nodata:::empty.example.com",
		"nxdomain:::gone.example.com",
	}
	if strings.Join(gotGroups, "\n") != strings.Join(wantGroups, "\n") {
		t.Errorf("groups:\n%s\nwant:\n%s", strings.Join(gotGroups, "\n"), strings.Join(wantGroups, "\n"))
	}
	if omitted["duplicates"] != 1 || omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(all[findings[0].StateKey]) != 1 {
		t.Errorf("state locations for the first finding = %v", all[findings[0].StateKey])
	}
}

// Lossless: every name given or resolved is in exactly one entry per answer it has.
func TestEveryNameIsListed(t *testing.T) {
	names, records, checks := load(t)
	findings, groups, _, _ := Reduce(names, records, checks, inScope(t))
	listed := entries(findings, groups)
	for _, r := range records {
		if r.Host == "outside.example.org" || r.Probe() {
			continue
		}
		if len(listed[r.Host]) != 1 {
			t.Errorf("%s is listed in %v, want exactly one entry", r.Host, listed[r.Host])
		}
	}
	if len(listed) != 16 {
		t.Errorf("%d names listed, want 16", len(listed))
	}
}

// Lossless: a name given but not resolved is listed: UNCHECKED without dnsx, NOANSWER with dnsx.
func TestUnresolvedNamesAreListed(t *testing.T) {
	names := []string{"a.example.com", "b.example.com"}
	opt := inScope(t)
	opt.Resolved = false
	_, groups, _, _ := Reduce(names, nil, nil, opt)
	if len(groups) != 1 || groups[0].Status != "UNCHECKED" || len(groups[0].Locations) != 2 {
		t.Errorf("not resolved: %+v", groups)
	}
	opt.Resolved = true
	_, groups, _, _ = Reduce(names, []dnsx.Record{rec("a.example.com", "NXDOMAIN", nil)}, nil, opt)
	if len(groups) != 2 || groups[0].Status != "NOANSWER" || groups[1].Status != "NXDOMAIN" {
		t.Errorf("resolved with one missing record: %+v", groups)
	}
}

// Lossless: the same name with two different answers (two replayed runs) is kept in both entries.
func TestSameNameDifferentAnswerIsKept(t *testing.T) {
	records := []dnsx.Record{
		rec("a.example.com", "NXDOMAIN", nil, "a.herokuapp.com"),
		rec("a.example.com", "NOERROR", []string{"192.0.2.2"}, "a.herokuapp.com"),
	}
	findings, groups, omitted, _ := Reduce(nil, records, nil, inScope(t))
	if len(entries(findings, groups)["a.example.com"]) != 2 || omitted["duplicates"] != 0 {
		t.Errorf("both answers must be kept: %+v %+v %v", findings, groups, omitted)
	}
}

// Lossless: two different HTTP checks of one name are both kept; an exact repeat is a duplicate.
func TestEveryHTTPCheckIsKept(t *testing.T) {
	records := []dnsx.Record{rec("docs.example.com", "NOERROR", []string{"185.199.108.153"}, "acme.github.io")}
	checks := []httpcheck.Check{
		{Check: "http", Host: "docs.example.com", Status: 404, Match: true},
		{Check: "http", Host: "docs.example.com", Status: 404, Match: true},
		{Check: "http", Host: "docs.example.com", Error: "timeout"},
	}
	findings, _, omitted, _ := Reduce(nil, records, checks, inScope(t))
	if len(findings) != 2 || findings[0].HTTP != "404 match" || findings[1].HTTP != "error: timeout" || omitted["duplicates"] != 1 {
		t.Errorf("findings = %+v, omitted = %v", findings, omitted)
	}
}

// Only exact repeats collapse: the same answer in another record order or case is a duplicate.
func TestExactDuplicatesAreCounted(t *testing.T) {
	records := []dnsx.Record{
		rec("a.example.com", "NOERROR", []string{"192.0.2.2", "192.0.2.1"}),
		rec("A.example.com.", "noerror", []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"}),
	}
	_, groups, omitted, _ := Reduce([]string{"a.example.com", "a.example.com"}, records, nil, inScope(t))
	if len(groups) != 1 || len(groups[0].Locations) != 1 || omitted["duplicates"] != 2 {
		t.Fatalf("groups=%+v omitted=%v", groups, omitted)
	}
}

// Lossless: names that share an answer collapse into one group, but every name is in it.
func TestSameAnswerCollapsesIntoOneGroup(t *testing.T) {
	var records []dnsx.Record
	for i := 0; i < 30; i++ {
		records = append(records, rec(fmt.Sprintf("h%02d.example.com", i), "NOERROR", []string{"192.0.2.2", "192.0.2.1"}))
	}
	_, groups, _, _ := Reduce(nil, records, nil, inScope(t))
	if len(groups) != 1 || len(groups[0].Locations) != 30 || strings.Join(groups[0].A, ",") != "192.0.2.1,192.0.2.2" {
		t.Errorf("groups = %+v", groups)
	}
}

// Lossless: one dangling name is split out of the names it shares a CNAME with; the rest stay listed.
func TestDanglingNameIsSplitOut(t *testing.T) {
	records := []dnsx.Record{
		rec("a.example.com", "NOERROR", []string{"20.1.1.1"}, "acme.azurewebsites.net"),
		rec("b.example.com", "NOERROR", []string{"20.1.1.1"}, "acme.azurewebsites.net"),
		rec("c.example.com", "NXDOMAIN", nil, "acme2.azurewebsites.net"),
	}
	findings, groups, _, _ := Reduce(nil, records, nil, inScope(t))
	if len(findings) != 1 || findings[0].Locations[0] != "c.example.com" || len(groups) != 1 || len(groups[0].Locations) != 2 {
		t.Errorf("findings = %+v groups = %+v", findings, groups)
	}
}

func TestOutOfScopeIsDroppedAndCounted(t *testing.T) {
	records := []dnsx.Record{rec("a.example.org", "NOERROR", []string{"192.0.2.1"}), rec("a.example.com", "NOERROR", []string{"192.0.2.1"})}
	checks := []httpcheck.Check{{Check: "http", Host: "a.example.org", Status: 200}}
	findings, groups, omitted, _ := Reduce([]string{"b.example.org"}, records, checks, inScope(t))
	if omitted["out_of_scope"] != 2 || len(entries(findings, groups)) != 1 {
		t.Errorf("omitted = %v, listed = %v", omitted, entries(findings, groups))
	}
}

func TestProbesAreNotResults(t *testing.T) {
	_, groups, _, _ := Reduce(nil, []dnsx.Record{rec(dnsx.ProbePrefix+"1a2b3c4d.example.com", "NOERROR", []string{"192.0.2.1"})}, nil, inScope(t))
	if len(groups) != 0 {
		t.Errorf("a raijin-subs wildcard probe is not a result: %+v", groups)
	}
}

func TestTagsAndSeverity(t *testing.T) {
	tests := []struct {
		a     schema.Answer
		tags  string
		sev   string
		conf  string
		title string
	}{
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"x.herokuapp.com"}}, "dangling", "high", "", "Dangling CNAME to Heroku"},
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"x.trafficmanager.net"}}, "dangling", "high", "", "Dangling CNAME to Azure Traffic Manager"},
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"gone.example.net"}}, "dangling", "medium", "", "Dangling CNAME to gone.example.net"},
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"acme.zendesk.com"}}, "dangling", "low", "", "Dangling CNAME to Zendesk (not claimable)"},
		{schema.Answer{CNAME: []string{"b.s3.amazonaws.com"}, A: []string{"52.216.1.1"}}, "fingerprint", "medium", "heuristic", "CNAME to Amazon S3: check the HTTP fingerprint"},
		{schema.Answer{CNAME: []string{"b.s3.amazonaws.com"}, A: []string{"52.216.1.1"}, HTTP: "404 match"}, "fingerprint", "high", "", "Amazon S3 fingerprint matched"},
		{schema.Answer{CNAME: []string{"b.s3.amazonaws.com"}, A: []string{"52.216.1.1"}, HTTP: "error: connection refused"}, "fingerprint", "medium", "heuristic", "CNAME to Amazon S3: HTTP check failed"},
		{schema.Answer{CNAME: []string{"b.s3.amazonaws.com"}, A: []string{"52.216.1.1"}, HTTP: "200 no match"}, "", "", "", ""},
		{schema.Answer{Status: "SERVFAIL", CNAME: []string{"x.azurewebsites.net"}}, "no-address", "medium", "heuristic", "CNAME to Azure App Service without an address"},
		{schema.Answer{CNAME: []string{"x.github.io"}}, "no-address", "medium", "heuristic", "CNAME to GitHub Pages without an address"},
		{schema.Answer{CNAME: []string{"x.azurewebsites.net"}, A: []string{"20.1.1.1"}}, "", "", "", ""},
		{schema.Answer{CNAME: []string{"x.zendesk.com"}}, "", "", "", ""},
		{schema.Answer{CNAME: []string{"x.example.net"}, A: []string{"198.51.100.1"}}, "", "", "", ""},
		{schema.Answer{Status: "NXDOMAIN"}, "", "", "", ""},
		{schema.Answer{A: []string{"198.51.100.1"}}, "", "", "", ""},
	}
	for _, tt := range tests {
		if p, _, ok := fingerprint.Match(tt.a.CNAME); ok {
			tt.a.Provider = p.Name
		}
		tags := Tags(tt.a)
		if strings.Join(tags, ",") != tt.tags {
			t.Errorf("%+v: tags %v, want %s", tt.a, tags, tt.tags)
			continue
		}
		if len(tags) == 0 {
			continue
		}
		if s, c := Severity(tt.a, tags); s != tt.sev || c != tt.conf {
			t.Errorf("%+v: severity %s/%s, want %s/%s", tt.a, s, c, tt.sev, tt.conf)
		}
		if s := Title(tt.a, tags); s != tt.title {
			t.Errorf("%+v: title %q, want %q", tt.a, s, tt.title)
		}
	}
}

func TestHTTPTargets(t *testing.T) {
	names, records, checks := load(t)
	got := HTTPTargets(names, records, checks, inScope(t))
	// docs, blog and shop already have a check; status has no address; app is NXDOMAIN
	if len(got) != 1 || got[0].Host != "assets.example.com" || got[0].Provider != "Amazon S3" || got[0].Body == "" {
		t.Errorf("targets = %+v", got)
	}
	if all := HTTPTargets(names, records, nil, inScope(t)); len(all) != 4 {
		t.Errorf("without checks: %+v", all)
	}
}

func TestRankingIsStable(t *testing.T) {
	names, records, checks := load(t)
	a, _, _, _ := Reduce(names, records, checks, inScope(t))
	b, _, _, _ := Reduce(names, records, checks, inScope(t))
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("the same input gives the same order and IDs: %s vs %s", a[i].ID, b[i].ID)
		}
	}
}

func TestDeadGroupsComeLast(t *testing.T) {
	var records []dnsx.Record
	for i := 0; i < 10; i++ {
		records = append(records, rec(fmt.Sprintf("d%d.example.com", i), "NXDOMAIN", nil))
	}
	records = append(records, rec("www.example.com", "NOERROR", []string{"192.0.2.1"}))
	_, groups, _, _ := Reduce(nil, records, nil, inScope(t))
	if len(groups) != 2 || groups[0].Status != "" {
		t.Errorf("a name that resolves ranks before 10 dead names, so the budget cuts dead names first: %+v", groups)
	}
}

func TestFitCutsLeastImportantFirstAndCountsEverything(t *testing.T) {
	res := &schema.Result{Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 3000}}
	var locs []string
	for i := 0; i < 20; i++ {
		locs = append(locs, fmt.Sprintf("host%02d.example.com", i))
	}
	for i := 0; i < 5; i++ {
		res.Findings = append(res.Findings, schema.Finding{ID: fmt.Sprintf("dangling-%d", i), Severity: "medium", Tags: []string{"dangling"}, Locations: locs, Count: len(locs)})
	}
	res.Groups = []schema.Group{{ID: "nxdomain-x", Answer: schema.Answer{Status: "NXDOMAIN"}, Locations: locs, Count: len(locs)}}

	Fit(res, 3000)
	b, _ := schema.Marshal(res)
	if len(b) > 3000 {
		t.Errorf("size %d > 3000", len(b))
	}
	if !res.Budget.Truncated {
		t.Error("truncation not reported")
	}
	if len(res.Groups) == 1 && res.Groups[0].Locations != nil {
		t.Error("group locations should go before any finding data")
	}
	if len(res.Findings) == 0 || len(res.Findings[0].Locations) != 20 {
		t.Errorf("the top finding should keep its locations while lower data can be cut: %+v", res.Findings)
	}
	if !strings.Contains(string(b), `"count":20`) {
		t.Errorf("a finding or group that lost locations must show its count: %s", b)
	}
	shown := 0
	for _, f := range res.Findings {
		shown += len(f.Locations)
	}
	for _, g := range res.Groups {
		shown += len(g.Locations)
	}
	if res.Omitted["findings"] != 5-len(res.Findings) || res.Omitted["groups"] != 1-len(res.Groups) {
		t.Errorf("omitted = %v", res.Omitted)
	}
	if res.Omitted["locations"]+shown < 20*len(res.Findings)+20*len(res.Groups) {
		t.Errorf("locations not accounted for: omitted=%v shown=%d", res.Omitted, shown)
	}
}
