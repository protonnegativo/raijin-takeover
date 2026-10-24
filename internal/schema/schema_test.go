package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-takeover",
		Findings: []Finding{{ID: "fingerprint-ab12cd34", Title: "CNAME to Amazon S3: check the HTTP fingerprint", Severity: "medium", Tags: []string{"fingerprint"}, Answer: Answer{CNAME: []string{"b.s3.amazonaws.com"}, A: []string{"192.0.2.1"}}, Locations: []string{"assets.example.com", "img.example.com"}, Count: 2, StateKey: "fp"}},
		Groups:   []Group{{ID: "a-ef56ab78", Answer: Answer{A: []string{"192.0.2.2"}}, Locations: []string{"www.example.com"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"statekey", "StateKey", "count", "confidence", "status", "aaaa", "provider", "http", "claim", "fingerprint\"", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestAnswerFieldsAreInline(t *testing.T) {
	f := Finding{ID: "dangling-x", Title: "Dangling CNAME to Heroku", Severity: "high", Tags: []string{"dangling"}, Answer: Answer{Status: "NXDOMAIN", CNAME: []string{"acme.herokuapp.com"}, Provider: "Heroku"}, Claim: "create the app", Locations: []string{"app.example.com"}}
	b, _ := json.Marshal(f)
	want := `{"id":"dangling-x","title":"Dangling CNAME to Heroku","severity":"high","tags":["dangling"],"status":"NXDOMAIN","cname":["acme.herokuapp.com"],"provider":"Heroku","claim":"create the app","locations":["app.example.com"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "dangling-x", Tags: []string{"dangling"}, Locations: []string{"a.example.com"}, Count: 7}},
		Groups:   []Group{{ID: "nxdomain-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["a.example.com"],"count":7`) || !strings.Contains(s, `{"id":"nxdomain-y","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
