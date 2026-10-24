package dnsx

import (
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	got := strings.Join(Args("names.txt", Options{Rate: 50, Threads: 10, Resolvers: "1.1.1.1", Extra: []string{"-retry", "3"}}), " ")
	want := "-l names.txt -a -aaaa -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused -rl 50 -t 10 -r 1.1.1.1 -retry 3"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseSkipsOtherLines(t *testing.T) {
	in := strings.Join([]string{
		`{"host":"a.example.com","input":"example.com","sources":["crtsh"]}`,
		`{"host":"a.example.com","ttl":300,"a":["192.0.2.1"],"cname":["x.example.net"],"status_code":"NOERROR"}`,
		`{"host":"b.example.com","status_code":"NXDOMAIN"}`,
		`{"check":"http","host":"a.example.com","status":404,"match":true}`,
		`a.example.com [A] [192.0.2.1]`,
		`{"host":"c.example.com","a":"not-a-list","status_code":"NOERROR"}`,
	}, "\n")
	recs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].A[0] != "192.0.2.1" || recs[0].CNAME[0] != "x.example.net" || recs[1].StatusCode != "NXDOMAIN" {
		t.Errorf("got %+v", recs)
	}
	names, err := ParseNames(strings.NewReader(in + "\nplain.example.com\n# comment.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "a.example.com,plain.example.com" {
		t.Errorf("names = %v (subfinder lines and plain names only)", names)
	}
}

func TestProbe(t *testing.T) {
	if !(Record{Host: ProbePrefix + "00ff00ff.example.com"}).Probe() || (Record{Host: "www.example.com"}).Probe() {
		t.Error("Probe() must recognise raijin-subs probe names only")
	}
}
