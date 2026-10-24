package httpcheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// lab starts a local server on the first free port in 19400-19449 (the range this project's tests and
// benchmark use). It answers by Host header, like a provider does.
func lab(t *testing.T) string {
	t.Helper()
	var ln net.Listener
	var err error
	for port := 19400; port <= 19449; port++ {
		if ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			break
		}
	}
	if ln == nil {
		t.Skip("no free port in 19400-19449")
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "gone.example.com":
			w.WriteHeader(404)
			fmt.Fprint(w, "<html><body>There isn't a GitHub Pages site here.</body></html>")
		case "redirect.example.com":
			http.Redirect(w, r, "https://redirect.example.com/", http.StatusMovedPermanently)
		default:
			fmt.Fprint(w, "welcome")
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestRunMatchesTheFingerprint(t *testing.T) {
	addr := lab(t)
	body := "There isn't a GitHub Pages site here."
	targets := []Target{
		{Host: "gone.example.com", Provider: "GitHub Pages", Body: body},
		{Host: "live.example.com", Provider: "GitHub Pages", Body: body},
		{Host: "redirect.example.com", Provider: "GitHub Pages", Body: body},
	}
	var raw bytes.Buffer
	got := Run(context.Background(), targets, Options{Connect: addr, Timeout: 3 * time.Second, Raw: &raw})
	var outcomes []string
	for _, c := range got {
		outcomes = append(outcomes, c.Outcome())
	}
	// the redirect is followed by an https:// request, which the plain lab cannot answer
	if outcomes[0] != "404 match" || outcomes[1] != "200 no match" || !strings.HasPrefix(outcomes[2], "error: ") {
		t.Errorf("outcomes = %v", outcomes)
	}
	again, err := Parse(&raw)
	if err != nil || len(again) != 3 || again[0] != got[0] || again[2].URL != "https://redirect.example.com/" {
		t.Errorf("raw replay = %+v, %v", again, err)
	}
}

func TestParseSkipsOtherLines(t *testing.T) {
	in := `{"host":"a.example.com","status_code":"NOERROR"}
{"check":"http","host":"a.example.com","status":404,"match":true}
{"check":"dns","host":"b.example.com"}
not json`
	got, _ := Parse(strings.NewReader(in))
	if len(got) != 1 || got[0].Outcome() != "404 match" {
		t.Errorf("got %+v", got)
	}
}
