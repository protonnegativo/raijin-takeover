// Package httpcheck fetches the page a takeover candidate serves and looks for the provider's
// fingerprint, the text the provider shows for a name nobody claimed.
//
// It only runs with --http, and only for names whose CNAME points into a claimable provider whose
// takeover shows in the HTTP body (GitHub Pages, S3, Heroku...). It sends one GET per name (two when the
// plain HTTP request fails or redirects without the fingerprint), reads at most 1 MB of the body, and
// never claims anything.
package httpcheck

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxBody is how much of a page is read; fingerprints are near the top of short error pages.
const maxBody = 1 << 20

// Target is a name to check and the text that means the name is unclaimed.
type Target struct {
	Host     string
	Provider string
	Body     string
}

// Check is the result of one HTTP check. It is written to the raw file as one JSON line, so a saved run
// replays with the same results.
type Check struct {
	Check    string `json:"check"` // always "http"
	Host     string `json:"host"`
	Provider string `json:"provider,omitempty"`
	URL      string `json:"url,omitempty"`
	Status   int    `json:"status,omitempty"`
	Match    bool   `json:"match"`
	Error    string `json:"error,omitempty"`
}

// Outcome is the check in one short string: "404 match", "200 no match" or "error: <reason>".
func (c Check) Outcome() string {
	if c.Error != "" {
		return "error: " + c.Error
	}
	if c.Match {
		return fmt.Sprintf("%d match", c.Status)
	}
	return fmt.Sprintf("%d no match", c.Status)
}

// Options are the HTTP check settings.
type Options struct {
	Timeout     time.Duration
	Concurrency int
	// Connect, if set ("127.0.0.1:19400"), is dialed for every request instead of the name's address,
	// with the name still in the Host header. It is for labs and tests.
	Connect   string
	UserAgent string
	// Raw, if set, receives one JSON line per check.
	Raw io.Writer
}

// Run checks every target and returns the results in the targets' order.
func Run(ctx context.Context, targets []Target, opt Options) []Check {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 10
	}
	dialer := &net.Dialer{Timeout: opt.Timeout}
	tr := &http.Transport{
		// An unclaimed name has no certificate of its own: the provider's default certificate is
		// expected, and only the body matters.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if opt.Connect != "" {
				addr = opt.Connect
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       opt.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	out := make([]Check, len(targets))
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = check(ctx, client, t, opt.UserAgent)
		}(i, t)
	}
	wg.Wait()
	if opt.Raw != nil {
		for _, c := range out {
			b, _ := json.Marshal(c)
			opt.Raw.Write(append(b, '\n'))
		}
	}
	return out
}

// check tries http:// first, then https:// when the first request fails or does not show the
// fingerprint and redirects (many providers redirect plain HTTP to HTTPS).
func check(ctx context.Context, client *http.Client, t Target, ua string) Check {
	c := Check{Check: "http", Host: t.Host, Provider: t.Provider}
	for _, scheme := range []string{"http", "https"} {
		url := scheme + "://" + t.Host + "/"
		status, body, err := fetch(ctx, client, url, ua)
		c.URL = url
		if err != nil {
			c.Status, c.Match, c.Error = 0, false, short(err)
			continue
		}
		c.Status, c.Error = status, ""
		c.Match = t.Body != "" && bytes.Contains(body, []byte(t.Body))
		if c.Match || status < 300 || status >= 400 {
			break
		}
	}
	return c
}

func fetch(ctx context.Context, client *http.Client, url, ua string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, body, err
}

// short is the error without the request it is about: "connection refused", "timeout"...
func short(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

// Parse reads the HTTP checks from a raw file; every other line is skipped.
func Parse(r io.Reader) ([]Check, error) {
	var out []Check
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' || !bytes.Contains(line, []byte(`"check"`)) {
			continue
		}
		var c Check
		if json.Unmarshal(line, &c) != nil || c.Check != "http" || c.Host == "" {
			continue
		}
		out = append(out, c)
	}
	return out, sc.Err()
}
