package fingerprint

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		chain     []string
		name      string
		claimable bool
		check     string
	}{
		{[]string{"acme.github.io"}, "GitHub Pages", true, HTTP},
		{[]string{"acme-assets.s3.amazonaws.com"}, "Amazon S3", true, HTTP},
		{[]string{"www.example.com.s3-website-us-east-1.amazonaws.com"}, "Amazon S3", true, HTTP},
		{[]string{"b.s3.eu-west-1.amazonaws.com"}, "Amazon S3", true, HTTP},
		{[]string{"s3-us-west-2.amazonaws.com"}, "Amazon S3", true, HTTP},
		{[]string{"my-lb-1.us-east-1.elb.amazonaws.com"}, "AWS ELB", false, ""},
		{[]string{"ec2-1-2-3-4.compute-1.amazonaws.com"}, "AWS", false, ""},
		{[]string{"acme.azurewebsites.net"}, "Azure App Service", true, NXDOMAIN},
		{[]string{"acme.blob.core.windows.net"}, "Azure Blob Storage", true, NXDOMAIN},
		{[]string{"acme.queue.core.windows.net"}, "Azure", false, ""},
		{[]string{"ACME.HerokuApp.com."}, "Heroku", true, HTTP},
		{[]string{"shops.myshopify.com"}, "Shopify", true, HTTP},
		{[]string{"acme.zendesk.com"}, "Zendesk", false, ""},
		{[]string{"d1.cloudfront.net"}, "Amazon CloudFront", false, ""},
		// the first name of the chain decides: the one the owner configured
		{[]string{"docs.example.net", "acme.github.io"}, "GitHub Pages", true, HTTP},
		{[]string{"acme.trafficmanager.net", "acme.azurewebsites.net"}, "Azure Traffic Manager", true, NXDOMAIN},
	}
	for _, tt := range tests {
		p, _, ok := Match(tt.chain)
		if !ok || p.Name != tt.name || p.Claimable != tt.claimable || p.Check != tt.check {
			t.Errorf("Match(%v) = %+v %v, want %s claimable=%v check=%s", tt.chain, p, ok, tt.name, tt.claimable, tt.check)
		}
	}
	for _, chain := range [][]string{nil, {"cdn.example.net"}, {"notgithub.io.example.com"}, {"fakegithub.io"}} {
		if p, _, ok := Match(chain); ok {
			t.Errorf("Match(%v) = %s, want no provider", chain, p.Name)
		}
	}
}

// Every claimable provider says how it is confirmed and how it is claimed; HTTP providers carry the body.
func TestTableIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range append(Providers, s3) {
		if seen[p.Name] {
			t.Errorf("%s is listed twice", p.Name)
		}
		seen[p.Name] = true
		if len(p.Suffixes) == 0 && p.Name != s3.Name {
			t.Errorf("%s has no suffix", p.Name)
		}
		if p.Claimable != (p.Check != "") || p.Claimable != (p.Claim != "") || (p.Check == HTTP) != (p.Body != "") {
			t.Errorf("%s: claimable=%v check=%q body=%q claim=%q", p.Name, p.Claimable, p.Check, p.Body, p.Claim)
		}
	}
}

func TestClaimHint(t *testing.T) {
	p, target, _ := Match([]string{"acme.azurewebsites.net"})
	if got := p.ClaimHint(target); got != "create an Azure App Service named acme" {
		t.Errorf("hint = %q", got)
	}
}
