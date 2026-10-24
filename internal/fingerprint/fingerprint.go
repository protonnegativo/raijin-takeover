// Package fingerprint is the table of services a dangling CNAME can point into, and how a takeover of
// each one is recognised and claimed.
//
// The table follows the public can-i-take-over-xyz list (github.com/EdOverflow/can-i-take-over-xyz):
// which services let anyone register a name that a CNAME points to, whether the sign is NXDOMAIN or a
// page the service shows for an unclaimed name, and how the name is claimed. Services the list marks as
// not vulnerable are in the table too, so a CNAME to them is labelled and not reported. The table is a
// set of hints: a match is a takeover candidate, not a verified takeover, and raijin-takeover never
// claims anything.
package fingerprint

import "strings"

// How a takeover of a provider shows up.
const (
	// NXDOMAIN: the CNAME target does not exist. A target that resolves is a resource in use.
	NXDOMAIN = "nxdomain"
	// HTTP: the target always resolves (the service answers for any name under it), and the page
	// served for the name says it is unclaimed. Only the HTTP body tells.
	HTTP = "http"
)

// Provider is one service. Claim is the hint written on a finding; {label} is replaced with the first
// label of the CNAME target ("acme" in acme.herokuapp.com). Edge cases (the list marks them so: the
// claim works only under some conditions) say so in the hint.
type Provider struct {
	Name      string
	Suffixes  []string
	Claimable bool
	Check     string // NXDOMAIN or HTTP; empty when not claimable
	Body      string // text of the unclaimed page, for HTTP
	Claim     string
}

// s3 is matched by its own rule: bucket endpoints have many shapes (bucket.s3.amazonaws.com,
// bucket.s3.us-east-1.amazonaws.com, bucket.s3-website-eu-west-1.amazonaws.com, s3-us-west-2...).
var s3 = Provider{
	Name: "Amazon S3", Claimable: true, Check: HTTP, Body: "The specified bucket does not exist",
	Claim: "create an S3 bucket in the endpoint's region named as the endpoint expects (the requested hostname for website endpoints, {label} otherwise)",
}

// Providers are matched by suffix of a CNAME target. The first entry that matches wins, so specific
// suffixes come before general ones (elb.amazonaws.com before amazonaws.com).
var Providers = []Provider{
	// NXDOMAIN: anyone can create a resource with the name the CNAME expects.
	{Name: "Azure App Service", Suffixes: []string{"azurewebsites.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure App Service named {label}"},
	{Name: "Azure Cloud Service", Suffixes: []string{"cloudapp.net", "cloudapp.azure.com"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure cloud service or public IP with the DNS label {label} in the same region"},
	{Name: "Azure Traffic Manager", Suffixes: []string{"trafficmanager.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure Traffic Manager profile named {label}"},
	{Name: "Azure Blob Storage", Suffixes: []string{"blob.core.windows.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure storage account named {label}"},
	{Name: "Azure CDN", Suffixes: []string{"azureedge.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure CDN endpoint named {label}"},
	{Name: "Azure API Management", Suffixes: []string{"azure-api.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure API Management service named {label}"},
	{Name: "Azure Container Instances", Suffixes: []string{"azurecontainer.io"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure container group with the DNS label {label} in the same region"},
	{Name: "Azure HDInsight", Suffixes: []string{"azurehdinsight.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure HDInsight cluster named {label}"},
	{Name: "Azure Container Registry", Suffixes: []string{"azurecr.io"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure container registry named {label}"},
	{Name: "Azure Cache for Redis", Suffixes: []string{"redis.cache.windows.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure Cache for Redis named {label}"},
	{Name: "Azure SQL Database", Suffixes: []string{"database.windows.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure SQL server named {label}"},
	{Name: "Azure Service Bus", Suffixes: []string{"servicebus.windows.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure Service Bus namespace named {label}"},
	{Name: "Azure Cognitive Search", Suffixes: []string{"search.windows.net"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Azure search service named {label}"},
	{Name: "Azure DevOps", Suffixes: []string{"visualstudio.com"}, Claimable: true, Check: NXDOMAIN, Claim: "create the Azure DevOps organization {label}"},
	{Name: "AWS Elastic Beanstalk", Suffixes: []string{"elasticbeanstalk.com"}, Claimable: true, Check: NXDOMAIN, Claim: "create an Elastic Beanstalk environment with the CNAME prefix {label} in the same region"},
	{Name: "Discourse", Suffixes: []string{"trydiscourse.com"}, Claimable: true, Check: NXDOMAIN, Claim: "create a hosted Discourse site and add the hostname as custom domain"},

	// HTTP: the service answers for any name and shows a page for unclaimed ones.
	{Name: "GitHub Pages", Suffixes: []string{"github.io"}, Claimable: true, Check: HTTP, Body: "There isn't a GitHub Pages site here.", Claim: "create the GitHub user or org {label} if it is free, then a Pages repository with the hostname as custom domain"},
	{Name: "Heroku", Suffixes: []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, Claimable: true, Check: HTTP, Body: "No such app", Claim: "edge case: create a Heroku app and add the hostname as custom domain; the DNS target Heroku gives must match the CNAME"},
	{Name: "Fastly", Suffixes: []string{"fastly.net"}, Claimable: true, Check: HTTP, Body: "Fastly error: unknown domain", Claim: "edge case: add the hostname as a domain of a Fastly service; Fastly refuses it if another account holds it"},
	{Name: "Shopify", Suffixes: []string{"myshopify.com"}, Claimable: true, Check: HTTP, Body: "Sorry, this shop is currently unavailable", Claim: "edge case: connect the hostname as a domain of a Shopify store"},
	{Name: "Netlify", Suffixes: []string{"netlify.app", "netlify.com"}, Claimable: true, Check: HTTP, Body: "Not Found - Request ID", Claim: "edge case: add the hostname as custom domain of a Netlify site"},
	{Name: "Help Scout", Suffixes: []string{"helpscoutdocs.com"}, Claimable: true, Check: HTTP, Body: "No settings were found for this company:", Claim: "add the hostname as custom domain of a Help Scout Docs site"},
	{Name: "Ghost", Suffixes: []string{"ghost.io"}, Claimable: true, Check: HTTP, Body: "Failed to resolve DNS path for this host", Claim: "create a Ghost(Pro) site and add the hostname as custom domain"},
	{Name: "Pantheon", Suffixes: []string{"pantheonsite.io"}, Claimable: true, Check: HTTP, Body: "The gods are wise, but do not know of the site which you seek.", Claim: "create a Pantheon site and add the hostname as its domain"},
	{Name: "ReadMe", Suffixes: []string{"readme.io"}, Claimable: true, Check: HTTP, Body: "The creators of this project are still working on making everything perfect!", Claim: "create a ReadMe project and add the hostname as custom domain"},
	{Name: "Surge", Suffixes: []string{"surge.sh"}, Claimable: true, Check: HTTP, Body: "project not found", Claim: "deploy a Surge project with the hostname as its domain"},
	{Name: "Bitbucket", Suffixes: []string{"bitbucket.io"}, Claimable: true, Check: HTTP, Body: "Repository not found", Claim: "create the Bitbucket workspace {label} and its {label}.bitbucket.io repository"},
	{Name: "WordPress.com", Suffixes: []string{"wordpress.com"}, Claimable: true, Check: HTTP, Body: "Do you want to register", Claim: "register {label}.wordpress.com and map the hostname to it"},
	{Name: "Tumblr", Suffixes: []string{"domains.tumblr.com"}, Claimable: true, Check: HTTP, Body: "Whatever you were looking for doesn't currently exist at this address", Claim: "edge case: add the hostname as custom domain of a Tumblr blog"},
	{Name: "Agile CRM", Suffixes: []string{"agilecrm.com"}, Claimable: true, Check: HTTP, Body: "Sorry, this page is no longer available.", Claim: "create an Agile CRM account and map the hostname to it"},
	{Name: "Cargo", Suffixes: []string{"cargocollective.com"}, Claimable: true, Check: HTTP, Body: "404 Not Found", Claim: "add the hostname as custom domain of a Cargo site"},
	{Name: "LaunchRock", Suffixes: []string{"launchrock.com"}, Claimable: true, Check: HTTP, Body: "It looks like you may have taken a wrong turn somewhere.", Claim: "create a LaunchRock page and add the hostname as its domain"},
	{Name: "ngrok", Suffixes: []string{"ngrok.io"}, Claimable: true, Check: HTTP, Body: "ngrok.io not found", Claim: "start an ngrok tunnel with the hostname as custom domain (paid plan)"},
	{Name: "SmartJobBoard", Suffixes: []string{"smartjobboard.com"}, Claimable: true, Check: HTTP, Body: "This job board website is either expired or its domain name is invalid.", Claim: "create a SmartJobBoard site and add the hostname as its domain"},
	{Name: "Uberflip", Suffixes: []string{"read.uberflip.com"}, Claimable: true, Check: HTTP, Body: "The URL you've accessed does not provide a hub.", Claim: "create an Uberflip hub and add the hostname as its domain"},
	{Name: "UptimeRobot", Suffixes: []string{"stats.uptimerobot.com"}, Claimable: true, Check: HTTP, Body: "page not found", Claim: "create an UptimeRobot status page with the hostname as custom domain"},
	{Name: "UserVoice", Suffixes: []string{"uservoice.com"}, Claimable: true, Check: HTTP, Body: "This UserVoice subdomain is currently available!", Claim: "create the UserVoice site {label} and map the hostname to it"},
	{Name: "Canny", Suffixes: []string{"canny.io"}, Claimable: true, Check: HTTP, Body: "Company Not Found", Claim: "create a Canny company and add the hostname as custom domain"},
	{Name: "Gemfury", Suffixes: []string{"furyns.com"}, Claimable: true, Check: HTTP, Body: "404: This page could not be found.", Claim: "create the Gemfury account {label}"},
	{Name: "Short.io", Suffixes: []string{"short.io"}, Claimable: true, Check: HTTP, Body: "Link does not exist", Claim: "add the hostname as a domain of a Short.io account"},
	{Name: "Pingdom", Suffixes: []string{"stats.pingdom.com"}, Claimable: true, Check: HTTP, Body: "Sorry, couldn't find the status page", Claim: "create a Pingdom public status page with the hostname as custom domain"},
	{Name: "Campaign Monitor", Suffixes: []string{"createsend.com"}, Claimable: true, Check: HTTP, Body: "Trying to access your account?", Claim: "add the hostname as custom domain of a Campaign Monitor account"},
	{Name: "JetBrains YouTrack", Suffixes: []string{"myjetbrains.com"}, Claimable: true, Check: HTTP, Body: "is not a registered InCloud YouTrack", Claim: "create the YouTrack InCloud instance {label}"},
	{Name: "Webflow", Suffixes: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, Claimable: true, Check: HTTP, Body: "The page you are looking for doesn't exist or has been moved.", Claim: "edge case: add the hostname as custom domain of a Webflow site"},
	{Name: "Kinsta", Suffixes: []string{"kinsta.cloud"}, Claimable: true, Check: HTTP, Body: "No Site For Domain", Claim: "edge case: add the hostname as a domain of a Kinsta site"},
	{Name: "Unbounce", Suffixes: []string{"unbouncepages.com"}, Claimable: true, Check: HTTP, Body: "The requested URL was not found on this server.", Claim: "edge case: add the hostname as custom domain of an Unbounce page"},

	// Not claimable: the list marks them not vulnerable, or the target names cannot be chosen. A CNAME to
	// them is labelled and grouped; one that ends in NXDOMAIN is still a stale record.
	{Name: "Amazon CloudFront", Suffixes: []string{"cloudfront.net"}},
	{Name: "AWS ELB", Suffixes: []string{"elb.amazonaws.com"}},
	{Name: "AWS Global Accelerator", Suffixes: []string{"awsglobalaccelerator.com"}},
	{Name: "AWS", Suffixes: []string{"amazonaws.com"}},
	{Name: "Azure Front Door", Suffixes: []string{"azurefd.net"}},
	{Name: "Azure", Suffixes: []string{"windows.net", "azure.com"}},
	{Name: "GitLab Pages", Suffixes: []string{"gitlab.io"}},
	{Name: "Heroku Private Spaces", Suffixes: []string{"herokuspace.com"}},
	{Name: "Vercel", Suffixes: []string{"vercel-dns.com", "vercel.app"}},
	{Name: "Cloudflare", Suffixes: []string{"cdn.cloudflare.net", "pacloudflare.com", "pages.dev"}},
	{Name: "Akamai", Suffixes: []string{"akamaiedge.net", "edgekey.net", "edgesuite.net", "akamai.net"}},
	{Name: "Google", Suffixes: []string{"googlehosted.com", "googleusercontent.com", "appspot.com"}},
	{Name: "Firebase", Suffixes: []string{"firebaseapp.com", "web.app"}},
	{Name: "Zendesk", Suffixes: []string{"zendesk.com"}},
	{Name: "Freshdesk", Suffixes: []string{"freshdesk.com"}},
	{Name: "HubSpot", Suffixes: []string{"hs-sites.com", "hubspot.net"}},
	{Name: "Marketo", Suffixes: []string{"mktoweb.com", "mktossl.com"}},
	{Name: "Salesforce", Suffixes: []string{"force.com", "salesforce.com"}},
	{Name: "SendGrid", Suffixes: []string{"sendgrid.net"}},
	{Name: "Mailgun", Suffixes: []string{"mailgun.org"}},
	{Name: "Squarespace", Suffixes: []string{"squarespace.com"}},
	{Name: "Wix", Suffixes: []string{"wixdns.net"}},
	{Name: "WP Engine", Suffixes: []string{"wpengine.com"}},
	{Name: "Atlassian", Suffixes: []string{"atlassian.net"}},
}

// Match returns the provider the CNAME chain points into and the chain name that matched, checking each
// name of the chain in order (the first is the one the domain owner configured). ok is false when no
// provider matches.
func Match(chain []string) (p Provider, target string, ok bool) {
	for _, c := range chain {
		c = strings.TrimSuffix(strings.ToLower(c), ".")
		if isS3(c) {
			return s3, c, true
		}
		for _, p := range Providers {
			for _, s := range p.Suffixes {
				if c == s || strings.HasSuffix(c, "."+s) {
					return p, c, true
				}
			}
		}
	}
	return Provider{}, "", false
}

// isS3 is true for an S3 endpoint: a name under amazonaws.com with a label that is s3 or starts with
// "s3-" or "s3." (s3-website-us-east-1, s3-us-west-2, s3.dualstack...).
func isS3(c string) bool {
	if !strings.HasSuffix(c, ".amazonaws.com") {
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(c, ".amazonaws.com"), ".") {
		if l == "s3" || strings.HasPrefix(l, "s3-") {
			return true
		}
	}
	return false
}

// ClaimHint is the provider's claim hint for a CNAME target.
func (p Provider) ClaimHint(target string) string {
	label := target
	if i := strings.IndexByte(target, '.'); i > 0 {
		label = target[:i]
	}
	return strings.ReplaceAll(p.Claim, "{label}", label)
}
