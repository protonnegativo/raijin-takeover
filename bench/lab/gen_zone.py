"""Writes the synthetic zone of the dangling scenario: zone.json (for lab.py) and names.txt.

The zone is fake and deterministic: acme.example (the .example TLD is reserved for examples) with 271
names, plus one name outside the scope. Most are noise (names behind three load balancers, a CDN,
providers where names cannot be claimed, names that no longer exist). 18 names have a CNAME into a
provider or to a name that does not exist: some dangling (NXDOMAIN), some serving the provider's
"unclaimed" page, some in use.

usage: python3 gen_zone.py <outdir>
"""
import json
import os
import sys

out = sys.argv[1]
D = "acme.example"
rec, http, names = {}, {}, []


def add(name, **r):
    rec[name] = r


def name(n):
    names.append(n)
    return n


# noise: 120 names behind three load balancers
pools = [["203.0.113.10", "203.0.113.11"], ["203.0.113.20", "203.0.113.21"], ["203.0.113.30"]]
for i in range(120):
    add(name(f"web{i:03d}.{D}"), a=pools[i % 3])
# 40 names behind a CDN that is not in the provider table
add("acme.cdn.example.net", cname="edge.cdn.example.net")
add("edge.cdn.example.net", a=["198.51.100.20", "198.51.100.21"], aaaa=["2001:db8:20::1"])
for i in range(40):
    add(name(f"static{i:02d}.{D}"), cname="acme.cdn.example.net")
# providers where names cannot be claimed
add("d1a2b3c4.cloudfront.net", a=["198.51.100.30", "198.51.100.31"])
for i in range(10):
    add(name(f"img{i}.{D}"), cname="d1a2b3c4.cloudfront.net")
add("acme.zendesk.com", a=["198.51.100.40"])
for n in ("support", "help", "tickets"):
    add(name(f"{n}.{D}"), cname="acme.zendesk.com")
# names that no longer exist (NXDOMAIN) or exist with no record (NODATA)
for i in range(60):
    name(f"old{i:02d}.{D}")
for i in range(20):
    add(name(f"txt{i:02d}.{D}"), rcode=0)

# takeover-prone providers
dangling = {
    "legacy": "acme-legacy.azurewebsites.net",
    "api-eu": "acme-api-eu.cloudapp.net",
    "tm": "acme-tm.trafficmanager.net",
    "beanstalk": "acme-prod.us-east-1.elasticbeanstalk.com",
    "promo": "acme-promo-2019.example.org",
    "old-cdn": "d9z8y7x6.cloudfront.net",
}
for n, target in dangling.items():
    add(name(f"{n}.{D}"), cname=target)  # the target is not in the zone: NXDOMAIN

add("acme-docs.github.io", a=["185.199.108.153", "185.199.109.153"])
add("acme-blog.github.io", a=["185.199.108.153", "185.199.109.153"])
add("s3-w.us-east-1.amazonaws.com", a=["52.216.0.10"])
add("acme-assets.s3.amazonaws.com", cname="s3-w.us-east-1.amazonaws.com")
add("acme-media.s3.amazonaws.com", cname="s3-w.us-east-1.amazonaws.com")
add("acme-app.herokuapp.com", a=["54.0.0.10"])
add("shops.myshopify.com", a=["23.227.38.65"])
add("j.sni.global.fastly.net", a=["151.101.1.10", "151.101.65.10"])
add("acme-site.netlify.app", a=["75.2.60.5"])
add("acme-status.herokudns.com", rcode=0)
add("waws-prod-bn1.cloudapp.net", a=["20.0.0.5"])
add("acme-web.azurewebsites.net", cname="waws-prod-bn1.cloudapp.net")
add("acme.helpscoutdocs.com", a=["52.0.0.9"])
for n, target in {
    "docs": "acme-docs.github.io", "blog": "acme-blog.github.io",
    "assets": "acme-assets.s3.amazonaws.com", "media": "acme-media.s3.amazonaws.com",
    "app": "acme-app.herokuapp.com", "shop": "shops.myshopify.com", "store": "shops.myshopify.com",
    "edge": "j.sni.global.fastly.net", "site": "acme-site.netlify.app",
    "status": "acme-status.herokudns.com", "web": "acme-web.azurewebsites.net", "kb": "acme.helpscoutdocs.com",
}.items():
    add(name(f"{n}.{D}"), cname=target)

# what the provider shows for each name (the lab web server answers by Host header)
http = {
    f"docs.{D}": {"status": 404, "body": "<html><title>Site not found · GitHub Pages</title><h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p></html>"},
    f"assets.{D}": {"status": 404, "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>assets.acme.example</BucketName></Error>"},
    f"app.{D}": {"status": 404, "body": "<html><head><title>No such app</title></head><body>There's nothing here, yet.</body></html>"},
    f"store.{D}": {"status": 404, "body": "<html><body><h1>Sorry, this shop is currently unavailable.</h1></body></html>"},
    f"edge.{D}": {"status": 500, "body": "Fastly error: unknown domain: edge.acme.example. Please check that this domain has been added to a service."},
    f"site.{D}": {"status": 404, "body": "Not Found - Request ID: 01JABCDEF0123456789"},
}

# one name outside the scope: raijin-takeover drops it before dnsx runs
names.append("acme.partner.example.org")

os.makedirs(out, exist_ok=True)
json.dump({"records": rec, "http": http}, open(os.path.join(out, "zone.json"), "w"), indent=1, sort_keys=True)
open(os.path.join(out, "names.txt"), "w").write("\n".join(names) + "\n")
print(f"{len(names)} names, {len(rec)} records, {len(http)} pages")
