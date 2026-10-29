# Token benchmark: dnsx vs raijin-takeover

How many tokens does an AI agent spend reading the result of a subdomain takeover check, and does it lose anything? This benchmark resolves three sets of names with dnsx, counts the tokens in each output shape, and checks that every name, record and HTTP check is in the raijin-takeover output.

Reproduce from the saved output: `bench/run.sh`. Re-resolve and refresh the fixtures first: `LIVE=1 bench/run.sh` (needs dnsx, and network for the public names; the records will differ from the numbers below, since DNS changes).

## Setup

- **Names:**
  - **noisy** and **providers**: the 510 hackerone.com names and the 830 gitlab.com names of the raijin-subs benchmark, which subfinder found in public passive sources (certificate logs, DNS datasets) on 2026-10-24. hackerone.com and gitlab.com run public bug bounty programs and are common public examples.
  - **dangling**: a synthetic zone, `acme.example` (the `.example` TLD is reserved for examples), with 271 names plus one outside the scope. `bench/lab/gen_zone.py` writes it, and `bench/lab/lab.py` serves it on 127.0.0.1: a fake DNS resolver that answers A and AAAA queries with the CNAME chain and NXDOMAIN when the chain ends at a name that does not exist, and a fake provider page server that answers by `Host` header. The zone has 6 dangling CNAMEs (4 on claimable Azure and AWS services, one to an unknown domain, one to CloudFront), 6 names whose provider page says they are unclaimed (GitHub Pages, S3, Heroku, Shopify, Fastly, Netlify), names on the same providers that are in use, and noise: 120 names behind three load balancers, 40 behind a CDN, 13 on CloudFront and Zendesk, 60 NXDOMAIN and 20 NODATA names. The provider names in it are only strings: nothing is sent to them.
- **DNS only for the public names.** dnsx asked its default public resolvers about them, on 2026-10-24. Nothing was sent to the names themselves: no HTTP, no port probes, nothing claimed. `--http` ran only in the dangling scenario, against the lab, with `--http-connect`.
- **dnsx:** v1.2.1. raijin-takeover runs it with `-a -aaaa -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused` (no `-cname`; see the README: `-cname` turns the NXDOMAIN of a dangling chain into NOERROR, which the lab shows).
- **Fixtures:** `bench/fixtures/<scenario>/dnsx.jsonl` (public) or `raw.jsonl` (dangling, with the 10 HTTP checks) is the `raw` file of the live raijin-takeover run. `dnsx.txt` is dnsx's text output (`-a -aaaa -cname -resp -silent`) on the same names, and `status.txt` dnsx's status output (`-rcode noerror,formerr,servfail,nxdomain,notimp,refused -silent`), both run right after. Every row below is computed from these files, so `bench/run.sh` gives the same numbers offline.
- **raijin-takeover:** replays the fixture plus the name list with `--input`, so every row sees the same names and records. The name list matters: dnsx wrote no line for 1 gitlab.com name (`runners-cache-5.gitlab.com`, a timeout), and raijin-takeover lists it as `NOANSWER`. Defaults apply: no limit on findings, and `--max-bytes 64000`, which was not reached.
- **Baselines**, as an agent would read dnsx:
  - JSON: the dnsx lines of the fixture (`-json -omit-raw`). This is the leanest JSON dnsx writes; without `-omit-raw` each line also carries the raw DNS message.
  - Text (records): `dnsx.txt`, one line per record. It has no DNS status and no line for names that do not resolve, so a dangling CNAME looks like any other CNAME in it.
  - Text (records + status): `dnsx.txt` then `status.txt`, one line per name with its status. That is the least an agent needs to see from text which CNAMEs end in NXDOMAIN. dnsx's status output also skipped a few names (505 of 510, 820 of 830).
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy (hackerone.com names)

510 names. 498 no longer exist: hackerone.com's DNS answers NOERROR with no record (`NODATA`) for them. 12 resolve. raijin-takeover returned 2 findings, both medium and heuristic: three `mta-sts` names CNAME to `hacker0x01.github.io`, a GitHub Pages site whose page was not fetched (the benchmark never sends HTTP to third-party hosts), split in two because one name returned only AAAA records. 8 groups: SendGrid, Freshdesk and CloudFront CNAMEs (not claimable), three groups of names that share A and AAAA records, and the 498 `NODATA` names.

| Output | Bytes | Tokens | vs. dnsx JSON |
|---|---:|---:|---:|
| dnsx `-json -omit-raw` | 244,798 | 86,665 | 1× |
| dnsx text (records) | 3,552 | 1,640 | 53× |
| dnsx text (records + status) | 19,260 | 7,043 | 12× |
| **raijin-takeover JSON (default)** | 14,516 | **4,996** | **17×** |
| raijin-takeover `--pretty` | 20,351 | 6,379 | 14× |
| raijin-takeover `--format table` | 1,251 | 454 | 191× |

## Scenario 2: providers (gitlab.com names)

830 names. 130 resolve, 602 are NXDOMAIN (mostly old review apps under `design-staging.gitlab.com`), 97 are NODATA, 1 had no answer. raijin-takeover returned 0 findings and 81 groups. Many names CNAME into providers: GitLab Pages, CloudFront, Cloudflare, Zendesk, Marketo, AWS, Heroku Private Spaces, and targets that are not in the table. None is a provider where names can be claimed, and no CNAME ends in NXDOMAIN, so none is a takeover candidate; every one is listed in a `not-claimable` or `cname` group with its provider.

| Output | Bytes | Tokens | vs. dnsx JSON |
|---|---:|---:|---:|
| dnsx `-json -omit-raw` | 568,776 | 193,586 | 1× |
| dnsx text (records) | 23,343 | 10,415 | 19× |
| dnsx text (records + status) | 64,148 | 23,297 | 8.3× |
| **raijin-takeover JSON (default)** | 46,685 | **16,243** | **12×** |
| raijin-takeover `--pretty` | 62,032 | 20,108 | 9.6× |
| raijin-takeover `--format table` | 5,211 | 2,425 | 80× |

## Scenario 3: dangling (synthetic lab zone)

271 names in scope, 185 resolve. The one name outside the scope was dropped before dnsx ran and is counted in `omitted.out_of_scope`. `--http` fetched the page of the 10 names on providers recognised by their page; the checks are saved in the fixture and replayed. raijin-takeover returned 13 findings:

- 10 high: 4 dangling CNAMEs on claimable services (Azure App Service, Azure Cloud Service, Azure Traffic Manager, AWS Elastic Beanstalk), and 6 names whose page had the provider's fingerprint (GitHub Pages, S3, Heroku, Shopify, Fastly, Netlify);
- 2 medium: a dangling CNAME to an unknown domain, and a CNAME to Heroku with no address (heuristic);
- 1 low: a dangling CNAME to CloudFront, where names cannot be claimed.

The 4 names on the same providers whose page had no fingerprint, and the Azure name whose target resolves, are `in-use` groups. 13 groups in all.

| Output | Bytes | Tokens | vs. dnsx JSON |
|---|---:|---:|---:|
| dnsx `-json -omit-raw` | 67,268 | 27,163 | 1× |
| dnsx text (records) | 20,912 | 8,565 | 3.2× |
| dnsx text (records + status) | 29,101 | 10,998 | 2.5× |
| **raijin-takeover JSON (default)** | 11,888 | **3,380** | **8.0×** |
| raijin-takeover `--pretty` | 17,188 | 4,798 | 5.7× |
| raijin-takeover `--format table` | 4,099 | 1,172 | 23× |

The raijin-takeover output holds more than the dnsx rows: the 10 HTTP checks, the provider of every CNAME and a claim hint per finding. In every scenario its JSON includes about 20 tokens for `target`, the paths of the replayed files. A live run writes the names there and adds about 19 tokens for `raw`.

## Nothing is lost

For each scenario, `bench/verify.py` checks the fixture plus the name list against the raijin-takeover output. A result is:

- each (name, record type, value) triple dnsx returned, for A, AAAA and CNAME, plus the name's DNS status: the name must be in the `locations` of a finding or group whose `status`, `cname`, `a` and `aaaa` equal the record's;
- each HTTP check: the name must be in an entry whose `http` is the check's outcome (`404 match`, `200 no match`, `error: ...`);
- each name given: it must be listed, as `NOANSWER` when dnsx wrote no line for it.

Results:

- Scenario 1: 510 dnsx records (571 triples), 510 names, **0 missing**.
- Scenario 2: 829 dnsx records (1,257 triples), 830 names, **0 missing**.
- Scenario 3: 271 dnsx records (742 triples), 10 HTTP checks, 271 names in scope, **0 missing**; 1 name out of scope.

The check also fails when it should: removing one name from a group, or the status from a finding, makes it report them as missing.

What the JSON leaves out stays in `raw`, which raijin-takeover saves to disk: TTLs, resolvers, SOA records, timestamps and the URL of each HTTP check.

## Reading the numbers

- **Against dnsx's JSON**, the structured output an agent would parse, raijin-takeover uses **8× to 17× fewer tokens** for the same names and records. Most of the JSON is dnsx repeating its resolvers, TTL, timestamp and the zone's SOA record on every line.
- **Against dnsx's text output**, raijin-takeover is not always smaller:
  - records only: **3.0× larger** on the noisy run (1,640 → 4,996) and **1.6× larger** on the providers run (10,415 → 16,243); **2.5× smaller** on the dangling run (8,565 → 3,380). The text has one line per record and nothing for names that do not resolve: on the public runs it leaves out 498 and 700 names that raijin-takeover lists, and it cannot show a dangling CNAME at all, since it has no status.
  - records plus the status run: **1.4× smaller** on the noisy run (7,043 → 4,996) and on the providers run (23,297 → 16,243), **3.3× smaller** on the dangling run (10,998 → 3,380).

  When most names are different and do not resolve, the cost is the names themselves, and raijin-takeover lists every one. It writes each IP once per group instead of once per name and record type, which is where the dangling run saves the most. In exchange the agent gets the status of every name, the provider of every CNAME, whether names there can be claimed, the claim hint, the fingerprint to look for, and the candidates ranked first.
- **The output stays bounded.** On a run too big for `--max-bytes`, raijin-takeover cuts the least important data first: names that do not resolve, then other group names, then groups, then extra names of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. dnsx's output has no upper bound.

## How the default output got here

On the first runs of the same fixtures:

- dnsx was first run with `-cname`, like raijin-subs. On the lab, dnsx with `-a -aaaa -cname` reported NOERROR for all 6 dangling names of the zone; with `-a -aaaa` it reports NXDOMAIN and still writes the chain in `cname`. The flag was removed before the fixtures were made.
- The public fixtures were first replayed without the name list, and the gitlab.com name dnsx wrote no line for was missing from the output (and from the check, since it only read dnsx's lines). The replay and the check now read the name list too.
- `herokuspace.com` (Heroku Private Spaces) was added to the table as not claimable, so its gitlab.com CNAME is labelled.
