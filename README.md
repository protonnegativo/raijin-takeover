# ⚡ Raijin Takeover

**dnsx plus a provider fingerprint table for AI agents: every name with its DNS answer, dangling CNAMEs ranked first with the provider and the claim hint.**

`raijin-takeover` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It resolves every name with [dnsx](https://github.com/projectdiscovery/dnsx), matches each CNAME chain against a native table of takeover-prone providers (after the public [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) list: GitHub Pages, S3, Heroku, Azure, Fastly, Shopify, Netlify, Zendesk and more, 72 services in all), and returns the **Raijin Schema**: one compact JSON where a CNAME that ends in NXDOMAIN on a claimable provider is a high finding with the way to claim it, a CNAME into a provider recognised by its "unclaimed" page is a medium finding with the text to look for, and every other name is still listed, in groups of names that share an answer.

## Why not just run dnsx?

dnsx is built for people and pipelines. An agent pays for every byte it reads. dnsx's JSON is one line per name, and every line repeats the resolvers, the TTL, the timestamp and the zone's SOA record. Its text output is short, but it has no DNS status and no line for a name that does not resolve, so a dangling CNAME looks like any other CNAME in it. Getting the status takes a second dnsx run, and the agent still has to know which provider each CNAME is on and whether names there can be claimed.

Here are the same names, with the same records, read by an agent (tokens, `o200k_base`):

```
Noisy: hackerone.com names, 510 names, 498 that do not resolve
  raijin-takeover █▏                      4,973 tokens
  dnsx text       ▍                       1,640 tokens
  text + status   █▋                      7,043 tokens
  dnsx JSON       ████████████████████   86,665 tokens

Providers: gitlab.com names, 830 names, 81 answers, none claimable
  raijin-takeover █▋                     16,220 tokens
  dnsx text       █▏                     10,415 tokens
  text + status   ██▍                    23,297 tokens
  dnsx JSON       ████████████████████  193,586 tokens

Dangling: synthetic lab zone, 271 names, 13 takeover candidates
  raijin-takeover ██▌                     3,357 tokens
  dnsx text       ██████▎                 8,565 tokens
  text + status   ████████▏              10,998 tokens
  dnsx JSON       ████████████████████   27,163 tokens
```

raijin-takeover reads **8× to 17×** fewer tokens than dnsx's JSON (`-json -omit-raw`). Each scenario's bars are drawn to scale against the JSON.

- **Nothing is lost.** Every name is in the output, and every A, AAAA and CNAME record, DNS status and HTTP check is on it. `bench/verify.py` checked 1,610 dnsx records (2,570 name/type/value triples), 10 HTTP checks and the 1,611 names in scope in the three scenarios and none were missing.
- **The takeover candidates come first**, each with its provider, the way to claim it and, when the provider is recognised by its page, the text that page shows for an unclaimed name. 498 names that do not resolve are one group that lists all 498.
- **DNS only by default.** `--http` fetches the page of the candidates that need it, and nothing else; it is off unless asked for.
- **Output is bounded.** On a huge run, `--max-bytes` cuts the least important data first (names that do not resolve) and counts every cut.
- **Details are one file away.** dnsx's full JSONL and the HTTP checks are saved to disk, and the path is in `raw`. It costs no tokens until the agent opens it, and replays with `--input`.

Against dnsx's text output the result depends on the run, and it is not always smaller. The text has no status line and leaves out every name that does not resolve, so on the noisy run it is **3.0×** smaller than raijin-takeover and on the providers run **1.6×** smaller; on the dangling run raijin-takeover is **2.6×** smaller. With the status run an agent needs to see which CNAMEs are dangling (`dnsx -rcode ...`), raijin-takeover is **1.4×** smaller on the public runs and **3.3×** on the dangling run. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-takeover/cmd/raijin-takeover@latest
```

You also need `dnsx` on `PATH`, or pass `--dnsx <path>`.

## Usage

```bash
raijin-takeover --scope scope.txt -d docs.example.com
raijin-takeover --scope scope.txt -l names.txt                 # one name per line, or subfinder JSONL
raijin-takeover --scope scope.txt -l names.txt --http          # also fetch the page of the HTTP candidates
raijin-takeover --scope scope.txt --input raw.jsonl            # replay a saved run, nothing is sent
raijin-takeover --scope scope.txt -l names.txt --state run.json  # mark findings that are new since last run
raijin-takeover ... -- -retry 3                                # anything after -- goes to dnsx
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

Names outside the scope are dropped before dnsx resolves them, and records and checks outside it are dropped from an input file. Both are counted in `omitted.out_of_scope`.

`--input` reads dnsx JSONL, the HTTP check lines raijin-takeover saves, name lists (one per line) and subfinder JSONL, or a file with all of them, like the `raw` file; a raijin-subs `raw` file works too. A replay never runs dnsx: names with no dnsx record are `NOANSWER` when the input has dnsx records, `UNCHECKED` when it has none. With `--http`, a replay fetches the pages of the candidates that have no saved check yet.

**DNS only by default.** dnsx asks the DNS resolvers, and nothing is sent to the names themselves. raijin-takeover never claims anything. `--http` sends one GET (two when plain HTTP fails or redirects) to each name whose CNAME points into a claimable provider that is recognised by its page, reads at most 1 MB of the body, and looks for the fingerprint. Those requests reach the provider's servers, so use `--http` only where the scope allows it. `--http-connect host:port` sends every check to one address, with the name in the `Host` header, for labs and tests.

## Output

```json
{
  "tool": "raijin-takeover",
  "version": "0.1.0",
  "target": "bench/fixtures/dangling/raw.jsonl, bench/lab/names.txt",
  "summary": "271 names, 185 resolve, 13 takeover candidates (10 high, 2 medium, 1 low), 13 groups",
  "findings": [
    {
      "id": "dangling-053e525c",
      "title": "Dangling CNAME to Azure App Service",
      "severity": "high",
      "tags": ["dangling"],
      "status": "NXDOMAIN",
      "cname": ["acme-legacy.azurewebsites.net"],
      "provider": "Azure App Service",
      "claim": "create an Azure App Service named acme-legacy",
      "locations": ["legacy.acme.example"]
    },
    {
      "id": "fingerprint-3e5c3d20",
      "title": "GitHub Pages fingerprint matched",
      "severity": "high",
      "tags": ["fingerprint"],
      "cname": ["acme-docs.github.io"],
      "a": ["185.199.108.153", "185.199.109.153"],
      "provider": "GitHub Pages",
      "http": "404 match",
      "claim": "create the GitHub user or org acme-docs if it is free, then a Pages repository with the hostname as custom domain",
      "locations": ["docs.acme.example"]
    },
    {
      "id": "dangling-1646d1a7",
      "title": "Dangling CNAME to acme-promo-2019.example.org",
      "severity": "medium",
      "tags": ["dangling"],
      "status": "NXDOMAIN",
      "cname": ["acme-promo-2019.example.org"],
      "claim": "the CNAME target acme-promo-2019.example.org does not exist: check whether its domain can be registered",
      "locations": ["promo.acme.example"]
    }
  ],
  "groups": [
    {
      "id": "in-use-80b266a7",
      "cname": ["acme-blog.github.io"],
      "a": ["185.199.108.153", "185.199.109.153"],
      "provider": "GitHub Pages",
      "http": "200 no match",
      "locations": ["blog.acme.example"]
    },
    {
      "id": "nxdomain-884496e7",
      "status": "NXDOMAIN",
      "locations": ["old00.acme.example", "old01.acme.example", "old02.acme.example", "... 57 more"]
    }
  ],
  "omitted": {"out_of_scope": 1}
}
```

That is the real dangling run from the benchmark (`--input` on the lab's saved dnsx output and HTTP checks), pretty-printed here. Three things are shortened: 10 of the 13 findings and 11 of the 13 groups are left out, and the `NXDOMAIN` group lists all 60 names in the real output (57 are replaced by `"... 57 more"` here). The tool writes it as one line.

The same run without `--http` (the default) lists `docs.acme.example` as `"CNAME to GitHub Pages: check the HTTP fingerprint"`, medium and `heuristic`, with `"fingerprint": "There isn't a GitHub Pages site here."` so the agent knows what to look for.

**Nothing dnsx found is dropped silently.** Every name is in exactly one finding or group per answer it has. Only exact repeats collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One entry per distinct answer.** Two names have the same answer when the DNS status, the CNAME chain, the A records, the AAAA records and the HTTP check are all equal (records sorted, so the order a resolver returns them in does not matter). Each entry lists every name that has it.
- **The answer** is written once per entry:
  - `status` is left out for NOERROR with records. Otherwise it is dnsx's status (`NXDOMAIN`, `SERVFAIL`, `REFUSED`...), `NODATA` (NOERROR with no A, AAAA or CNAME), `NOANSWER` (dnsx returned nothing for the name) or `UNCHECKED` (dnsx did not run).
  - `cname` is the chain in the order the resolver returned it.
  - `provider` is the service the chain points into, when it is in the table. The first name of the chain that matches decides, since it is the one the domain owner configured.
  - `http` is the `--http` check: `404 match`, `200 no match` or `error: <reason>`.
- **The provider table** (`internal/fingerprint`) says for each service whether names on it can be claimed by anyone, how a takeover shows (the CNAME target is NXDOMAIN, or the service answers for any name and its page says the name is unclaimed, with the text of that page), and how the name is claimed. Services the public list marks as edge cases say so in the claim hint. Services it marks as not vulnerable (Zendesk, GitLab Pages, CloudFront...), and CDNs and load balancers whose target names cannot be chosen (Cloudflare, Akamai, AWS ELB...), are in the table too, so a CNAME to them is labelled and grouped. It is a set of hints: a match is a takeover candidate, not a verified takeover.
- **Findings** are the answers that match a rule:

  | Tag | Severity | Rule |
  |---|---|---|
  | `dangling` | high on a claimable provider, medium on an unknown target, low on a provider where names cannot be claimed | The name has a CNAME and the chain ends in NXDOMAIN. On an unknown target, the target's domain may be free to register; on a provider that is not claimable it is a stale record, not a takeover. |
  | `fingerprint` | medium and `heuristic` without a check; high when the page has the fingerprint | The CNAME points into a claimable provider recognised by its page (GitHub Pages, S3, Heroku, Fastly, Shopify, Netlify...) and the name resolves. Only the page tells, so the finding carries `fingerprint`, the text to look for, until `--http` checks it. A page without the fingerprint makes it a group; a failed check keeps it medium. |
  | `no-address` | medium, `heuristic` | The CNAME points into a claimable provider and the chain resolves to no address (NODATA, SERVFAIL...): the resource may have been removed. |

  Every finding on a claimable provider has `claim`, the way to claim the name there, with the label of the CNAME target filled in. It is for the report: never claim a name without authorization.
- **Groups** are the answers that match no rule. Their `id` says why: `in-use` (a claimable provider, and the resource exists: the target resolves, or its page has no fingerprint), `not-claimable` (a provider where names cannot be claimed), `cname` (a target that is not in the table, and it resolves), `a` (no CNAME), or the status of names that do not resolve (`nxdomain`, `nodata`, `noanswer`, `unchecked`...).
- **Ranking:** findings by severity, then confidence (matched before heuristic), then the number of names, then `id`. Groups on a known provider come first, then other groups that resolve, then groups that do not, then by the number of names, then `id`. The same input always gives the same order.
- **`id`** is the tag (or the group reason) and a short hash of the answer, so the same answer has the same `id` in the next run.
- **`raw`** is dnsx's full JSONL plus one line per HTTP check, saved to one file. It holds the TTLs, resolvers, SOA records and timestamps, reading it costs no tokens until the agent opens it, and `--input` replays it. `--raw <file>` picks the path. A replay without `--http` writes no file.
- **Budget:** `--max-bytes` (64,000 by default, about 2,000 names, the same as raijin-subs: a takeover run lists every name it was given) keeps the output bounded on huge runs. It cuts in this order until the JSON fits:
  1. group names, starting with the groups that do not resolve;
  2. groups;
  3. the names of the lowest-ranked findings, each keeping one name plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If dnsx is missing, every name is still listed as `UNCHECKED`, with the hint in `errors`, and the exit code is 2.

**No `-cname` for dnsx, on purpose.** dnsx writes the CNAME chain from the A and AAAA answers already. With `-cname` it also sends a CNAME query, which a resolver answers NOERROR even when the chain ends at a name that does not exist, and dnsx v1.2.1 then reports NOERROR instead of the A query's NXDOMAIN: the one status that makes a CNAME dangling is lost. The benchmark lab shows it (`legacy.acme.example` is `NXDOMAIN` with `-a`, `NOERROR` with `-a -cname`). A CNAME into a claimable provider with no address and NOERROR is still a `no-address` finding, so input collected with `-cname` does not hide those names.

Fields an agent can rebuild are left out to save tokens:

- `status` is left out for NOERROR with records; `cname`, `a`, `aaaa`, `provider` and `http` when there are none.
- `claim` appears only on claimable providers and unknown targets; `fingerprint` only on a `fingerprint` finding that was not checked.
- `count` appears only when the budget cut `locations`.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The JSON is compact (one line) by default because indentation costs 24% to 42% more tokens in the benchmark; `--pretty` indents it (the example above is pretty-printed, with short arrays kept on one line). `--format table` prints a short human view of the same result; it lists finding names but only counts group names.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-d` / `-l` / `--input` | | one name (repeatable) / name file (or subfinder JSONL) / existing dnsx output, HTTP checks and name lists (repeatable) |
| `--http` | false | fetch the page of each candidate recognised by its HTTP body |
| `--http-connect` | | send every HTTP check to this host:port, with the name in `Host` (labs) |
| `--http-timeout` | 10 | seconds per HTTP check |
| `--rate`, `--threads`, `--resolvers` | | dnsx `-rl` / `-t` / `-r` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 64000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save dnsx's full JSONL and the HTTP checks |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--dnsx` | dnsx | path to the binary |
| `--banner` | false | print the banner to stderr |

## Development

```bash
go test ./...
go vet ./...
```

Standard library only. dnsx runs as a subprocess with `-a -aaaa -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused`, so the binary stays small and dnsx can be updated on its own. `-rcode` with every status makes dnsx write a line for the names that do not resolve too. The CLI tests run the live path offline with a small fake dnsx and a page server on 127.0.0.1 (ports 19400-19449); `testdata/sample.jsonl` is a synthetic run that hits every rule. `bench/lab/lab.py` is a local DNS resolver and provider page server for the synthetic zone of the benchmark.

## Responsible use

Only check names you are authorized to test, and never claim a name you do not own without written permission. raijin-takeover is DNS only by default; `--http` sends requests to third-party providers, so the scope still applies.
