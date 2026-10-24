#!/usr/bin/env bash
# Reproducible token benchmark: dnsx output vs raijin-takeover output on the same names.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   re-resolve the names and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs dnsx and, for the public
#        scenarios, network
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, DNSX=<path>, DNS_PORT, HTTP_PORT (lab ports, default 19410 and 19411)
#
# Safety: DNS only for the public names. The names come from raijin-subs's benchmark (passive data on
# public bug bounty domains); dnsx asks public resolvers about them and nothing else is sent: no HTTP,
# no port probes, nothing claimed. The --http check runs only in the dangling scenario, against the
# local lab (bench/lab/lab.py on 127.0.0.1), whose zone and pages are synthetic.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
DNSX=${DNSX:-dnsx}
DNS_PORT=${DNS_PORT:-19410}
HTTP_PORT=${HTTP_PORT:-19411}
mkdir -p "$W"
echo "workdir: $W"

# Scenarios:
#   noisy:    hackerone.com names, most of them no longer resolve
#   providers: gitlab.com names, CNAMEs into GitLab Pages, CloudFront, Cloudflare, Zendesk and other
#             providers where names cannot be claimed
#   dangling: acme.example, a synthetic zone served by the local lab, with dangling CNAMEs and
#             unclaimed provider pages, checked with --http against the lab
scenarios=(noisy=hackerone.com providers=gitlab.com dangling=acme.example)

(cd "$ROOT" && go build -o "$W/raijin-takeover" ./cmd/raijin-takeover)

for s in "${scenarios[@]}"; do
  name=${s%%=*}; domain=${s#*=}
  printf '%s\n*.%s\n' "$domain" "$domain" > "$W/$name.scope"
done

if [ "${LIVE:-}" = 1 ]; then
  for name in noisy providers; do
    f=$HERE/fixtures/$name
    # raijin-takeover runs dnsx (-a -aaaa -resp -json -omit-raw) and saves its JSONL as raw: the fixture.
    "$W/raijin-takeover" --dnsx "$DNSX" --scope "$W/$name.scope" -l "$f/names.txt" --raw "$f/dnsx.jsonl" > "$W/$name.live.json"
    # dnsx as an agent would run it, in text, on the same names: the records, then the DNS status of
    # every name (the text output has no status and no line for names that do not resolve).
    "$DNSX" -l "$f/names.txt" -a -aaaa -cname -resp -silent -nc -duc < /dev/null > "$f/dnsx.txt"
    "$DNSX" -l "$f/names.txt" -rcode noerror,formerr,servfail,nxdomain,notimp,refused -silent -nc -duc < /dev/null > "$f/status.txt"
  done
  f=$HERE/fixtures/dangling
  mkdir -p "$f"
  python3 "$HERE/lab/gen_zone.py" "$HERE/lab"
  python3 "$HERE/lab/lab.py" "$HERE/lab/zone.json" "$DNS_PORT" "$HTTP_PORT" > "$W/lab.log" 2>&1 &
  LAB=$!
  trap 'kill $LAB 2>/dev/null || true' EXIT
  sleep 1
  "$W/raijin-takeover" --dnsx "$DNSX" --resolvers "127.0.0.1:$DNS_PORT" --scope "$W/dangling.scope" -l "$HERE/lab/names.txt" \
    --http --http-connect "127.0.0.1:$HTTP_PORT" --raw "$f/raw.jsonl" > "$W/dangling.live.json"
  "$DNSX" -r "127.0.0.1:$DNS_PORT" -l "$HERE/lab/names.txt" -a -aaaa -cname -resp -silent -nc -duc < /dev/null > "$f/dnsx.txt"
  "$DNSX" -r "127.0.0.1:$DNS_PORT" -l "$HERE/lab/names.txt" -rcode noerror,formerr,servfail,nxdomain,notimp,refused -silent -nc -duc < /dev/null > "$f/status.txt"
  kill $LAB 2>/dev/null || true
  trap - EXIT
fi

scenario() {
  local name=$1 domain=$2
  local f=$HERE/fixtures/$name o=$W/$name in names
  mkdir -p "$o"
  in=bench/fixtures/$name/dnsx.jsonl names=bench/fixtures/$name/names.txt
  [ -f "$ROOT/$in" ] || in=bench/fixtures/$name/raw.jsonl names=bench/lab/names.txt
  # Engine JSON: the dnsx lines only (the dangling fixture also holds the recorded HTTP checks).
  grep '"status_code"' "$ROOT/$in" > "$o/dnsx.jsonl" || true
  # raijin-takeover replays the fixture with --input, plus the names it was given: dnsx writes no line
  # for a name it could not resolve (a timeout), and the name is still a result.
  local args=(--scope "$W/$name.scope" --input "$in" --input "$names")
  (cd "$ROOT" && "$W/raijin-takeover" "${args[@]}") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-takeover" "${args[@]}" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-takeover" "${args[@]}" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  cat "$ROOT/$names" "$ROOT/$in" > "$o/engine_and_names.jsonl"
  python3 "$HERE/verify.py" "$o/engine_and_names.jsonl" "$o/raijin.json" "$domain"
  "$PY" "$HERE/count_tokens.py" \
    "dnsx -json -omit-raw=$o/dnsx.jsonl" \
    "dnsx text (records)=$f/dnsx.txt" \
    "dnsx text (records + status)=$f/dnsx.txt+$f/status.txt" \
    "raijin-takeover JSON (default)=$o/raijin.json" \
    "raijin-takeover --pretty=$o/raijin_pretty.json" \
    "raijin-takeover --format table=$o/raijin_table.txt"
}

for s in "${scenarios[@]}"; do scenario "${s%%=*}" "${s#*=}"; done
