"""Checks that every dnsx result (and every HTTP check) is in a raijin-takeover result.

The engine output is a JSONL file: dnsx lines, plus the HTTP check lines and name lists raijin-takeover
reads with --input (the `raw` file it saves has both kinds of lines). Results are:

- each (name, record type, value) triple from dnsx, for A, AAAA and CNAME, plus the name's DNS status:
  the name must be in the locations of a finding or group whose status, cname, a and aaaa equal the
  record's (NOERROR with no record is NODATA);
- each HTTP check: the name must be in an entry whose http is the check's outcome ("404 match",
  "200 no match", "error: <reason>");
- each name given without a dnsx record (a name list or subfinder line): it must be listed as NOANSWER
  (UNCHECKED when the file has no dnsx line at all).

raijin-subs wildcard probe names (raijin-wc-*) are not results and are skipped. With roots given, names
outside them count as out of scope, not missing.

usage: python verify.py <engine.jsonl> <raijin.json> [root,root...]
"""
import json, sys

raw, out = sys.argv[1], sys.argv[2]
roots = [r.strip().lower() for r in sys.argv[3].split(",")] if len(sys.argv) > 3 else []
o = json.load(open(out))


def norm(s):
    s = s.strip().lower().rstrip(".")
    return s[2:] if s.startswith("*.") else s


entries = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        answer = (x.get("status", ""), tuple(x.get("cname", [])), tuple(x.get("a", [])), tuple(x.get("aaaa", [])), x.get("http", ""))
        for loc in x.get("locations", []):
            entries.setdefault(loc, set()).add(answer)

names, records, checks = [], [], []
probes = 0
for line in open(raw, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if not line.startswith("{"):
        if "." in line and not any(c in line for c in ' \t[]{}"'):
            names.append(norm(line))
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if not isinstance(e, dict) or not e.get("host"):
        continue
    if norm(e["host"]).startswith("raijin-wc-"):
        probes += 1
    elif "status_code" in e:
        records.append(e)
    elif e.get("check") == "http":
        checks.append(e)
    elif "check" not in e:
        names.append(norm(e["host"]))


def in_roots(n):
    return not roots or any(n == r or n.endswith("." + r) for r in roots)


def chain(cn):
    out = []
    for c in cn or []:
        c = norm(c)
        if c and (not out or out[-1] != c):
            out.append(c)
    return tuple(out)


def outcome(c):
    if c.get("error"):
        return "error: " + c["error"]
    return f'{c.get("status", 0)} {"match" if c.get("match") else "no match"}'


miss, triples, oos = [], 0, 0
resolved = set()
for e in records:
    n = norm(e["host"])
    if not in_roots(n):
        oos += 1
        continue
    resolved.add(n)
    status = e["status_code"].upper()
    a, aaaa, cn = tuple(sorted(set(e.get("a") or []))), tuple(sorted(set(e.get("aaaa") or []))), chain(e.get("cname"))
    if status == "NOERROR":
        status = "" if (a or aaaa or cn) else "NODATA"
    want = (status, cn, a, aaaa)
    got = {g[:4] for g in entries.get(n, set())}
    ts = [("status", status or "NOERROR")] + [("a", v) for v in a] + [("aaaa", v) for v in aaaa] + [("cname", v) for v in cn]
    triples += len(ts)
    if want not in got:
        for t in ts:
            ok = any((t[0] == "status" and (s or "NOERROR") == t[1]) or (t[0] == "a" and t[1] in ga) or (t[0] == "aaaa" and t[1] in g6) or (t[0] == "cname" and t[1] in gc) for s, gc, ga, g6 in got)
            if not ok:
                miss.append((n,) + t)
        if not any(m[0] == n for m in miss):
            miss.append((n, "answer", want))

for c in checks:
    n = norm(c["host"])
    if not in_roots(n):
        oos += 1
        continue
    if not any(g[4] == outcome(c) for g in entries.get(n, set())):
        miss.append((n, "http", outcome(c)))

unresolved = "NOANSWER" if records else "UNCHECKED"
for n in set(names):
    if not in_roots(n):
        oos += 1
        continue
    if n not in entries:
        miss.append((n, "name"))
    elif n not in resolved and not any(g[0] == unresolved for g in entries[n]):
        miss.append((n, "status", unresolved))

print(f"{len(records)} dnsx records ({triples} name/type/value triples), {len(checks)} HTTP checks, "
      f"{len(set(names))} listed names, {len(miss)} missing from output",
      f"({probes} raijin-subs probes skipped, {oos} out of scope)",
      "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
sys.exit(1 if miss else 0)
