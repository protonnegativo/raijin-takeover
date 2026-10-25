"""Checks a raijin-takeover result against a known answer: each "name STATUS" line of the expected file
must be in the locations of a finding with that status.

verify.py checks that nothing dnsx wrote is lost, so it cannot see what dnsx itself did not write.
This one compares with the lab zone, which does not depend on the engine.

usage: python known_answer.py <raijin.json> <expected.txt>
"""
import json, sys

o = json.load(open(sys.argv[1]))
want = []
for line in open(sys.argv[2]):
    line = line.strip()
    if line and not line.startswith("#"):
        name, status = line.split()
        want.append((name.lower(), status.upper()))

got = {(loc.lower(), f.get("status", "")) for f in o["findings"] for loc in f.get("locations", [])}
miss = [w for w in want if w not in got]
print(f"known answer: {len(want) - len(miss)} of {len(want)} expected findings present")
for m in miss:
    print("  MISSING known answer", m[0], m[1])
sys.exit(1 if miss else 0)
