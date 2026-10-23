"""Run: python demo.py [num_voters]   (default 12)"""
import sys, random, time, copy
from election import *

N = int(sys.argv[1]) if len(sys.argv) > 1 else 12
cands = ["Alice", "Bob", "Carol"]
ids = [f"voter{i}" for i in range(N + 1)]   # +1 spare voter used for the attack test
t0 = time.time(); el = Election(ids, cands, n_auth=5, threshold=3); print(f"[setup] keys generated in {time.time()-t0:.1f}s")

voters, truth = [Voter(i) for i in ids[:N]], [0] * len(cands)
t0 = time.time()
for v in voters: v.get_token(el.ra)
print(f"[register] {N} blind-signed tokens in {time.time()-t0:.2f}s")

t0 = time.time(); first = None
for v in voters:
    ch = random.randrange(len(cands)); truth[ch] += 1
    b = v.cast(el.pub, len(cands), ch); first = first or b
    assert el.submit(b) is None
print(f"[vote] {N} ballots cast+verified in {time.time()-t0:.2f}s")

print("\n--- attacks ---")
print("double vote       ->", el.submit(copy.deepcopy(first)))
cheat = voters[0].cast(el.pub, len(cands), 0); cheat["nullifier"] += 1
print("forged token      ->", el.submit(cheat))
sneaky = Voter(ids[N]); sneaky.get_token(el.ra)      # eligible, fresh, not yet voted
bad = sneaky.cast(el.pub, len(cands), 0)
bad["cts"][0] = el.pub.encrypt(100)[0]                  # try to add 100 votes
print("ballot with 100 votes ->", el.submit(bad))
try: el.ra.issue_token("voter0", 1)
except ValueError as e: print("second token request ->", e)

print("\n--- tally ---")
try: el.tally(el.shares[:2])
except ValueError as e: print("2 of 5 authorities ->", e)
totals = el.tally(el.shares[:3]); print("3 of 5 authorities ->", {t["candidate"]: t["votes"] for t in totals})
print("expected           ->", dict(zip(cands, truth)))
assert [t["votes"] for t in totals] == truth
print("\n--- public audit (no secrets) ---\n", public_audit(el, totals))
el.ledger.entries[0]["record"]["nullifier"] += 1
print("after tampering ledger ->", public_audit(el, totals))
