"""SecureVote web service logic (framework-independent).
handle(method, path, body, headers) -> (status, json_obj)
The server only ever receives: blinded tokens, encrypted ballots + proofs. Never a plaintext vote."""
import os, pickle, threading, hashlib, secrets
from crypto import *
from election import Election, check_ballot

LOCK = threading.RLock()
STATE_FILE = os.environ.get("SV_STATE", "state.pkl")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:                      # never fall back to a guessable default
    ADMIN_PASSWORD = secrets.token_urlsafe(12)
    print(f"ADMIN_PASSWORD not set - generated one for this run: {ADMIN_PASSWORD}", flush=True)
MAXBITS = 4200

S = {"phase": "setup", "el": None, "title": "", "codes": {}, "share_hashes": {}, "submitted": {}, "results": None}

def save():
    with open(STATE_FILE, "wb") as f: pickle.dump(S, f)
def load():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "rb") as f: S.update(pickle.load(f))
load()

class ApiError(Exception):
    def __init__(self, msg, status=400): self.msg, self.status = msg, status

def sx(o):
    """Big ints -> strings so JavaScript doesn't lose precision."""
    if isinstance(o, bool): return o
    if isinstance(o, int): return str(o)
    if isinstance(o, dict): return {k: sx(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)): return [sx(v) for v in o]
    return o

def toint(v, lo=0, hi=None, name="value"):
    try: x = int(v)
    except Exception: raise ApiError(f"{name} must be an integer string")
    if x.bit_length() > MAXBITS or x < lo or (hi is not None and x >= hi): raise ApiError(f"{name} out of range")
    return x

def need_admin(h):
    if not secrets.compare_digest(h.get("x-admin", ""), ADMIN_PASSWORD): raise ApiError("admin password required", 401)

def need_election():
    if S["el"] is None: raise ApiError("no election has been set up yet", 409)
    return S["el"]

# ---------------- public ----------------
def api_state():
    el = S["el"]
    out = {"phase": S["phase"], "title": S["title"]}
    if el:
        out.update(candidates=el.candidates, paillier_n=el.pub.n, rsa_n=el.ra.signer.n, rsa_e=el.ra.signer.e,
                   threshold=el.threshold, n_auth=len(S["share_hashes"]), eligible=len(el.ra.eligible),
                   tokens_issued=len(el.ra.issued), ballots=len(el.ledger.entries),
                   shares_submitted=len(S["submitted"]), results=S["results"], rejected=len(el.rejected))
    return sx(out)

def api_register(b):
    el = need_election()
    if S["phase"] != "open": raise ApiError("voting is not open", 409)
    vid, code = str(b.get("voter_id", "")), str(b.get("code", ""))
    if vid not in el.ra.eligible or not secrets.compare_digest(S["codes"].get(vid, ""), code):
        raise ApiError("unknown voter ID or wrong access code", 403)
    try: sig = el.ra.issue_token(vid, toint(b.get("blinded"), 1, el.ra.signer.n, "blinded"))
    except ValueError as e: raise ApiError(str(e), 409)
    save()
    return 200, sx({"blind_sig": sig})

def parse_ballot(b, el):
    k, n, n2, rn = len(el.candidates), el.pub.n, el.pub.n2, el.ra.signer.n
    try:
        cts = [toint(c, 1, n2, "ciphertext") for c in b["cts"]]
        bp = []
        for p in b["bit_proofs"]:
            bp.append({"a": [toint(x, 1, n2, "a") for x in p["a"]], "e": [toint(x, 0, CH, "e") for x in p["e"]],
                       "z": [toint(x, 1, n, "z") for x in p["z"]]})
        sp = {"a": toint(b["sum_proof"]["a"], 1, n2, "a"), "z": toint(b["sum_proof"]["z"], 1, n, "z")}
        out = {"nullifier": toint(b["nullifier"], 0, 1 << 256, "nullifier"), "sig": toint(b["sig"], 0, rn, "sig"),
               "cts": cts, "bit_proofs": bp, "sum_proof": sp}
    except (KeyError, TypeError, IndexError): raise ApiError("malformed ballot")
    if len(cts) != k or len(bp) != k or any(len(p["a"]) != 2 or len(p["e"]) != 2 or len(p["z"]) != 2 for p in bp):
        raise ApiError("malformed ballot")
    return out

def api_vote(b):
    el = need_election()
    if S["phase"] != "open": raise ApiError("voting is not open", 409)
    ballot = parse_ballot(b.get("ballot", {}), el)
    err = el.submit(ballot)
    if err:
        save(); raise ApiError("ballot rejected: " + err, 422)
    save()
    e = el.ledger.entries[-1]
    return 200, sx({"accepted": True, "index": len(el.ledger.entries) - 1, "hash": e["hash"]})

def api_ledger():
    el = need_election()
    return 200, sx({"valid_chain": el.ledger.verify_chain(), "entries": el.ledger.entries})

def api_audit():
    """Public audit: uses only public data - no secrets."""
    el = need_election(); pub, rn, re_ = el.pub, el.ra.signer.n, el.ra.signer.e
    ents = [e["record"] for e in el.ledger.entries]
    checks = []
    def add(name, ok, detail=""): checks.append({"name": name, "ok": bool(ok), "detail": detail})
    add("Ledger hash chain is unbroken", el.ledger.verify_chain(), f"{len(ents)} entries")
    add("Every ballot carries a valid eligibility signature", all(rsa_verify(H(r["nullifier"], mod=rn), r["sig"], rn, re_) for r in ents))
    add("No nullifier appears twice (no double voting)", len({r["nullifier"] for r in ents}) == len(ents))
    add("Every ciphertext is proven to encrypt 0 or 1",
        all(all(verify_bit(pub, c, p, H("ballot", r["nullifier"])) for c, p in zip(r["cts"], r["bit_proofs"])) for r in ents))
    add("Every ballot is proven to contain exactly one choice",
        all(verify_sum_is_one(pub, r["cts"], r["sum_proof"], H("ballot", r["nullifier"])) for r in ents))
    if S["results"]:
        ok1 = ok2 = True
        for i, t in enumerate(S["results"]):
            C = 1
            for r in ents: C = pub.add(C, r["cts"][i])
            ok1 &= (C == t["C"]); ok2 &= (pub.encrypt(t["votes"], t["r"])[0] == C)
        add("Published tally = product of all ballots on the ledger", ok1)
        add("Published totals decrypt that tally (checked with revealed randomness)", ok2)
        add("Total votes equals number of ballots", sum(t["votes"] for t in S["results"]) == len(ents))
    return 200, {"ok": all(c["ok"] for c in checks), "checks": checks}

# ---------------- admin / authorities ----------------
def api_setup(b, h):
    need_admin(h)
    if S["phase"] != "setup" and not b.get("reset"): raise ApiError("an election already exists (reset to replace it)", 409)
    cands = [str(c).strip() for c in b.get("candidates", []) if str(c).strip()]
    if not 2 <= len(cands) <= 10 or len(set(cands)) != len(cands): raise ApiError("need 2-10 distinct candidates")
    v = b.get("voters", 10)
    ids = [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) else [f"V{i+1:03d}" for i in range(int(v))]
    if not 1 <= len(ids) <= 1000 or len(set(ids)) != len(ids): raise ApiError("need 1-1000 distinct voters")
    na, th, bits = int(b.get("n_auth", 5)), int(b.get("threshold", 3)), int(b.get("bits", 1024))
    if not (2 <= th <= na <= 9) or bits not in (512, 768, 1024): raise ApiError("bad authority/threshold/key-size settings")
    el = Election(ids, cands, na, th, bits)
    shares = el.shares; el.shares = None          # the server forgets the key shares
    S.update(phase="open", el=el, title=str(b.get("title", "Election"))[:120] or "Election",
             codes={i: secrets.token_hex(2) + "-" + secrets.token_hex(2) for i in ids},
             share_hashes={x: hashlib.sha256(str(y).encode()).hexdigest() for x, y in shares},
             submitted={}, results=None)
    save()
    return 200, sx({"codes": S["codes"], "shares": [{"authority": x, "share": y} for x, y in shares]})

def api_codes(h): need_admin(h); need_election(); return 200, {"codes": S["codes"]}

def api_close(h):
    need_admin(h); need_election()
    if S["phase"] != "open": raise ApiError("voting is not open", 409)
    S["phase"] = "closed"; save(); return 200, {"phase": "closed"}

def api_share(b):
    need_election()
    if S["phase"] not in ("closed",): raise ApiError("shares are accepted after voting closes", 409)
    x, y = int(b.get("authority", 0)), toint(b.get("share"), 0, PRIME, "share")
    if S["share_hashes"].get(x) != hashlib.sha256(str(y).encode()).hexdigest(): raise ApiError("that is not authority %s's share" % x, 403)
    S["submitted"][x] = y; save()
    return 200, {"submitted": len(S["submitted"]), "threshold": S["el"].threshold}

def api_tally(h):
    need_admin(h); el = need_election()
    if S["phase"] != "closed": raise ApiError("close voting first", 409)
    try: res = el.tally(list(S["submitted"].items()))
    except ValueError: raise ApiError(f"need {el.threshold} authority shares, have {len(S['submitted'])}", 409)
    S["results"] = res; S["submitted"] = {}; S["phase"] = "tallied"; save()
    return 200, sx({"results": res})

def api_reset(h):
    need_admin(h); S.update(phase="setup", el=None, title="", codes={}, share_hashes={}, submitted={}, results=None)
    if os.path.exists(STATE_FILE): os.remove(STATE_FILE)
    return 200, {"phase": "setup"}

ROUTES_GET = {"/api/state": lambda b, h: (200, api_state()), "/api/ledger": lambda b, h: api_ledger(),
              "/api/audit": lambda b, h: api_audit(), "/api/admin/codes": lambda b, h: api_codes(h)}
ROUTES_POST = {"/api/register": lambda b, h: api_register(b), "/api/vote": lambda b, h: api_vote(b),
               "/api/admin/setup": lambda b, h: api_setup(b, h), "/api/admin/close": lambda b, h: api_close(h),
               "/api/admin/tally": lambda b, h: api_tally(h), "/api/admin/reset": lambda b, h: api_reset(h),
               "/api/authority/share": lambda b, h: api_share(b)}

def handle(method, path, body=None, headers=None):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    fn = (ROUTES_GET if method == "GET" else ROUTES_POST).get(path.rstrip("/"))
    if not fn: return 404, {"error": "not found"}
    try:
        with LOCK: return fn(body or {}, h)
    except ApiError as e: return e.status, {"error": e.msg}
    except (ValueError, TypeError) as e: return 400, {"error": "bad request: %s" % e}
