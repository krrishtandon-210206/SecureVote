"""SecureVote election roles: Registration Authority, Voter, Ledger, Tally."""
import json, time
from crypto import *

class RegistrationAuthority:
    """Checks eligibility and blind-signs tokens. Never sees the final token."""
    def __init__(self, voter_ids, bits=1024):
        self.signer, self.eligible, self.issued = RSASigner(bits), set(voter_ids), set()
    def issue_token(self, voter_id, blinded):
        if voter_id not in self.eligible: raise ValueError("not eligible")
        if voter_id in self.issued: raise ValueError("token already issued")
        self.issued.add(voter_id)
        return self.signer.sign_blinded(blinded)

class Ledger:
    """Public append-only hash chain: tampering with any entry breaks all later hashes."""
    def __init__(self): self.entries = []
    def append(self, record):
        prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
        body = json.dumps(record, sort_keys=True)
        self.entries.append({"record": record, "prev": prev, "hash": str(H(prev, body))})
    def verify_chain(self):
        prev = "GENESIS"
        for e in self.entries:
            if e["prev"] != prev or e["hash"] != str(H(prev, json.dumps(e["record"], sort_keys=True))):
                return False
            prev = e["hash"]
        return True

class Voter:
    def __init__(self, voter_id): self.id, self.serial, self.sig = voter_id, None, None
    def get_token(self, ra):
        """Anonymous eligibility: serial is secret; RA signs it blindly."""
        self.serial = secrets.randbits(128)
        n, e = ra.signer.n, ra.signer.e
        blinded, r = blind(H(self.serial, mod=n), n, e)
        self.sig = unblind(ra.issue_token(self.id, blinded), r, n)
    def cast(self, pub, n_candidates, choice):
        cs, rs, proofs = [], [], []
        ctx = H("ballot", self.serial)                  # binds proofs to this ballot
        for i in range(n_candidates):
            c, r = pub.encrypt(1 if i == choice else 0)
            cs.append(c); rs.append(r)
        for i in range(n_candidates):
            proofs.append(prove_bit(pub, cs[i], 1 if i == choice else 0, rs[i], ctx))
        return {"nullifier": self.serial, "sig": self.sig, "cts": cs,
                "bit_proofs": proofs, "sum_proof": prove_sum_is_one(pub, cs, rs, ctx)}

def check_ballot(b, pub, ra_n, ra_e, seen):
    """Every check is public: anyone can re-run it during audit."""
    if b["nullifier"] in seen: return "duplicate nullifier"
    if not rsa_verify(H(b["nullifier"], mod=ra_n), b["sig"], ra_n, ra_e): return "bad eligibility signature"
    ctx = H("ballot", b["nullifier"])
    if not all(verify_bit(pub, c, p, ctx) for c, p in zip(b["cts"], b["bit_proofs"])): return "invalid 0/1 proof"
    if not verify_sum_is_one(pub, b["cts"], b["sum_proof"], ctx): return "not exactly one choice"
    return None

class Election:
    def __init__(self, voter_ids, candidates, n_auth=5, threshold=3, bits=1024):
        self.candidates, self.ra, self.ledger, self.seen = candidates, RegistrationAuthority(voter_ids, bits), Ledger(), set()
        self.pub, lam = paillier_keygen(bits)
        self.shares = shamir_split(lam, threshold, n_auth)      # one share per authority
        self.threshold, self.rejected = threshold, []
    def submit(self, ballot):
        err = check_ballot(ballot, self.pub, self.ra.signer.n, self.ra.signer.e, self.seen)
        if err: self.rejected.append(err); return err
        self.seen.add(ballot["nullifier"]); self.ledger.append(ballot)
        return None
    def tally(self, authority_shares):
        if len(authority_shares) < self.threshold: raise ValueError("not enough authorities")
        lam = shamir_combine(authority_shares)
        totals = []
        for i in range(len(self.candidates)):
            C = 1
            for e in self.ledger.entries: C = self.pub.add(C, e["record"]["cts"][i])   # homomorphic add
            m = paillier_decrypt(self.pub, lam, C)
            # publish randomness so anyone can check C == Enc(m, r)  (verifiable decryption)
            r = pow(C * pow(self.pub.g, -m, self.pub.n2) % self.pub.n2, pow(self.pub.n, -1, lam), self.pub.n2) % self.pub.n
            totals.append({"candidate": self.candidates[i], "votes": m, "C": C, "r": r})
        return totals

def public_audit(election, totals):
    """Run with NO secrets: re-verify chain, every ballot, uniqueness, and the tally."""
    pub, seen = election.pub, set()
    if not election.ledger.verify_chain(): return "ledger tampered"
    for e in election.ledger.entries:
        err = check_ballot(e["record"], pub, election.ra.signer.n, election.ra.signer.e, seen)
        if err: return "audit failed: " + err
        seen.add(e["record"]["nullifier"])
    for i, t in enumerate(totals):
        C = 1
        for e in election.ledger.entries: C = pub.add(C, e["record"]["cts"][i])
        if C != t["C"] or pub.encrypt(t["votes"], t["r"])[0] != C: return "tally mismatch"
    return "OK"
