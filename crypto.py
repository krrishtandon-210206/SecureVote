"""Core cryptography for SecureVote (pure Python, educational key sizes)."""
import hashlib, secrets
from math import gcd

# ---------- number theory ----------
def is_prime(n, k=30):
    if n < 4: return n in (2, 3)
    if n % 2 == 0: return False
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(k):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p): return p

def H(*parts, mod=None):
    """Hash any values to an integer (Fiat-Shamir challenges, token hashing)."""
    h = hashlib.sha256()
    for p in parts: h.update(str(p).encode() + b"|")
    v = int.from_bytes(h.digest(), "big")
    return v % mod if mod else v

# ---------- 1. RSA blind signatures (anonymous eligibility) ----------
class RSASigner:
    def __init__(self, bits=1024):
        while True:
            p, q = gen_prime(bits // 2), gen_prime(bits // 2)
            phi = (p - 1) * (q - 1)
            if p != q and gcd(65537, phi) == 1: break
        self.n, self.e, self._d = p * q, 65537, pow(65537, -1, phi)
    def sign_blinded(self, blinded):          # signer never sees the message
        return pow(blinded, self._d, self.n)

def blind(msg_hash, n, e):
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1: break
    return (msg_hash * pow(r, e, n)) % n, r   # (blinded msg, blinding factor)

def unblind(blind_sig, r, n):
    return (blind_sig * pow(r, -1, n)) % n

def rsa_verify(msg_hash, sig, n, e):
    return pow(sig, e, n) == msg_hash % n

# ---------- 2. Paillier (additively homomorphic) ----------
class PaillierPublic:
    def __init__(self, n):
        self.n, self.n2, self.g = n, n * n, n + 1
    def encrypt(self, m, r=None):
        if r is None:
            while True:
                r = secrets.randbelow(self.n - 1) + 1
                if gcd(r, self.n) == 1: break
        return (1 + m * self.n) * pow(r, self.n, self.n2) % self.n2, r
    def add(self, c1, c2):                    # Enc(a)*Enc(b) = Enc(a+b)
        return c1 * c2 % self.n2

def paillier_keygen(bits=1024):
    while True:
        p, q = gen_prime(bits // 2), gen_prime(bits // 2)
        if p != q and gcd(p * q, (p - 1) * (q - 1)) == 1: break
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    return PaillierPublic(p * q), lam

def paillier_decrypt(pub, lam, c):
    L = (pow(c, lam, pub.n2) - 1) // pub.n
    return L * pow(lam, -1, pub.n) % pub.n

# ---------- 3. Shamir secret sharing (threshold key) ----------
PRIME = 2**1279 - 1                           # Mersenne prime > any 1024-bit lambda

def shamir_split(secret, t, n):
    coeffs = [secret] + [secrets.randbelow(PRIME) for _ in range(t - 1)]
    return [(x, sum(c * pow(x, i, PRIME) for i, c in enumerate(coeffs)) % PRIME)
            for x in range(1, n + 1)]

def shamir_combine(shares):
    secret = 0
    for xi, yi in shares:
        num = den = 1
        for xj, _ in shares:
            if xj != xi: num = num * (-xj) % PRIME; den = den * (xi - xj) % PRIME
        secret = (secret + yi * num * pow(den, -1, PRIME)) % PRIME
    return secret

# ---------- 4. Zero-knowledge proofs (Sigma protocols + Fiat-Shamir) ----------
# Core statement: "u is an n-th residue", i.e. I know r with u = r^n mod n^2.
# Enc(m) = g^m r^n  =>  Enc(0) is an n-th residue, Enc(1)/g is an n-th residue.
CH = 1 << 128                                 # challenge space

def prove_bit(pub, c, bit, r, ctx):
    """OR-proof: c encrypts 0 OR c encrypts 1 (without saying which)."""
    n, n2 = pub.n, pub.n2
    ginv = (1 - n) % n2                       # g^-1 mod n^2
    u = [c, c * ginv % n2]                    # u[b] is an n-th residue iff bit == b
    fake = 1 - bit
    # simulate the false branch
    e_f = secrets.randbelow(CH); z_f = secrets.randbelow(n - 1) + 1
    a = [0, 0]
    a[fake] = pow(z_f, n, n2) * pow(u[fake], -e_f, n2) % n2
    # real commitment for the true branch
    x = secrets.randbelow(n - 1) + 1
    a[bit] = pow(x, n, n2)
    e = H(ctx, c, a[0], a[1]) % CH
    e_t = (e - e_f) % CH
    z_t = x * pow(r, e_t, n) % n
    es, zs = [0, 0], [0, 0]
    es[bit], zs[bit], es[fake], zs[fake] = e_t, z_t, e_f, z_f
    return {"a": a, "e": es, "z": zs}

def verify_bit(pub, c, proof, ctx):
    n, n2 = pub.n, pub.n2
    u = [c, c * ((1 - n) % n2) % n2]
    a, es, zs = proof["a"], proof["e"], proof["z"]
    if (es[0] + es[1]) % CH != H(ctx, c, a[0], a[1]) % CH: return False
    return all(pow(zs[b], n, n2) == a[b] * pow(u[b], es[b], n2) % n2 for b in (0, 1))

def prove_sum_is_one(pub, cs, rs, ctx):
    """Product of ciphertexts encrypts exactly 1 (one choice per ballot)."""
    n, n2 = pub.n, pub.n2
    R = 1
    for r in rs: R = R * r % n
    x = secrets.randbelow(n - 1) + 1
    a = pow(x, n, n2)
    U = _sum_residue(pub, cs)
    e = H(ctx, U, a) % CH
    return {"a": a, "z": x * pow(R, e, n) % n}

def _sum_residue(pub, cs):
    P = 1
    for c in cs: P = P * c % pub.n2
    return P * ((1 - pub.n) % pub.n2) % pub.n2

def verify_sum_is_one(pub, cs, proof, ctx):
    U = _sum_residue(pub, cs)
    e = H(ctx, U, proof["a"]) % CH
    return pow(proof["z"], pub.n, pub.n2) == proof["a"] * pow(U, e, pub.n2) % pub.n2
