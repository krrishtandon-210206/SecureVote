/* SecureVote voter-side cryptography (BigInt). Mirrors crypto.py exactly.
   Runs in the browser: blinding, Paillier encryption and zero-knowledge proofs happen here,
   so the server never sees a plaintext vote or the link between a voter and a ballot. */
const SV = (() => {
  const CH = 1n << 128n;
  const te = new TextEncoder();

  async function H(...parts) {                       // SHA-256 of "p1|p2|..." -> BigInt (same as Python H)
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(parts.map(p => String(p) + "|").join(""))));
    let hex = "0x"; for (const b of d) hex += b.toString(16).padStart(2, "0");
    return BigInt(hex);
  }
  function modPow(b, e, m) {
    let r = 1n; b %= m;
    for (const bit of e.toString(2)) { r = r * r % m; if (bit === "1") r = r * b % m; }
    return r;
  }
  function modInv(a, m) {
    let [r0, r1] = [m, ((a % m) + m) % m], [t0, t1] = [0n, 1n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
    if (r0 !== 1n) throw new Error("not invertible");
    return ((t0 % m) + m) % m;
  }
  function randBits(bits) {
    const bytes = new Uint8Array(Math.ceil(bits / 8)); crypto.getRandomValues(bytes);
    let x = 0n; for (const b of bytes) x = (x << 8n) | BigInt(b);
    return x & ((1n << BigInt(bits)) - 1n);
  }
  const randBelow = n => randBits(n.toString(2).length + 64) % n;       // negligible bias
  const randUnit = n => randBelow(n - 1n) + 1n;

  // ---- 1. anonymous eligibility token (RSA blind signature) ----
  async function newToken(rsaN, rsaE) {
    const serial = randBits(128);                                       // secret serial = nullifier
    const msg = (await H(serial)) % rsaN;
    const r = randUnit(rsaN);
    return { serial, r, blinded: msg * modPow(r, rsaE, rsaN) % rsaN };  // only `blinded` is sent
  }
  const unblind = (blindSig, r, rsaN) => blindSig * modInv(r, rsaN) % rsaN;

  // ---- 2. Paillier ----
  function encrypt(n, m, r) {
    const n2 = n * n;
    return (1n + m * n) * modPow(r, n, n2) % n2;
  }

  // ---- 3. zero-knowledge proofs ----
  async function proveBit(n, c, bit, r, ctx) {
    const n2 = n * n, ginv = n2 - n + 1n, fake = 1 - bit;
    const u = [c, c * ginv % n2];
    const eF = randBelow(CH), zF = randUnit(n);
    const a = [0n, 0n];
    a[fake] = modPow(zF, n, n2) * modPow(modInv(u[fake], n2), eF, n2) % n2;   // simulated branch
    const x = randUnit(n); a[bit] = modPow(x, n, n2);                          // real branch
    const e = (await H(ctx, c, a[0], a[1])) % CH;
    const eT = ((e - eF) % CH + CH) % CH;
    const es = [0n, 0n], zs = [0n, 0n];
    es[bit] = eT; zs[bit] = x * modPow(r, eT, n) % n; es[fake] = eF; zs[fake] = zF;
    return { a, e: es, z: zs };
  }
  async function proveSumIsOne(n, cs, rs, ctx) {
    const n2 = n * n;
    let R = 1n, P = 1n;
    for (const r of rs) R = R * r % n;
    for (const c of cs) P = P * c % n2;
    const U = P * (n2 - n + 1n) % n2;
    const x = randUnit(n), a = modPow(x, n, n2);
    const e = (await H(ctx, U, a)) % CH;
    return { a, z: x * modPow(R, e, n) % n };
  }

  const S = v => Array.isArray(v) ? v.map(S) : (v && typeof v === "object") ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, S(x)])) : (typeof v === "bigint" ? v.toString() : v);

  /** Build an encrypted ballot. onStep(label) lets the UI show progress. */
  async function makeBallot(n, nCand, choice, serial, sig, onStep = () => {}) {
    const ctx = await H("ballot", serial);
    const cs = [], rs = [];
    for (let i = 0; i < nCand; i++) { const r = randUnit(n); rs.push(r); cs.push(encrypt(n, i === choice ? 1n : 0n, r)); }
    onStep("encrypted");
    const bp = [];
    for (let i = 0; i < nCand; i++) bp.push(await proveBit(n, cs[i], i === choice ? 1 : 0, rs[i], ctx));
    onStep("bit-proofs");
    const sp = await proveSumIsOne(n, cs, rs, ctx);
    onStep("sum-proof");
    return S({ nullifier: serial, sig, cts: cs, bit_proofs: bp, sum_proof: sp });
  }

  /** Independent in-browser check of a published tally: Enc(votes, r) must equal the product of ledger ciphertexts. */
  function verifyTally(n, ledgerEntries, results) {
    const n2 = n * n;
    return results.map((t, i) => {
      let C = 1n; for (const e of ledgerEntries) C = C * BigInt(e.record.cts[i]) % n2;
      const ok = C === BigInt(t.C) && encrypt(n, BigInt(t.votes), BigInt(t.r)) === C;
      return { candidate: t.candidate, ok };
    });
  }
  return { H, modPow, modInv, newToken, unblind, makeBallot, verifyTally, encrypt };
})();
if (typeof module !== "undefined") module.exports = SV;
