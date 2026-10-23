// End-to-end test: Node plays the browser (voter.js) against the running server.
// Usage: python server.py 8765 &   node test_e2e.js http://localhost:8765
const SV = require("./web/voter.js");
const BASE = process.argv[2] || "http://localhost:8000", ADMIN = { "x-admin": process.env.ADMIN_PASSWORD };
const post = async (p, b, h = {}) => { const r = await fetch(BASE + p, { method: "POST", headers: { "content-type": "application/json", ...h }, body: JSON.stringify(b || {}) }); return [r.status, await r.json()]; };
const get = async (p, h = {}) => { const r = await fetch(BASE + p, { headers: h }); return [r.status, await r.json()]; };
let fails = 0; const ok = (c, m) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) fails++; };

(async () => {
  await post("/api/admin/reset", {}, ADMIN);
  let [s, setup] = await post("/api/admin/setup", { title: "Test", candidates: ["Alice", "Bob", "Carol"], voters: 6, n_auth: 5, threshold: 3, bits: 512 }, ADMIN);
  ok(s === 200, "admin setup");
  const st = (await get("/api/state"))[1], n = BigInt(st.paillier_n), rn = BigInt(st.rsa_n), re = BigInt(st.rsa_e);
  const ids = Object.keys(setup.codes), truth = [0, 0, 0], tokens = [];
  // register (ID + code -> blind signature), then vote anonymously
  for (const id of ids.slice(0, 5)) {
    const t = await SV.newToken(rn, re);
    const [c, r] = await post("/api/register", { voter_id: id, code: setup.codes[id], blinded: t.blinded.toString() });
    if (c !== 200) { ok(false, "register " + id + JSON.stringify(r)); continue; }
    tokens.push({ serial: t.serial, sig: SV.unblind(BigInt(r.blind_sig), t.r, rn) });
  }
  ok(tokens.length === 5, "5 blind-signed tokens issued");
  ok((await post("/api/register", { voter_id: ids[0], code: setup.codes[ids[0]], blinded: "5" }))[0] === 409, "second token for same voter refused");
  ok((await post("/api/register", { voter_id: ids[5], code: "0000-0000", blinded: "5" }))[0] === 403, "wrong access code refused");
  let first;
  for (let i = 0; i < tokens.length; i++) {
    const ch = i % 3; truth[ch]++;
    const b = await SV.makeBallot(n, 3, ch, tokens[i].serial, tokens[i].sig); first ||= b;
    const [c, r] = await post("/api/vote", { ballot: b });
    ok(c === 200, "ballot " + i + " accepted (browser proofs verified by Python server)");
  }
  ok((await post("/api/vote", { ballot: first }))[0] === 422, "double vote rejected (nullifier)");
  // rigged ballot: 100 votes for Alice using a fresh valid token
  const t = await SV.newToken(rn, re);
  const [c6, r6] = await post("/api/register", { voter_id: ids[5], code: setup.codes[ids[5]], blinded: t.blinded.toString() });
  const sig6 = SV.unblind(BigInt(r6.blind_sig), t.r, rn);
  const bad = await SV.makeBallot(n, 3, 0, t.serial, sig6); bad.cts[0] = SV.encrypt(n, 100n, 7n).toString();
  const [cb, rb] = await post("/api/vote", { ballot: bad }); ok(cb === 422, "ballot with 100 votes rejected: " + rb.error);
  const forged = await SV.makeBallot(n, 3, 1, 12345n, 999n); ok((await post("/api/vote", { ballot: forged }))[0] === 422, "forged token rejected");
  // close, authorities, tally
  ok((await post("/api/admin/close", {}, ADMIN))[0] === 200, "voting closed");
  ok((await post("/api/admin/tally", {}, ADMIN))[0] === 409, "tally refused with 0 shares");
  const sh = setup.shares;
  ok((await post("/api/authority/share", { authority: 1, share: sh[1].share }))[0] === 403, "wrong share refused");
  for (const k of [0, 2]) await post("/api/authority/share", { authority: sh[k].authority, share: sh[k].share });
  ok((await post("/api/admin/tally", {}, ADMIN))[0] === 409, "tally refused with 2 of 3 shares");
  await post("/api/authority/share", { authority: sh[4].authority, share: sh[4].share });
  const [ct, rt] = await post("/api/admin/tally", {}, ADMIN);
  const got = rt.results.map(x => Number(x.votes));
  ok(ct === 200 && JSON.stringify(got) === JSON.stringify(truth), `tally ${got} == expected ${truth}`);
  const [, led] = await get("/api/ledger");
  ok(SV.verifyTally(n, led.entries, rt.results).every(x => x.ok), "browser independently verifies tally");
  const [, au] = await get("/api/audit"); ok(au.ok, "server public audit OK (" + au.checks.length + " checks)");
  console.log(fails ? `\n${fails} FAILED` : "\nALL PASSED"); process.exit(fails ? 1 : 0);
})();
