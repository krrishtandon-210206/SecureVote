# SecureVote - anonymous, publicly verifiable e-voting website

## Run it
    pip install -r requirements.txt
    ADMIN_PASSWORD=choose-one uvicorn main:app --port 8000 --workers 1     # open http://localhost:8000
Deploying online: see **DEPLOY.md**. (`python server.py` is a zero-dependency alternative for quick local tests.)

## 2-minute demo script
1. **Administration** tab -> enter the admin password -> *Create election* (use 512-bit keys for a snappy demo). Note the voter codes and the 5 authority key shares.
2. **Vote** tab -> enter a voter ID + code -> *Get token* -> pick a candidate -> *Cast encrypted ballot*. Watch the dark panel: it shows what the browser computed.
3. Try to cheat: vote again (rejected: nullifier reuse), request a second token (refused).
4. **Ledger and audit** tab -> *Run public audit*.
5. **Administration** -> *Close voting* -> submit 3 authority shares (2 are not enough) -> *Decrypt tally*.
6. **Results** tab -> *Verify the tally in my browser*.

## How it maps to the synopsis
| Idea | Where |
|---|---|
| RSA blind signature (eligible but anonymous) | token step: `web/voter.js` blinds, `crypto.py` signs |
| Nullifier (no double voting) | serial revealed at casting, one use only |
| Paillier encryption + homomorphic tally | ballot = 1 ciphertext per candidate; tally = product of ciphertexts |
| ZK proofs | each ciphertext is 0-or-1 (OR-proof) + ballot has exactly one choice; verified by server and by audit |
| Shamir 3-of-5 | key shares shown once at setup; server keeps only hashes of them |
| Hash-chained ledger, public audit | Ledger tab; tally re-checked in the browser |

Voter-side crypto runs in the browser, so the server never sees a plaintext vote or the voter-to-ballot link.

## Files
`main.py` (FastAPI app) · `server.py` (dependency-free alt. server) · `service.py` (API logic) · `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `setup.sh`, `deploy-vps.sh`, `render.yaml` (deployment) · `crypto.py`, `election.py` (cryptography) · `web/index.html`, `web/voter.js` (site) · `test_e2e.js` (automated test, `node test_e2e.js http://localhost:8000` against a running server, it resets the election) · `demo.py` (command-line version)

## Limitations (state these honestly)
- Trusted dealer creates the key and shares at setup; the key is reconstructed at tally time (real systems use distributed key generation and threshold decryption).
- Timing metadata: the server sees when a token was issued and when ballots arrive. Mitigate with a delay or mixing.
- No coercion resistance or receipt-freeness; not quantum-safe.
- Demo key sizes and a simple admin password; no HTTPS or rate limiting. Do not use for a real election.
