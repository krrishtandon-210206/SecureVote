# SecureVote

### 🔗 Live demo: [https://securevote-gixi.onrender.com](https://securevote-gixi.onrender.com)

_Hosted on Render's free tier: if the site has been idle, the first load can take about a minute._

**An anonymous and publicly verifiable electronic voting system using homomorphic encryption and zero-knowledge proofs.**

SecureVote lets people vote online so that:

- **nobody can tell how you voted**, not even the administrator or the server,
- **only eligible voters vote, and only once**, and
- **anyone can check the result** is correct using public data alone.

> Research and educational prototype. Do not use it for a real, high-stakes election (see [Limitations](#limitations)).

**Team:** Krrish Tandon (240953666) · Sai Harshith Reddy (240953498) · Zaid Akhtar (240953580), CCE-C2

---

## Contents

1. [How it works](#how-it-works)
2. [Step-by-step demo tutorial](#step-by-step-demo-tutorial)
3. [Command-line demo and automated test](#command-line-demo-and-automated-test)
4. [How it maps to the synopsis](#how-it-maps-to-the-synopsis)
5. [Project files](#project-files)
6. [Deployment](#deployment)
7. [Limitations](#limitations)
8. [Troubleshooting](#troubleshooting)

---

## How it works

| Stage | Technique | What it achieves |
|---|---|---|
| Get a token | RSA blind signatures | The authority certifies you are eligible without seeing your token's serial number |
| Cast a ballot | Paillier encryption | One ciphertext per candidate (1 for your pick, 0 for the rest), encrypted in your browser |
| Prove validity | Zero-knowledge proofs (Fiat-Shamir) | Each ciphertext is 0 or 1, and the ballot holds exactly one vote, without revealing which |
| Stop double voting | Nullifier | Your serial is used once; reuse is rejected without revealing who you are |
| Record | Hash-chained ledger | Every ballot is appended and linked by hash, so edits are detectable |
| Count | Homomorphic addition | Ballots are multiplied while encrypted; only the totals are decrypted |
| Decrypt | Shamir secret sharing (threshold) | A minimum number of authorities must cooperate to decrypt |
| Verify | Public audit and in-browser check | Anyone re-checks every signature, proof, hash and the final tally |

The voter-side cryptography runs **in the browser**, so the server never sees a plaintext vote or a link between a voter and a ballot.

---

## Step-by-step demo tutorial

This walkthrough takes about five minutes. It runs a full election and tries to cheat along the way.

### Before you start

- The live site open: https://securevote-gixi.onrender.com
- The admin password (held by the project team, not published here).
- **Use two browser windows if you can** (for example one normal and one private window). The token is stored per browser, so a second window acts as a second voter.

### Step 1: Create the election (Administration tab)

1. Open the **Administration** tab and type your **admin password**.
2. Fill in the form:
   - **Title:** `Student Council Election`
   - **Candidates:** `Alice`, `Bob`, `Carol` (one per line)
   - **Number of voters:** `10`
   - **Authorities:** `5`
   - **Needed to decrypt:** `3`
   - **Key size:** `512 (fast)` for the demo, or `1024` for a more realistic run
3. Click **Create election**.

You will then see:

- **Voter access codes**, a table of voter IDs (`V001`, `V002`, ...) with one code each. These are the credentials you hand to voters.
- **Authority key shares**, 5 shares of the decryption key. **They are shown only once** and are not stored on the server. Keep this browser tab open; do not refresh before you finish the tally.

The header badge changes to **voting open**.

### Step 2: Get an anonymous token (Vote tab, step 1)

1. Open the **Vote** tab.
2. Enter a voter ID and its access code from the table, for example `V001` and its code.
3. Click **Get token**.

Watch the dark panel on the right (**What your browser just did**):

- A secret serial number is generated and never leaves your browser.
- It is blinded with a random factor, so the authority sees only noise.
- The authority signs it without seeing the serial, and your browser removes the blinding.

You now hold a valid signature on a serial the authority has never seen. This is what separates your identity from your ballot.

### Step 3: Cast your encrypted ballot (Vote tab, step 2)

1. Choose one candidate.
2. Click **Cast encrypted ballot** and wait a few seconds.

The panel shows your browser:

- encrypting one ciphertext per candidate,
- proving each ciphertext is 0 or 1,
- proving the ballot contains exactly one vote,
- sending everything with your serial as the nullifier (no name, no plaintext choice).

When it is accepted you get a **receipt** with your ledger position and entry hash.

### Step 4: Cast more votes

Repeat Steps 2 and 3 for several voters, using different voter IDs and access codes, and ideally pick different candidates. Use a private window or clear the site's local storage between voters, because one browser holds one token at a time.

A good spread for the demo is 3 votes for Alice, 2 for Bob and 1 for Carol.

### Step 5: Try to cheat

These attacks should all fail, which is the point of the demo.

| Attack | How to try it | Expected result |
|---|---|---|
| Vote twice | Reuse a token to cast a second ballot, for example with `node test_e2e.js` | Rejected: nullifier already used |
| Get a second token | Request another token with the same voter ID and code | Refused: one token per code |
| Use a wrong code | Enter a valid ID with an invalid code | Refused |
| Vote without a token | Send a ballot with a made-up serial or signature | Rejected: invalid signature |

The **ballots rejected** counter on the Results tab increases when ballots are refused.

### Step 6: Run the public audit (Ledger and audit tab)

1. Open **Ledger and audit**.
2. Look at the **Ballot ledger**. Each row shows the nullifier, the first ciphertext (unreadable) and the entry hash chained to the previous one.
3. Click **Run public audit**.

You should see green ticks for the signatures, proofs and hash chain, ending with **Election verified**. The audit uses only public data.

### Step 7: Close voting and decrypt (Administration tab)

1. Click **Close voting**. The badge changes to **voting closed**; no more ballots are accepted.
2. Submit key shares. In the **Authority key shares** section, click **Submit as authority 1**, then **2**.
   - After 2 shares, the message says 2 of 3 needed. **Two shares are not enough.** Try **Decrypt tally** now and it will refuse.
3. Submit authority **3** (any 3 of the 5 work).
4. Click **Decrypt tally**.

Only the **totals per candidate** are decrypted. No individual ballot ever is.

### Step 8: View and verify the results (Results tab)

1. Open **Results** to see the bar chart and vote counts.
2. Click **Verify the tally in my browser**.

Your browser re-encrypts each published total and checks that it equals the product of all ledger ballots. You should see: *Verified here in your browser*. This shows the result matches the ledger without trusting the server.

### Step 9: Start over (optional)

In **Administration**, click **Delete election** to remove the election, ledger and keys, then create a new one.

### What to point out when presenting

1. Step 2: the authority never sees the serial (blind signature).
2. Step 3: the server accepts a ballot it cannot read (encryption plus zero-knowledge proofs).
3. Step 5: cheating fails (nullifiers, one token per code).
4. Step 6: anyone can audit without any secret.
5. Step 7: two authorities cannot decrypt, but three can (threshold).
6. Step 8: the result is checked in your own browser.

---

## Command-line demo and automated test

**Command-line version** (no website, runs a full simulated election and attack tests):

```bash
python demo.py 12        # 12 voters; the default is 12
```

**Automated end-to-end test** (needs Node.js; it **resets the election** on the target server):

```bash
ADMIN_PASSWORD=<your password> node test_e2e.js http://localhost:8000
```

---

## How it maps to the synopsis

| Idea | Where |
|---|---|
| RSA blind signature (eligible but anonymous) | Token step: `web/voter.js` blinds, `crypto.py` signs |
| Nullifier (no double voting) | Serial revealed at casting, one use only |
| Paillier encryption and homomorphic tally | Ballot = 1 ciphertext per candidate; tally = product of ciphertexts |
| ZK proofs | Each ciphertext is 0-or-1 (OR-proof) and the ballot has exactly one choice; verified by the server and by the audit |
| Shamir threshold sharing | Key shares shown once at setup; the server keeps only hashes of them |
| Hash-chained ledger, public audit | Ledger tab; tally re-checked in the browser |

---

## Project files

| File | Purpose |
|---|---|
| `main.py` | FastAPI application (serves the API and the website) |
| `server.py` | Dependency-free alternative server |
| `service.py` | API logic and election state |
| `crypto.py`, `election.py` | Cryptography: Paillier, blind signatures, proofs, Shamir, ledger |
| `web/index.html`, `web/voter.js` | The website and browser-side cryptography |
| `demo.py` | Command-line demo |
| `test_e2e.js` | Automated end-to-end test |
| `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `setup.sh`, `deploy-vps.sh`, `render.yaml`, `securevote.service` | Deployment |
| `DEPLOY.md` | Full deployment guide |

---

## Deployment

See **[DEPLOY.md](DEPLOY.md)** for running on your own computer, on a VPS with Docker and automatic HTTPS, or on Render.

The browser's Web Crypto API only works over **HTTPS** (or on `localhost`), so any online deployment needs HTTPS.

---

## Limitations

- **Trusted dealer:** one party generates the key and shares at setup, and the key is reconstructed at tally time. Real systems use distributed key generation and threshold decryption.
- **Timing metadata:** the server sees when a token is issued and when ballots arrive. A delay or mixing would reduce this.
- **No coercion resistance or receipt-freeness:** a voter who is pressured or watched is not protected.
- **Not quantum-safe:** RSA and Paillier are broken by large quantum computers.
- **Demo-grade operations:** a single admin password, no rate limiting, and state stored in a pickle file.

Do not use SecureVote for a real election.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "admin password required" | Enter the password in the Administration tab. It is the `ADMIN_PASSWORD` you set, or the one printed at startup. |
| Crypto errors on a deployed site | Use HTTPS. Web Crypto does not work on plain HTTP except on `localhost`. |
| Shares are missing in Administration | They are shown only once, at creation, and kept in that browser tab. If lost, delete the election and create a new one. |
| Election looks different after a refresh | Make sure you started with `--workers 1`. |
| Token already issued / "Token ready" appears | The browser already holds a token. Use a private window or clear the site's local storage to act as a new voter. |
| Setup is slow | Choose the 512-bit key size for demos. |
| Live site is slow or blank at first | Render's free tier sleeps when idle. Wait about a minute and refresh. |
| Port already in use | Use another port: `uvicorn main:app --port 8001 --workers 1`. |
