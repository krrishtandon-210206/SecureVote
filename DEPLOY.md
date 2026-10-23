# Deploying SecureVote (FastAPI)

The app is `main:app` (FastAPI + uvicorn). The browser's Web Crypto API only works over **HTTPS** (or on `localhost`),
so every online option below sets up HTTPS for you. No placeholders to edit: the scripts ask for your domain and generate the admin password.

Run **one worker only** (election state lives in the process). All options below already do this.

---
## A. Try it on your own computer (2 minutes)
    unzip securevote.zip && cd securevote
    python3 -m venv venv && source venv/bin/activate          # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    export ADMIN_PASSWORD="$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')"; echo $ADMIN_PASSWORD
    uvicorn main:app --port 8000 --workers 1
Open http://localhost:8000. (Windows PowerShell: `$env:ADMIN_PASSWORD="choose-a-password"` instead of export.)
If you forget to set ADMIN_PASSWORD, a random one is generated and printed in the terminal at startup.

---
## B. Cloud server with Docker (recommended)
You need: a VPS (Ubuntu, any provider, 1 GB RAM is enough), a domain name, and ports 80 and 443 open.

1. **DNS:** create an `A` record for your domain (e.g. the name you want voters to visit) pointing to the server's public IP. Wait a few minutes.
2. **Install Docker** on the server:
       curl -fsSL https://get.docker.com | sh
3. **Upload and unzip:**
       scp securevote.zip root@YOUR_SERVER_IP:~      # run on your computer
       ssh root@YOUR_SERVER_IP
       apt-get install -y unzip && unzip securevote.zip && cd securevote
4. **Configure:** `./setup.sh` - it asks for your domain, creates `.env`, and prints the generated admin password. **Write it down.**
5. **Start:** `docker compose up -d --build`
6. **Open** `https://<your domain>`. Caddy obtains the HTTPS certificate automatically on first visit (takes ~30 seconds).

Logs: `docker compose logs -f` - Stop: `docker compose down` (election data is kept in the `sv-data` volume).
Update after changing code: `docker compose up -d --build`.

To test the whole thing on your own machine first: run `./setup.sh`, press Enter at the domain prompt (uses `localhost`), then `docker compose up -d --build` and visit https://localhost (accept the local certificate warning).

---
## C. Cloud server without Docker
Ubuntu/Debian server, domain already pointing at it (step 1 above), then:
    scp securevote.zip root@YOUR_SERVER_IP:~ ; ssh root@YOUR_SERVER_IP
    apt-get install -y unzip && unzip securevote.zip && cd securevote
    sudo ./deploy-vps.sh
It asks for the domain, installs Python + Caddy, creates a systemd service, and prints the site URL and a generated admin password.
Check: `systemctl status securevote` - Logs: `journalctl -u securevote -f`.

---
## D. Render.com (no server to manage)
1. Put the `securevote` folder in a GitHub repository.
2. Render dashboard -> New -> Blueprint -> pick the repo. It reads `render.yaml`, builds the Dockerfile, generates `ADMIN_PASSWORD`, and attaches a 1 GB disk.
3. After deploy, open the service -> Environment to read `ADMIN_PASSWORD`. Your site is the `https://<name>.onrender.com` URL shown.
(Persistent disks need a paid Render plan. Without one, election data is lost on restart.)

---
## Configuration (environment variables)
| Variable | Meaning |
|---|---|
| `ADMIN_PASSWORD` | Protects setup / close / tally. Generated for you by the scripts. |
| `SV_STATE` | File where election state is saved (set automatically in Docker/systemd). |
| `DOMAIN` | Used only by Caddy (set by `setup.sh` / `deploy-vps.sh`). |

## Running an election
1. Open the site -> Administration -> enter admin password -> create the election (use 1024-bit keys for a real vote).
2. **Copy the authority shares immediately** (shown once, never stored on the server) and give one to each authority.
3. Give each voter their ID and access code. 4. After voting: *Close voting*. 5. Authorities submit shares (3 of 5 by default). 6. *Decrypt tally*.
7. Optionally back up the state file (`docker compose cp app:/data/state.pkl .` or `/var/lib/securevote/state.pkl`).

## Verify a deployment
    ADMIN_PASSWORD=<your password> node test_e2e.js https://<your domain>     # WARNING: resets the election

## Security notes
Demo-grade: dealer-generated key, single admin password, no rate limiting, pickle state file. Suitable for classroom/club elections;
not for binding public elections. Keep it behind HTTPS.
