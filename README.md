# NessusDashboard

A self-hosted vulnerability management dashboard for **Nessus Professional** data.

NessusDashboard ingests Nessus scan results, correlates findings with **CISA Known Exploited Vulnerabilities (KEV)**, and presents deduplicated, actionable views by asset, severity, and plugin.

Built with:
- **FastAPI** (backend API)
- **PostgreSQL** (data store)
- **React + Vite** (frontend)
- **Docker Compose** (deployment)

---

## Features

- Ingest Nessus Professional scans via API
- Normalize and deduplicate findings
- Severity filtering (Critical / High / Medium / Low / Info)
- Per-asset vulnerability views
- Instance counting (same plugin across multiple ports/hosts)
- CISA KEV enrichment
- CSV export support
- Local-only binding by default (safe by design)

---

## Prerequisites

You must have:

- **Docker** and **Docker Compose**
- **Nessus Professional** (API access required)
- A Nessus user with permission to:
  - View scans
  - Export scan results

> ⚠️ Nessus Essentials is **not supported** (API limitations).

---

## Quick Start (5 minutes)

### 1. Clone the repository

```bash
git clone https://github.com/RobLoTech/NessusDashboard.git
cd NessusDashboard
````

---

### 2. Create your environment file

```bash
cp .env.example .env
```

Edit `.env` and update **only** the following values:

* `NESSUS_URL`
* `NESSUS_ACCESS_KEY`
* `NESSUS_SECRET_KEY`
* `DATABASE_URL` (password must match docker-compose)

---

### 3. Create your Docker Compose file

```bash
cp docker-compose.example.yml docker-compose.yml
```

Edit **only one value** in `docker-compose.yml`:

* `POSTGRES_PASSWORD` (must match `.env`)

---

### 4. Start the stack

```bash
docker-compose up -d --build
```

Verify health:

```bash
curl http://localhost:8000/healthz
```

Expected response:

```json
{"status":"ok"}
```

---

## Ingesting Nessus Data

### List available scans

```bash
docker exec -it nessusdashboard_app_1 python /app/nessus_cli.py scans
```

### Ingest a scan by ID

```bash
docker exec -it nessusdashboard_app_1 python /app/nessus_cli.py ingest --scan-id <SCAN_ID>
```

Scans are normalized and deduplicated automatically.

---

## Accessing the UI

Open your browser:

```
http://localhost:8000
```

By default:

* API and UI bind to **127.0.0.1 only**
* No authentication is exposed publicly

---

## Security Notes

* Secrets are **never committed**
* `.env` and `docker-compose.yml` are git-ignored
* Database is isolated inside Docker
* Ports bind to localhost by default
* Safe to run on internal servers

If exposing externally:

* Use a reverse proxy
* Add authentication
* Restrict network access

---

## Common Issues

### Database connection errors

* Ensure `DATABASE_URL` password matches `POSTGRES_PASSWORD`
* Ensure database container is healthy

### Nessus API errors

* Verify API keys
* Confirm Nessus URL includes `https://` and correct port
* Check Nessus user permissions

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Disclaimer

This project is **not affiliated with Tenable**.
Use at your own risk in accordance with your organization's security policies.
