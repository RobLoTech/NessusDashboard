# NessusDashboard

NessusDashboard is a self-hosted vulnerability management dashboard designed to ingest, normalize, and analyze Tenable Nessus scan data.

It provides multiple operational views to support remediation prioritization, including:
- Patch snapshot (Patch Tuesday–oriented visibility)
- KEV-focused CVE tracking
- Deduplicated findings with severity controls
- Remediation-centric rollups

## Architecture
- **Backend:** FastAPI + SQLAlchemy + PostgreSQL
- **Frontend:** React + TypeScript (Vite)
- **Ingestion:** Nessus exports and API-driven workflows
- **Deployment:** Docker / Docker Compose (excluded from repo by design)

## Status
This project is under active development and is intended as a reference implementation for vulnerability management workflows, automation, and data modeling.

## Security Notes
- Environment-specific files (`.env`, `docker-compose.yml`, scan exports) are intentionally excluded.
- No credentials, tokens, or internal infrastructure details are stored in this repository.

## License
To be added.
