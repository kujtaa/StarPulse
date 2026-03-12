# Sentinel V3

Multi-tenant SaaS platform for Linux security monitoring. Companies register, add their servers, and monitor security events from a unified dashboard.

Zero external dependencies — built entirely with Python 3 stdlib.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 Sentinel Platform                      │
│  ┌──────────────────────────────────────────────────┐ │
│  │  Organization: Acme Corp                          │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │ │
│  │  │ Agent 1  │  │ Agent 2  │  │ Agent 3  │ ──────► │ │
│  │  │ web-01   │  │ db-01    │  │ api-01   │         │ │
│  │  └─────────┘  └─────────┘  └─────────┘          │ │
│  └──────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────┐ │
│  │  Organization: Startup Inc                        │ │
│  │  ┌─────────┐  ┌─────────┐                        │ │
│  │  │ Agent 1  │  │ Agent 2  │ ──────────────────►   │ │
│  │  │ prod-01  │  │ staging  │                       │ │
│  │  └─────────┘  └─────────┘                        │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  Central Server: REST API + Dashboard + SQLite         │
└──────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Deploy the Platform

```bash
# On your VPS (requires root)
git clone <repo-url> sentinel-v3
cd sentinel-v3
sudo bash setup.sh
sudo systemctl start sentinel-central
```

### 2. Register Your Organization

Open `http://YOUR_VPS:8765/register` in your browser and create your account.

### 3. Create an API Token

Go to **Settings** → **API Tokens** → Create a new token.

### 4. Install Agents

On each server you want to monitor:

```bash
curl -sSL http://YOUR_VPS:8765/install.sh | \
  SENTINEL_SERVER=http://YOUR_VPS:8765 SENTINEL_TOKEN=your-api-token bash
```

The server appears on your dashboard immediately.

### Docker (Alternative)

```bash
sudo bash setup.sh
docker-compose up -d
```

## Multi-Tenancy

Each organization gets:
- **Isolated data** — agents and alerts are scoped to the org
- **Own API tokens** — generate as many as needed for different environments
- **Team access** — multiple users per org (owner, admin, member roles)
- **Dedicated dashboard** — see only your servers and alerts

## Project Structure

```
sentinel-v3/
├── setup.sh                    ← Platform setup wizard
├── docker-compose.yml          ← Docker deployment
├── README.md
├── central/
│   ├── server.py               ← Central server (single file)
│   └── dashboard/
│       └── index.html          ← Dashboard UI (single file)
└── agent/
    ├── agent.py                ← Security agent (single file)
    └── install.sh              ← Universal installer
```

## Detection Modules

| Module | Category | What it detects |
|--------|----------|-----------------|
| **FIM** | `file_integrity` | Modified system binaries, suspicious files in /tmp |
| **CMD** | `crypto_mining` | Known miners, high CPU processes, mining pool connections, cron injection |
| **HAD** | `http_anomaly` | 404/403 floods, request spikes, scanner patterns |
| **NAD** | `network` | Suspicious port connections, new listeners, DNS tampering |

## Dashboard Pages

- **Overview** — Live stats, 24h sparkline, severity/category breakdown
- **Servers** — All monitored servers with online/offline status
- **All Alerts** — Filterable, paginated alert feed
- **Install Agent** — Token-aware install command with copy button
- **Settings** — API token management, organization info

## API Endpoints

### Public
| Method | Path | Description |
|--------|------|-------------|
| GET | `/register` | Registration page |
| POST | `/register` | Create organization + user |
| GET | `/login` | Login page |
| POST | `/login` | Authenticate user |
| POST | `/api/ingest` | Agent data push (token auth) |
| GET | `/api/status` | Health check |

### Authenticated (session cookie)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/me` | Current user + org info |
| GET | `/api/agents` | List org's agents |
| GET | `/api/alerts` | Paginated org alerts |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/tokens` | List API tokens |
| POST | `/api/tokens` | Create new token |
| DELETE | `/api/tokens/:id` | Delete a token |

## Coding Rules

- **No external dependencies** — stdlib only
- **Single-file constraint** — each component is one file
- **No build step** — dashboard is vanilla HTML/CSS/JS
- **Python 3.6+** compatible
