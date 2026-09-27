# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

Upload an IPsec capture → get what's inside, whether it's safe, and what traffic it carries.
No message content is ever read. Sizes, timing, labels and handshake metadata only.

## Quick start

```bash
# backend
cd ~/ipsec-analyzer/backend
~/ipsec-analyzer/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
# dashboard (second terminal)
cd ~/ipsec-analyzer/dashboard
npm run dev -- --host 127.0.0.1 --port 5173
```

Open http://127.0.0.1:5173 → Files tab → Dashboard → pick a sample → Analyze.

## What each part does

| Part | Path | Job |
|---|---|---|
| Testbed | Docker `vpn-net`, strongSwan IKEv2 | Real encrypted traffic |
| Parser | `backend/app.py::analyze` | PCAP → JSON (counts, flows, SPIs, sizes, gaps, loss) |
| Security | `backend/app.py::assess` | Deterministic rules → HIGH/MEDIUM/LOW + evidence |
| AI | `ml/train.py` + `rf_v1.joblib` | Traffic shape classifier (ping/web/bulk/voip/video/handshake) |
| Narrative | `GET /summary` | Plain-words analyst report from file numbers |
| Dashboard | `dashboard/src` | 5 tabs: Dashboard, History, Files, Reports, Learn |
| Store | `captures.db` (SQLite) | Uploads survive restarts |

## Honesty rule (say it in demos)

Seen = in the file. Known = testbed settings. Guessed = AI hint.
Cipher, DH group and PFS live in device settings, never guessed from ESP bytes.
Risk comes from each file: old IKEv1 on wire = HIGH, IKEv2 + data = LOW,
data without handshake = MEDIUM.

## API

- `POST /api/captures/upload` → observed + security
- `GET /api/captures/{id}` `/security` `/flows` `/packets?limit=` `/classify` `/summary`
- `GET /api/samples` + `/api/samples/{name}` → download test files
- `GET /health`
