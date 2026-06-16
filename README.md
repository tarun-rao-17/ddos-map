# DDoS Live Attack Map

A real-time DDoS attack monitoring system that combines a Cloudflare Worker sensor, AbuseIPDB reputation checks, a machine learning confidence scorer, and a live Leaflet.js map — built entirely on free tiers.

**Live demo:** https://ddos-map.pages.dev

## How it works

```
Real traffic / attacker
        │
        ▼
Cloudflare Worker (worker/src/index.js)
intercepts requests, extracts IP + geo data,
filters for suspicious patterns
        │
        ▼
FastAPI backend (backend/main.py)
runs ML confidence scoring + AbuseIPDB lookup,
stores event in SQLite, broadcasts over WebSocket
        │
        ▼
Live map (frontend/index.html)
plots the event as a coloured marker in real time
```

Red markers are flagged attacks. Amber markers are suspicious but unconfirmed. Green markers are clean traffic.

## Project structure

```
ddos-map/
├── worker/                  Cloudflare Worker — the sensor
│   ├── wrangler.toml         Worker config and environment variables
│   └── src/index.js          Intercepts requests, forwards suspicious ones
│
├── backend/                  FastAPI server — the brain
│   ├── main.py                API endpoints, ML scoring, AbuseIPDB calls
│   ├── database.py            SQLite setup and queries
│   ├── requirements.txt       Python dependencies
│   ├── build.sh                Render build script (installs deps + trains model)
│   └── ml/
│       ├── train.py            Trains the RandomForest model
│       └── data/
│           ├── generate_sample.py   Generates synthetic training data
│           └── sample_training.csv  Small benign + attack dataset (committed)
│
└── frontend/
    └── index.html            Live Leaflet.js map with WebSocket feed
```

## Tech stack

| Layer | Technology | Tier |
|---|---|---|
| Sensor | Cloudflare Workers | Free — 100k requests/day |
| Backend | FastAPI + Uvicorn | Free — Render free tier |
| ML model | scikit-learn RandomForestClassifier | Free — runs in-process |
| IP reputation | AbuseIPDB API | Free — 1,000 checks/day |
| Database | SQLite | Free — file-based, no persistent disk on free tier |
| Frontend | Leaflet.js + vanilla JS | Free — Cloudflare Pages |

## Setup from scratch

### 1. Prerequisites

- Node.js and npm (for Wrangler)
- Python 3.10+
- A Cloudflare account
- A Render account
- A free AbuseIPDB API key from abuseipdb.com

### 2. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/ddos-map.git
cd ddos-map

cd backend
pip install -r requirements.txt --break-system-packages

cd ../worker
npm install
```

### 3. Train the ML model locally (optional — Render trains it automatically on deploy)

```bash
cd backend/ml
python train.py
```

This reads CSVs from `backend/ml/data/` and saves `model.pkl`. The repo ships with a small synthetic dataset (`sample_training.csv`) so this works out of the box. For higher accuracy, download the CIC-DDoS2019 dataset and drop additional CSVs into `backend/ml/data/` before training — just don't commit large CSVs to git (see `.gitignore`).

### 4. Configure environment variables

Create `backend/.env`:

```
ABUSEIPDB_API_KEY=your_abuseipdb_key
WORKER_SECRET=pick_any_random_string
```

### 5. Run the backend locally

```bash
cd backend
python -m uvicorn main:app --reload --port 8000
```

Visit `http://127.0.0.1:8000/health` — should return `{"status": "ok", "model": true}`.

### 6. Deploy the backend to Render

1. Push your repo to GitHub
2. On Render: New + → Web Service → connect your repo
3. Root directory: `backend`
4. Build command: `chmod +x build.sh && ./build.sh`
5. Start command: `python -m uvicorn main:app --host 0.0.0.0 --port 8000`
6. Add environment variables: `ABUSEIPDB_API_KEY`, `WORKER_SECRET`
7. Deploy — copy the resulting URL (e.g. `https://your-app.onrender.com`)

### 7. Configure and deploy the Worker

Edit `worker/wrangler.toml`:

```toml
name = "ddos-sensor"
main = "src/index.js"
compatibility_date = "2024-06-01"

[vars]
FASTAPI_URL = "https://your-app.onrender.com/ingest"
WORKER_SECRET = "same_string_as_backend_env"
```

```bash
cd worker
npx wrangler login
npx wrangler deploy
```

### 8. Deploy the frontend to Cloudflare Pages

1. Cloudflare dashboard → Workers & Pages → Create → Pages → Connect to Git
2. Select your repo
3. Build output directory: `frontend`
4. Leave build command empty
5. Save and deploy

Update `BACKEND` and `WS_URL` constants at the top of `frontend/index.html` to point to your Render URL before deploying.

## Testing

Send a simulated attack event directly to the backend:

```bash
curl -X POST https://your-app.onrender.com/ingest \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2024-10-15T08:32:11Z","ip":"185.220.101.42","country":"DE","city":"Frankfurt","latitude":50.1155,"longitude":8.6842,"asn":24940,"asn_org":"Hetzner Online GmbH","url":"https://example.com/api/login","method":"POST","user_agent":"python-requests/2.31","requests_this_isolate":50}'
```

Watch the live map for a red marker over Frankfurt within a few seconds.

## Known limitations

- Render's free tier has no persistent disk — SQLite history resets whenever the server restarts after inactivity. Live events still work correctly; only historical data is lost on restart.
- The ML model ships trained on a small synthetic dataset for portability. Accuracy improves significantly with the full CIC-DDoS2019 dataset (not committed due to size).
- AbuseIPDB free tier allows 1,000 lookups/day; results are cached for 24 hours per IP to stay within quota.

