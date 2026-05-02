# SIB MSME RM Tracker

Personal relationship manager tracker for MSME loan customers — South Indian Bank.

---

## Features

- **Portfolio Management** — Full customer details including account, limits, ROI, collateral, insurance
- **BPM Tracking** — Loan processing pipeline with status tracking
- **Dashboard** — Alerts for expiring limits (60 days) and insurance (30 days)
- **Target Tracking** — Disbursement and book growth targets with progress bars
- **Daily Book Entry** — Track outstanding book day by day
- **Reports** — Book Movement report shareable via WhatsApp

---

## Setup (One Time)

### 1. Install Python 3.10+
Download from https://www.python.org/downloads/

### 2. Install dependencies
Open terminal/command prompt in this folder:
```
pip install -r requirements.txt
```

### 3. Run the app
```
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Open in Chrome
```
http://localhost:8000
```

---

## Access from Internet (via Cloudflare Tunnel)

To access from outside your network without port forwarding:

```
# Install cloudflared (one time)
# Windows: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

# Run tunnel (while app is running)
cloudflared tunnel --url http://localhost:8000
```

You will get a public URL like: https://abc-xyz.trycloudflare.com

---

## Run on Windows Startup (optional)

Create a batch file `start_tracker.bat`:
```bat
@echo off
cd /d "C:\path\to\sib-tracker"
uvicorn main:app --host 0.0.0.0 --port 8000
```

Add this to Windows Startup folder (Win+R → shell:startup).

---

## Data

All data is stored in `sib_msme.db` (SQLite file in the same folder).
To backup: just copy `sib_msme.db` to a safe location.

---

## API Documentation

Auto-generated API docs available at: http://localhost:8000/docs
