# PortScan — Real-Time IP Port Scanner

A full-stack port scanning tool with a live streaming UI. Built with React + Vite + Tailwind CSS on the frontend and Node.js + Express + Socket.io on the backend.

---

## Features

- **Real-time streaming** — port results stream live via WebSocket as they're discovered
- **5 scan presets** — Top 20, Top 100, Web, Database, Remote
- **Custom port ranges** — scan any range up to 10,000 ports
- **Service detection** — identifies 40+ known services (HTTP, SSH, MySQL, Redis, etc.)
- **Response time** — measures latency per port
- **CSV export** — download open port results
- **Live feed** — scrolling terminal-style output of all scanned ports
- **Cancel scan** — stop mid-scan at any time
- **Rate limiting** — 30 requests/minute per client
- **Input validation** — guards against bad port ranges and unresolvable hosts

---

## Project Structure

```
port-scanner/
├── server/
│   ├── index.js        # Express + Socket.io server
│   ├── scanner.js      # TCP connect scanner logic
│   └── package.json
├── client/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── hooks/
│   │   │   └── useScanner.js     # WebSocket state management
│   │   └── components/
│   │       ├── ScanForm.jsx      # Inputs + preset selector
│   │       ├── ProgressBar.jsx   # Animated progress
│   │       ├── OpenPortsPanel.jsx # Open ports list + export
│   │       └── LiveFeed.jsx      # Scrolling live terminal
│   └── package.json
└── README.md
```

---

## Local Setup

### 1. Start the backend server

```bash
cd server
npm install
npm run dev       # runs on http://localhost:4000
```

### 2. Start the React frontend

```bash
cd client
npm install
npm run dev       # runs on http://localhost:5173
```

Open your browser at **http://localhost:5173**

---

## Deployment

### Backend — Railway (recommended)

1. Push the `server/` folder to a GitHub repo
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Set environment variable: `CLIENT_URL=https://your-vercel-app.vercel.app`
4. Railway will auto-detect Node.js and deploy

### Frontend — Vercel

1. Push the `client/` folder to GitHub
2. Go to [vercel.com](https://vercel.com) → Import Project
3. Set environment variable: `VITE_SERVER_URL=https://your-railway-app.up.railway.app`
4. Deploy

---

## How It Works

The scanner uses **TCP connect scanning** — the most reliable method that doesn't require root/admin privileges:

1. For each port, Node.js attempts a TCP connection via `net.createConnection`
2. If the connection succeeds → port is **open**
3. If the server immediately refuses → port is **closed**
4. If the connection times out → port is **filtered** (firewall dropping packets)

Ports are scanned with a concurrency of 150, meaning 150 simultaneous connection attempts are in-flight at any time. This makes scanning 1,000 ports take ~2–5 seconds on a local network.

---

## Legal & Ethical Notice

Only scan IP addresses and hosts that you **own** or have **explicit written permission** to scan. Unauthorized port scanning may violate laws including the Computer Fraud and Abuse Act (CFAA) and equivalent legislation in other countries.

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS 3 |
| Backend | Node.js, Express 4 |
| Real-time | Socket.io 4 |
| Scanner | Node.js `net` module (TCP) |
| Deploy | Vercel (frontend) + Railway (backend) |
