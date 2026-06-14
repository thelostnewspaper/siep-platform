# SIEP - Secure Industrial Edge Platform

A full-stack cybersecurity platform for managing and monitoring industrial edge devices. SIEP handles device identity management, cryptographic certificate issuance, adaptive trust scoring, distributed security mesh, intrusion detection, autonomous incident response, and NIS2 compliance tracking.

---

## Overview

SIEP is built as a demonstration of a Zero Trust architecture applied to industrial IoT environments. Every device that connects to the platform must hold a valid x509 certificate signed by the platform's own Root Certificate Authority. Telemetry from each device is continuously evaluated against a trust engine that detects anomalies such as DDoS flooding, certificate hijacking, rogue connections, malicious payload injection, and physical tampering.

When a violation is detected, an autonomous agent decides whether to quarantine or block the device and broadcasts that decision across all gateways in the distributed security mesh.

---

## Project Structure

```
siep-platform/
  backend/         Python FastAPI server
    main.py        API routes, WebSocket server, simulation loop
    ca.py          Mini Certificate Authority (RSA 2048, x509)
    trust_engine.py  Adaptive trust scoring logic
    mesh.py        Distributed gateway mesh and blocklist sync
    agent.py       Autonomous incident response agent
    simulator.py   Device telemetry simulator and attack injector
    db.py          SQLite database layer
    certs/         Generated Root CA and device certificates
  frontend/        React + Vite dashboard
    src/App.jsx    Main application component
    src/index.css  Design system and global styles
```

---

## Requirements

**Backend**

- Python 3.10 or higher
- pip

**Frontend**

- Node.js 18 or higher
- npm

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/thelostnewspaper/siep-platform.git
cd siep-platform
```

### 2. Start the backend

```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive API documentation is at `http://localhost:8000/docs`.

On first startup, the platform will:
- Generate a self-signed Root CA certificate (`certs/rootCA.pem`)
- Seed the database with four default industrial devices
- Issue x509 client certificates for each seeded device
- Start the device telemetry simulation loop

### 3. Start the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5174`.

---

## Platform Features

### Asset Directory

View all registered industrial devices in real time. Each device shows its gateway node, IP address, firmware version, live trust score, and current status (online, restricted, or blocked). Operators can manually block, isolate, or restore any device from this view.

### Security Mesh

A topology view of the three distributed gateway nodes (Alpha, Beta, Gamma). When one gateway detects a compromised device, the block is broadcast to all other gateways automatically. The panel shows the shared blocklist count and active peering state.

### Intrusion Detection System

A live event feed showing every telemetry packet processed by the platform, colour-coded by severity (INFO, MAJOR, CRITICAL). The autonomous response agent panel displays the step-by-step reasoning trace whenever a security violation triggers a containment action.

### PKI Management

Displays the Root CA subject and PEM certificate. Lists every device's certificate status (active or revoked). Operators can revoke a device certificate from this panel, which prevents the device from passing future cryptographic validation.

### NIS2 Compliance Registry

A self-assessment checklist mapped to Danish NIS2 critical infrastructure requirements. Each control item shows its current status (Compliant, In-Progress, or Non-Compliant) and allows operators to update the status and add audit notes. A compliance score bar shows the overall percentage of controls met.

---

## Attack Simulation

The platform includes a built-in threat simulation panel on the Asset Directory page. This is intended for testing and demonstration purposes only.

**Available attack vectors:**

| Vector | Description |
|---|---|
| DDoS Traffic Flooding | Sends 20 packets per tick to a single device, triggering the rate anomaly detector |
| Certificate Hijack | Forces a certificate validation failure, simulating a forged or stolen cert |
| Rogue Endpoint | Connects an unregistered device with no valid certificate |
| Malicious Payload Injection | Injects SQL-like strings into the telemetry payload |
| Physical Node Tampering | Sends sensor readings outside physically plausible ranges |

Each attack progressively lowers the target device's trust score. Once the score crosses configurable thresholds, the autonomous agent issues a quarantine or block command, which is then synchronized across all gateways.

---

## Configuration

Security thresholds are configurable at runtime via the Policy Rules panel in the dashboard header.

| Policy Key | Default | Description |
|---|---|---|
| `trust_quarantine_threshold` | 70 | Trust score below which a device is quarantined |
| `trust_block_threshold` | 45 | Trust score below which a device is fully blocked |
| `ddos_threshold_per_min` | 120 | Maximum packets per minute before flooding is flagged |

Policy changes take effect immediately without restarting the server.

---

## API Reference

The full API is documented via Swagger at `http://localhost:8000/docs`. Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/devices` | List all registered devices |
| POST | `/api/register` | Register a new device and issue its certificate |
| POST | `/api/attack` | Inject an attack simulation |
| POST | `/api/override` | Manually block, quarantine, or restore a device |
| POST | `/api/clear_attack` | Reset simulation state to normal |
| GET | `/api/ca/root` | Retrieve the Root CA PEM certificate |
| GET | `/api/nis2` | Get the NIS2 compliance checklist |
| POST | `/api/nis2/update` | Update a compliance item's status and notes |
| GET | `/api/policies` | Get current security policy thresholds |
| POST | `/api/policies/update` | Update a policy threshold |
| WS | `/ws/telemetry` | WebSocket stream for live device and log updates |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI (Python) |
| Database | SQLite via built-in `sqlite3` module |
| Cryptography | Python `cryptography` library (RSA 2048, x509) |
| Real-time updates | WebSockets |
| Frontend framework | React 19 with Vite |
| Styling | Vanilla CSS |

---

## Notes

- The Root CA private key is stored unencrypted on disk at `backend/certs/rootCA.key`. This is intentional for demonstration purposes. In a production deployment, the key must be stored in a hardware security module or encrypted key store.
- The certificate revocation list is held in memory and resets when the server restarts. A production system would persist this to the database.
- The CORS policy is set to allow all origins. Restrict this to your frontend origin before deploying publicly.
