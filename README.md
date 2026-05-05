# HPE: Enterprise Network Threat Detection Pipeline
HPE is a production-grade, AI-powered cybersecurity threat detection pipeline. It simulates a modern Security Operations Center (SOC) backend and visualizes real-time network traffic interceptions via a stunning 3D WebGL interface, a Structural Spatial (Bento Box) dashboard, and a Security Admin Console with human-in-the-loop credential rotation.

## Overview
The system is designed to ingest raw network traffic, extract behavioral features, execute high-speed machine learning inference in a microservice backend, and trigger automated orchestrated responses (like HashiCorp Vault credential rotation) when a zero-day or malicious pattern is detected.

### Key Feature: Human-in-the-Loop Approval
For BLOCK and CRITICAL severity threats, credential rotation is not automatic. Instead, the system creates a pending alert that an admin must review and approve before Vault rotates credentials. This ensures human oversight over high-impact security actions.

## The Pipeline Architecture
The dashboard visually maps and documents an enterprise-grade 10-stage pipeline. Here is exactly what happens during a real-time event:

* **Network / Apps:** We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.
* **Zeek / Suricata (IDS):** Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).
* **Elastic Beats:** To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.
* **Apache Kafka:** To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as an immutable buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.
* **AI Detection Engine:** The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on a state-of-the-art AI ensemble (XGBoost, LightGBM, Random Forest, Gradient Boosting) to predict if an event is a novel, previously unseen threat.
* **SOAR:** If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human analyst, it automatically triggers conditional incident response playbooks—like isolating machines or initiating automated password resets.
* **HashiCorp Vault (Human-in-the-Loop):** For BLOCK/CRITICAL threats, the system creates a pending admin alert instead of auto-rotating credentials. The admin must review the forensic data, model scores, and pipeline results before approving the rotation.
* **Credential Rotation:** Once approved by an admin, Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services.
* **Credential Distribution:** Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets back to our servers and active microservices using encrypted TLS tunnels, restoring security without taking the system offline.
* **ELK / Grafana:** Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana dashboards.

## Security Admin Console
The admin dashboard provides:

* **Real-time Alert Queue** — Critical and high-severity threats appear as pending alerts
* **Forensic Detail View** — Full event facts, model scores (XGBoost, LightGBM, Ensemble), geo data, and all 10 pipeline stage results
* **Approve / Reject Workflow** — One-click credential rotation approval or false positive rejection
* **Audit Log** — Complete history of all admin actions with timestamps and notes
* **WebSocket Notifications** — Instant toast alerts when new critical threats are detected

## Technologies Used
* **Frontend:** Vanilla JavaScript, Vite, HTML5, CSS3 (Structural Cyber-Bento styling).
* **3D Visualization:** three-globe / globe.gl (WebGL-accelerated geospatial projections).
* **Backend:** Python 3.10+, FastAPI (Asynchronous API and WebSockets).
* **Machine Learning:** scikit-learn, xgboost, lightgbm (Feature Engineering and Ensembling).
* **Infrastructure Layer:** Docker Compose (Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL).

## Project Setup
You can run this project in two ways: the full enterprise stack (via Docker) which runs all services in real-time, or a standalone local demo mode for testing the UI.

---

### Option 1: Full Enterprise Stack (Docker Compose) 🐳
*Recommended for production environments.*

This method will automatically download, build, and orchestrate all 7 containers: Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL, the Python AI Backend, and the Vite Frontend.

**Prerequisites:**
* Docker Desktop running with at least 8GB of Memory allocated (required for Elasticsearch)
* Python 3.10+ installed locally

**Step 1 — Generate ML model artifacts (required on first run only):**
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```
This creates `model_output/pipeline_artifacts_v2.joblib`, `test_events.json`, and `user_profiles.json`. Only needed once — or after dataset changes.

**Step 2 — Start the full stack:**
```bash
docker-compose up --build
```
On **first boot**, allow **2-3 minutes** for all services to fully initialize. Wait until all containers report as healthy before opening the browser.

**Step 3 — Open the application:**

Once all systems are healthy, open your browser and navigate to:
**http://localhost:5173**

Navigate to the **Admin Console** to see pending threat alerts.

> **Note on restarts:** If you stop with `docker-compose down` (without `-v`), Vault will be sealed on the next startup. Unseal it manually with:
> ```bash
> docker exec hpe-vault vault operator unseal -address=http://127.0.0.1:8200 YOUR_UNSEAL_KEY
> ```
> The unseal key is printed in `docker logs hpe-vault-init` on first boot. Then restart the backend:
> ```bash
> docker-compose restart backend
> ```

---

### Option 2: Local Demo Mode (No Docker) 💻
*Recommended for UI development or low-resource machines.*

If you do not want to spin up the heavy infrastructure containers, you can run the backend and frontend scripts directly on your local system. The dashboard will intelligently fall back to generating simulation traffic locally.

**Step 1: Generate model artifacts (if not already done):**
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

**Step 2: Start the Backend (API & Simulation)**
```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000
```
*Because Kafka and Elastic are not active, the backend API will safely fallback into test mode.*

**Step 3: Start the Frontend (3D UI)**
Open a **new** terminal window and run:
```bash
cd frontend

# Install Node modules
npm install

# Start the Vite development server
npm run dev
```
Navigate to **http://localhost:5173**. The application will automatically use "Local Simulation" mode.

---

### Admin API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/alerts` | List all alerts (filter: `?status=pending&severity=critical`) |
| GET | `/api/admin/alerts/{id}` | Full forensic detail for an alert |
| POST | `/api/admin/alerts/{id}/approve` | Approve credential rotation |
| POST | `/api/admin/alerts/{id}/reject` | Reject as false positive |
| GET | `/api/admin/stats` | Dashboard summary statistics |
| GET | `/api/admin/audit-log` | History of admin actions |
| GET | `/api/admin/infra-leases` | Active Vault infrastructure leases and Kafka credential status |
| WS | `/api/admin/ws` | Real-time alert notifications |

---

### Dataset

The training dataset is included in `dataset/`:
- `updated_realistic_network_logs.csv` — 100K+ network events with injected anomalies
- `updated_realistic_user_profiles.csv` — User behavioral profiles

To retrain the model, run:
```bash
python export_v2_model.py
```

---

### Teardown (Stopping Docker) 🛑
To gracefully stop all running containers, open a terminal in the root directory and run:
```bash
docker-compose down
```
If you wish to perform a **hard reset** and wipe all saved databases (Elasticsearch logs, Kafka topics, Vault secrets, PostgreSQL data) to start fresh next time, use:
```bash
docker-compose down -v
```
After a hard reset, re-run `python export_v2_model.py` before starting again.

## Team
HPE Code Project Interns
