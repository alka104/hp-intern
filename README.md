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
* **Infrastructure Layer:** Docker Compose / Kubernetes (Minikube) — Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL.
* **Orchestration:** Minikube with multi-replica HA deployments, StatefulSets, init containers, and PersistentVolumeClaims.

---

## Project Setup

You can run this project in **three ways**:

| Mode | Best For | Infrastructure |
|------|----------|---------------|
| **Option 1** — Docker Compose | Full stack on a single machine | Docker Desktop |
| **Option 2** — Kubernetes (Minikube) | Production-grade HA deployment | Minikube + kubectl |
| **Option 3** — Local Demo (No Docker) | UI development / low-resource machines | Python + Node.js only |

---

### Prerequisites (All Options)

**Generate ML model artifacts** (required once, or after dataset changes):
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```
This creates `model_output/pipeline_artifacts_v2.joblib`, `test_events.json`, and `user_profiles.json`.

---

### Option 1: Full Enterprise Stack (Docker Compose) 🐳
*Recommended for single-machine testing.*

This method will automatically download, build, and orchestrate all 7 containers: Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL, the Python AI Backend, and the Vite Frontend.

**Prerequisites:**
* Docker Desktop running with at least **8 GB of Memory** allocated (required for Elasticsearch)
* Python 3.10+ installed locally

**Step 1 — Start the full stack:**
```bash
docker-compose up --build
```
On **first boot**, allow **2-3 minutes** for all services to fully initialize. Wait until all containers report as healthy before opening the browser.

**Step 2 — Open the application:**

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

### Option 2: Kubernetes on Minikube ☸️
*Recommended for production-grade, high-availability deployment.*

This deploys the entire pipeline into a Kubernetes cluster with **HA replicas** (2 Kafka brokers, 2 backend pods, 2 frontend pods), StatefulSets for stateful services, and a Vault init Job for automated secrets management.

#### Architecture Highlights

| Component | K8s Resource | Replicas | Notes |
|-----------|-------------|----------|-------|
| Kafka | StatefulSet | 2 | KRaft mode, headless service with `publishNotReadyAddresses` |
| Elasticsearch | StatefulSet | 1 | Single-node dev mode, 1 Gi PVC |
| PostgreSQL | StatefulSet | 1 | Init ConfigMap for schema + extensions |
| Vault | StatefulSet | 1 | Raft storage on PVC, server mode |
| Vault Init | Job | 1 (run-once) | Phases 1-5: init, unseal, DB engine, AppRole, Kafka creds |
| Backend | Deployment | 2 | Init container waits for all deps + `.approle_credentials` |
| Frontend | Deployment | 2 | Vite dev server behind NodePort |

#### Prerequisites
* **Minikube** installed and running (`minikube start --memory=8192 --cpus=4`)
* **kubectl** configured to point at your Minikube cluster
* **Docker CLI** available (for building images into Minikube's Docker daemon)
* Python 3.10+ (for the model export step)

#### Step 1 — Start Minikube
```bash
minikube start --memory=8192 --cpus=4
```

#### Step 2 — Generate ML artifacts (if not done)
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

#### Step 3 — Deploy with the automated script (Windows PowerShell)
The project includes a **one-shot deployment script** that handles everything:
```powershell
# Full deployment (builds images + deploys all manifests)
.\deploy.ps1

# Skip image rebuilds (faster, if images are already built)
.\deploy.ps1 -SkipBuild

# Clean slate: delete namespace first, then redeploy
.\deploy.ps1 -DeleteFirst

# Fresh: deploy + wipe all pipeline data after startup
.\deploy.ps1 -Fresh
```

The script performs these 6 phases:
1. **Configure Docker** — Points Docker CLI at Minikube's daemon
2. **Build images** — `hpe-backend:latest` and `hpe-frontend:latest` inside Minikube
3. **Create namespace + config** — Applies namespace, ConfigMap, Secrets, PVC
4. **Deploy infrastructure** — PostgreSQL, Kafka (2 brokers), Elasticsearch, Vault
5. **Vault initialization** — Runs the vault-init Job (init → unseal → database engine → AppRole → credential file)
6. **Deploy application** — Backend (2 replicas) + Frontend (2 replicas)

#### Step 4 — Manual deployment (Linux/Mac or if not using PowerShell)

If you are **not** on Windows PowerShell, run the equivalent commands manually:

```bash
# Point Docker to Minikube
eval $(minikube docker-env)

# Build images inside Minikube
docker build -t hpe-backend:latest -f backend/Dockerfile .
docker build -t hpe-frontend:latest -f frontend/Dockerfile ./frontend

# Create namespace and config
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/vault-pvc.yaml

# Deploy infrastructure
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/kafka/
kubectl apply -f k8s/elasticsearch/
kubectl apply -f k8s/vault/vault-config-configmap.yaml
kubectl apply -f k8s/vault/vault-service.yaml
kubectl apply -f k8s/vault/vault-statefulset.yaml

# Wait for infrastructure pods
kubectl wait --for=condition=Ready pod -l app=kafka -n hpe --timeout=240s
kubectl wait --for=condition=Ready pod -l app=elasticsearch -n hpe --timeout=180s
kubectl wait --for=condition=Ready pod -l app=vault -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=postgres -n hpe --timeout=120s

# Run Vault init Job
kubectl apply -f k8s/vault/vault-init-configmap.yaml
kubectl apply -f k8s/vault/vault-init-job.yaml
kubectl wait --for=condition=Complete job/vault-init -n hpe --timeout=180s

# Deploy application
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/

# Wait for app pods
kubectl wait --for=condition=Ready pod -l app=backend -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=frontend -n hpe --timeout=120s
```

#### Step 5 — Access the dashboard
```bash
minikube service frontend -n hpe
```
This opens a browser tunnel to the frontend NodePort service.

#### Useful Kubernetes Commands
```bash
# Check pod status
kubectl get pods -n hpe

# View logs for a specific pod
kubectl logs -f deployment/backend -n hpe

# View Vault init logs
kubectl logs job/vault-init -n hpe

# Port-forward backend for direct API access
kubectl port-forward service/backend 8000:8000 -n hpe

# Tear down everything
kubectl delete namespace hpe
```

#### Vault Unsealing After Restart

> **Why does Vault seal itself?**
> Vault uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) as a security mechanism. Every time Vault's container restarts (e.g., after `minikube stop` → `minikube start`), Vault deliberately seals itself. This is **by design** — if someone gains physical access to the server, they cannot read any secrets without the unseal key. This is not automated intentionally to preserve the security model.

If the dashboard shows **Vault** as red (🔴) after a Minikube restart, follow these steps:

**Step 1 — Check if Vault is sealed:**
```bash
kubectl exec vault-0 -n hpe -- vault status
```
If `Sealed: true`, proceed to Step 2.

**Step 2 — Retrieve the unseal key from the PVC:**
```bash
kubectl exec vault-0 -n hpe -- cat /vault/data/.unseal_key
```

**Step 3 — Unseal Vault using the key:**
```bash
kubectl exec vault-0 -n hpe -- vault operator unseal <YOUR_UNSEAL_KEY>
```

**Step 4 — Restart the backend so it reconnects to Vault:**
```bash
kubectl rollout restart deployment/backend -n hpe
```

After this, refresh the dashboard — the Vault indicator should turn green (🟢).

---

### Option 3: Local Demo Mode (No Docker) 💻
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

### Kubernetes Manifest Structure
```
k8s/
├── namespace.yaml              # hpe namespace
├── configmap.yaml              # Shared env vars (Kafka, ES, Vault URLs)
├── secrets.yaml                # VAULT_TOKEN fallback secret
├── vault-pvc.yaml              # Shared PVC for Vault data + AppRole creds
├── kafka/
│   ├── kafka-headless-service.yaml   # Headless service (publishNotReadyAddresses)
│   └── kafka-statefulset.yaml        # 2-broker KRaft cluster
├── elasticsearch/
│   ├── es-service.yaml
│   └── es-statefulset.yaml
├── postgres/
│   ├── postgres-init-configmap.yaml  # Schema, pgcrypto, tables
│   ├── postgres-service.yaml
│   └── postgres-statefulset.yaml
├── vault/
│   ├── vault-config-configmap.yaml   # vault.hcl server config
│   ├── vault-init-configmap.yaml     # Full init script (5 phases)
│   ├── vault-init-job.yaml           # One-shot init Job
│   ├── vault-service.yaml
│   └── vault-statefulset.yaml
├── backend/
│   ├── backend-deployment.yaml       # 2 replicas + init container
│   └── backend-service.yaml
└── frontend/
    ├── frontend-deployment.yaml      # 2 replicas
    └── frontend-service.yaml
```

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

### Teardown 🛑

**Docker Compose:**
```bash
# Graceful stop
docker-compose down

# Hard reset (wipes all databases, Kafka topics, Vault secrets)
docker-compose down -v
```

**Kubernetes (Minikube):**
```bash
# Delete everything in the hpe namespace
kubectl delete namespace hpe

# Optionally stop Minikube
minikube stop
```

After a hard reset, re-run `python export_v2_model.py` before starting again.

## Team
HPE Code Project Interns
