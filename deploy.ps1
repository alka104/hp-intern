# deploy.ps1 - Robust HPE Pipeline deployment
param(
    [switch]$SkipBuild,
    [switch]$DeleteFirst,
    [switch]$Fresh
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step($n, $msg) {
    Write-Host ""
    Write-Host "[$n] $msg" -ForegroundColor Cyan
}

function Assert-Command($cmd) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: '$cmd' not found. Please install it." -ForegroundColor Red
        exit 1
    }
}

function Wait-ForPods($label, $timeout = "240s") {
    Write-Host "    Waiting for: $label" -ForegroundColor DarkYellow
    kubectl wait --for=condition=Ready pod -l $label -n hpe --timeout=$timeout
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Pods not ready ($label). Current pod status:" -ForegroundColor Red
        kubectl get pods -n hpe
        exit 1
    }
    Write-Host "    Ready: $label" -ForegroundColor Green
}

# ── Pre-flight ──────────────────────────────────────────────────────────────
Assert-Command "minikube"
Assert-Command "kubectl"
Assert-Command "docker"

Write-Host ""
Write-Host "=== HPE Threat Detection Pipeline ===" -ForegroundColor Cyan

# Make sure MINIKUBE_HOME points to D drive
# NEW - respects each person's own setup
if ($env:MINIKUBE_HOME) {
    Write-Host "  Using MINIKUBE_HOME: $env:MINIKUBE_HOME" -ForegroundColor DarkYellow
} else {
    Write-Host "  MINIKUBE_HOME not set - using default Minikube location" -ForegroundColor DarkYellow
    Write-Host "  (If Minikube fails, set MINIKUBE_HOME to your preferred path)" -ForegroundColor DarkYellow
}

# Start minikube if not running
$mkStatus = (minikube status --format='{{.Host}}' 2>$null)
if ($mkStatus -ne "Running") {
    Write-Host "  Starting Minikube..." -ForegroundColor Yellow
    minikube start --driver=docker --memory=8192 --cpus=4
}

# ── Phase 0: Optional clean slate ──────────────────────────────────────────
if ($DeleteFirst) {
    Write-Step "0" "Removing previous deployment"
    kubectl delete namespace hpe --ignore-not-found=true
    Write-Host "  Waiting for namespace to terminate..." -ForegroundColor DarkYellow
    Start-Sleep -Seconds 10
}

# ── Phase 1: Docker ─────────────────────────────────────────────────────────
Write-Step "1" "Pointing Docker at Minikube"
& minikube docker-env | Invoke-Expression

# ── Phase 2: Build images ───────────────────────────────────────────────────
if (-not $SkipBuild) {
    Write-Step "2" "Building backend image"
    docker build -t hpe-backend:latest -f backend/Dockerfile .
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: backend build failed" -ForegroundColor Red; exit 1 }

    Write-Step "2b" "Building frontend image"
    docker build -t hpe-frontend:latest -f frontend/Dockerfile ./frontend
    if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: frontend build failed" -ForegroundColor Red; exit 1 }
} else {
    Write-Step "2" "Skipping image builds (--SkipBuild)"
}

# ── Phase 3: Namespace + config ─────────────────────────────────────────────
Write-Step "3" "Creating namespace and shared config"
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/vault-pvc.yaml

# ── Phase 4: Infrastructure ─────────────────────────────────────────────────
Write-Step "4" "Deploying infrastructure services"
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/kafka/
kubectl apply -f k8s/elasticsearch/
kubectl apply -f k8s/vault/vault-config-configmap.yaml
kubectl apply -f k8s/vault/vault-service.yaml
kubectl apply -f k8s/vault/vault-statefulset.yaml

Write-Host "  Giving pods 20s to start scheduling..." -ForegroundColor DarkYellow
Start-Sleep -Seconds 20

Wait-ForPods "app=postgres"    "120s"
Wait-ForPods "app=kafka"       "240s"
Wait-ForPods "app=elasticsearch" "180s"
Wait-ForPods "app=vault"       "120s"

# ── Phase 5: Vault init ─────────────────────────────────────────────────────
Write-Step "5" "Running Vault initialization"
kubectl delete job vault-init -n hpe --ignore-not-found=true
Start-Sleep -Seconds 3
kubectl apply -f k8s/vault/vault-init-configmap.yaml
kubectl apply -f k8s/vault/vault-init-job.yaml

Write-Host "  Waiting for vault-init to complete (up to 3 min)..." -ForegroundColor DarkYellow
kubectl wait --for=condition=Complete job/vault-init -n hpe --timeout=180s
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: vault-init failed! Last 30 log lines:" -ForegroundColor Red
    kubectl logs job/vault-init -n hpe --tail=30
    exit 1
}
Write-Host "  vault-init complete. Last 5 lines:" -ForegroundColor Green
kubectl logs job/vault-init -n hpe --tail=5

# ── Phase 6: App ────────────────────────────────────────────────────────────
Write-Step "6" "Deploying backend and frontend"
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/

Start-Sleep -Seconds 10
Wait-ForPods "app=backend"  "120s"
Wait-ForPods "app=frontend" "120s"

# ── Phase 7: HPA ────────────────────────────────────────────────────────────
Write-Step "7" "Enabling metrics-server and HPA"
minikube addons enable metrics-server
kubectl apply -f k8s/backend/backend-hpa.yaml
Write-Host "  HPA applied. Takes ~60s for metrics to populate." -ForegroundColor DarkYellow

# ── Optional fresh reset ────────────────────────────────────────────────────
if ($Fresh) {
    Write-Step "FRESH" "Wiping pipeline data via API"
    $job = Start-Job -ScriptBlock { kubectl port-forward service/backend 8000:8000 -n hpe }
    Start-Sleep -Seconds 4
    try {
        Invoke-RestMethod -Uri "http://localhost:8000/api/admin/reset" -Method Post
        Write-Host "  Pipeline data cleared." -ForegroundColor Green
    } catch {
        Write-Host "  Could not reset (backend may still be warming up): $_" -ForegroundColor Yellow
    } finally {
        $job | Stop-Job | Remove-Job
    }
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Deployment Complete ===" -ForegroundColor Green
Write-Host ""
kubectl get pods -n hpe
Write-Host ""
Write-Host "Next commands:" -ForegroundColor Cyan
Write-Host "  Open app:          minikube service frontend -n hpe"
Write-Host "  Watch pods:        kubectl get pods -n hpe -w"
Write-Host "  Check autoscaler:  kubectl get hpa -n hpe"
Write-Host "  Manual scale:      kubectl scale deployment backend --replicas=5 -n hpe"
Write-Host "  Pod logs:          kubectl logs -l app=backend -n hpe --tail=30"
Write-Host ""