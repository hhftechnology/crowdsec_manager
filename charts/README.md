# CrowdSec Manager — Helm Chart

Deploy CrowdSec Manager on Kubernetes with a **Tailscale sidecar** for VPN-only access using Helm.

For plain `kubectl` manifests (no Helm), see [`../k8s/`](../k8s/).

---

## Chart Location

```
charts/
└── crowdsec-manager/       ← chart directory (pass this to helm install)
    ├── Chart.yaml
    ├── values.yaml          ← all configurable defaults
    └── templates/
        ├── _helpers.tpl
        ├── deployment.yaml  ← Pod with Tailscale sidecar + app container
        ├── service.yaml
        ├── configmap.yaml
        ├── secret.yaml
        ├── pvc-data.yaml
        ├── pvc-config.yaml
        ├── pvc-backups.yaml
        ├── pvc-logs.yaml
        ├── pvc-tailscale.yaml
        └── NOTES.txt
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes 1.24+ | Tested on k3s, k0s, microk8s |
| Helm 3.10+ | `helm version` to check |
| Tailscale account | Auth key from [admin console](https://login.tailscale.com/admin/settings/keys) |
| Node with Docker daemon | The node that runs CrowdSec + Traefik |
| `/dev/net/tun` + WireGuard | Linux 5.6+ has both built-in; older: `modprobe tun wireguard` |

---

## Quick Start

### 1. Label the target node

```bash
kubectl label node <your-node-name> crowdsec-manager/host=true
```

> Skip this step on single-node clusters — set `nodeSelector: {}` in your values instead.

### 2. Create the namespace

```bash
kubectl create namespace crowdsec
```

### 3. Create the Tailscale secret (recommended — keeps the key out of Helm values)

Generate a **reusable** auth key at [Tailscale Admin → Settings → Keys](https://login.tailscale.com/admin/settings/keys).

```bash
kubectl create secret generic crowdsec-manager-tailscale \
  --namespace crowdsec \
  --from-literal=TS_AUTHKEY="tskey-auth-XXXXXXXXXXXX-YYYYYYY"
```

### 4. Install the chart

Using the pre-created secret:

```bash
helm install crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --set tailscaleSecret.existingSecret=crowdsec-manager-tailscale
```

Or supply the key inline (not recommended for GitOps — it ends up in Helm history):

```bash
helm install crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --set tailscaleSecret.authKey="tskey-auth-XXXXXXXXXXXX-YYYYYYY"
```

---

## Configuration

All defaults are in `values.yaml`. Override with `--set key=value` or a custom values file.

### Common overrides

```yaml
# my-values.yaml

# Single-node cluster — disable node label requirement
nodeSelector: {}

# Adjust container names to match your Docker setup
app:
  crowdsec:
    containerName: crowdsec
    metricsUrl: http://crowdsec:6060/metrics
  traefik:
    containerName: traefik

# Disable Pangolin/Gerbil if not in use
app:
  pangolin:
    enabled: "false"
  gerbil:
    enabled: "false"

# Tailscale hostname in the admin console
tailscale:
  hostname: my-crowdsec-server

# StorageClass for PVCs (leave empty for cluster default)
persistence:
  data:
    storageClass: local-path
```

Apply:

```bash
helm install crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --set tailscaleSecret.existingSecret=crowdsec-manager-tailscale \
  -f my-values.yaml
```

### Injecting a docker-compose.yml

To let the app manage Docker Compose services, inject your compose file as a ConfigMap:

```bash
helm upgrade crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --reuse-values \
  --set dockerCompose.enabled=true \
  --set-file dockerCompose.content=/path/to/your/docker-compose.yml
```

### Userspace Tailscale (no kernel WireGuard)

If your node's kernel lacks WireGuard support (Linux < 5.6 without backport):

```bash
helm install crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --set tailscale.userspace=true \
  --set tailscaleSecret.existingSecret=crowdsec-manager-tailscale
```

### NATS messaging (optional)

```bash
kubectl create secret generic crowdsec-manager-nats \
  --namespace crowdsec \
  --from-literal=NATS_TOKEN="my-nats-token"

helm install crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --set app.nats.enabled=true \
  --set app.nats.url=nats://nats-server:4222 \
  --set natsSecret.existingSecret=crowdsec-manager-nats \
  --set tailscaleSecret.existingSecret=crowdsec-manager-tailscale
```

---

## Verify the Deployment

```bash
# Pod status — both containers should show Running
kubectl get pods -n crowdsec

# Find the Tailscale IP
kubectl logs -n crowdsec deployment/crowdsec-manager -c tailscale | grep -E "100\.[0-9]"

# Health check from a Tailscale-connected device
curl http://<tailscale-ip>:8080/health
# Expected: {"status":"ok"}

# All 5 PVCs should be Bound
kubectl get pvc -n crowdsec
```

---

## Upgrading

```bash
# Pull latest app image and apply changed values
helm upgrade crowdsec-manager ./charts/crowdsec-manager \
  --namespace crowdsec \
  --reuse-values
```

Deployments use `strategy.type: Recreate` — there is brief downtime while the old Pod terminates and the new one starts. This is required because SQLite PVCs use `ReadWriteOnce`.

---

## Uninstalling

```bash
# Removes the Deployment, Service, ConfigMap, and non-keep PVCs
helm uninstall crowdsec-manager --namespace crowdsec

# PVCs annotated with helm.sh/resource-policy=keep must be deleted manually:
kubectl delete pvc \
  crowdsec-manager-data \
  crowdsec-manager-config \
  crowdsec-manager-tailscalestate \
  -n crowdsec

# Remove the Tailscale auth secret if you created it separately
kubectl delete secret crowdsec-manager-tailscale -n crowdsec

# Remove the namespace
kubectl delete namespace crowdsec
```

---

## Key Design Notes

### Tailscale Sidecar = `network_mode: service:tailscale`

In Docker Compose, `network_mode: service:tailscale` makes the app share the Tailscale container's network namespace. In Kubernetes, all containers in the same Pod share a network namespace automatically — no special configuration required. The sidecar pattern is the direct equivalent.

### Deployment Strategy: Recreate

`ReadWriteOnce` PVCs can only be mounted by one node at a time. `RollingUpdate` would deadlock waiting for the old Pod to release the PVC. `Recreate` terminates the old Pod first.

### SQLite StorageClass

Use a **node-local** StorageClass (`local-path`, `openebs-hostpath`) for the `data` PVC. SQLite over NFS causes corruption due to POSIX lock semantics.

### Docker Socket Security

Mounting `/var/run/docker.sock` grants the container effective root on the host node. Mitigations:
- `nodeSelector` pins the Pod to a trusted node
- Add a `NetworkPolicy` to restrict cluster-wide egress from this Pod
- Keep `replicas: 1` — never run two instances of this app

### Auth Key Persistence

After first boot, the Tailscale WireGuard identity is saved to the `tailscaleState` PVC. The auth key is only needed for the initial registration. Use a **reusable** key so the Pod can re-authenticate if the state PVC is ever lost.
