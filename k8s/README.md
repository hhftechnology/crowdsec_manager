# CrowdSec Manager — Kubernetes Raw Manifests

Deploy CrowdSec Manager on Kubernetes with a **Tailscale sidecar** for VPN-only access.
Access is strictly via your Tailscale network — no Ingress or NodePort is exposed.

---

## Architecture

```
Pod: crowdsec-manager
├── Container: tailscale          (sidecar — creates WireGuard interface)
└── Container: crowdsec-manager   (main app — shares the same network namespace)
```

All containers in a Kubernetes Pod automatically share one network namespace.
This is the exact equivalent of Docker Compose's `network_mode: service:tailscale`.
The Tailscale sidecar builds a `tailscale0` WireGuard interface that the app container uses transparently.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Kubernetes 1.24+ | Tested on k3s, k0s, microk8s |
| `kubectl` configured | Pointing at your cluster |
| Tailscale account | Auth key from [admin console](https://login.tailscale.com/admin/settings/keys) |
| Node with Docker daemon | The node that runs CrowdSec + Traefik |
| `/dev/net/tun` on the node | For kernel WireGuard (`modprobe tun`) |
| WireGuard kernel module | Linux 5.6+ has it built-in; older: `modprobe wireguard` |

> **Single-node cluster?** If you only have one node (e.g. k3s on a homelab server), skip the node label step and remove `nodeSelector` from `deployment.yaml`.

---

## Quick Start

### 1. Label the target node

The Pod must land on the node that runs Docker/CrowdSec/Traefik:

```bash
kubectl label node <your-node-name> crowdsec-manager/host=true

# Verify:
kubectl get nodes --show-labels | grep crowdsec-manager
```

### 2. Create the namespace

```bash
kubectl apply -f namespace.yaml
```

### 3. Create the Tailscale auth key secret

Get a **reusable** auth key from [Tailscale Admin → Settings → Keys](https://login.tailscale.com/admin/settings/keys).
Enable "Reusable" so the Pod can re-authenticate if the state PVC is ever lost.

```bash
# Recommended: imperative command (never commit a real key to Git)
kubectl create secret generic crowdsec-manager-tailscale \
  --namespace crowdsec \
  --from-literal=TS_AUTHKEY="tskey-auth-XXXXXXXXXXXX-YYYYYYY"
```

Alternatively edit `secret.yaml`, replace `tskey-auth-REPLACE_ME`, then:

```bash
kubectl apply -f secret.yaml
```

### 4. Configure the application

Edit `configmap.yaml` and set values for your environment:

| Key | What to change |
|---|---|
| `CROWDSEC_METRICS_URL` | URL to your CrowdSec metrics endpoint |
| `TRAEFIK_CONTAINER_NAME` | Name of your Traefik container on the host |
| `CROWDSEC_CONTAINER_NAME` | Name of your CrowdSec container on the host |
| `INCLUDE_PANGOLIN` / `INCLUDE_GERBIL` | Set `"false"` if not running Pangolin/Gerbil |
| `NATS_ENABLED` | Set `"true"` and add `NATS_URL` if using NATS |

### 5. Apply all manifests

```bash
kubectl apply -f namespace.yaml
kubectl apply -f secret.yaml        # or skip if created imperatively above
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

Or apply the whole directory at once:

```bash
kubectl apply -f k8s/
```

---

## Verify the Deployment

```bash
# Check Pod status — both containers should be Running
kubectl get pods -n crowdsec -w

# Check both containers are up
kubectl get pods -n crowdsec -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.name}={.ready}{" "}{end}{"\n"}{end}'

# Find your Tailscale IP (look for "100.x.x.x")
kubectl logs -n crowdsec deployment/crowdsec-manager -c tailscale | grep -E "100\.[0-9]"

# Confirm the app is healthy via Tailscale IP (run from a Tailscale-connected device)
curl http://<tailscale-ip>:8080/health
# Expected: {"status":"ok"}

# Check all PVCs are Bound
kubectl get pvc -n crowdsec
```

---

## Accessing the Dashboard

The app is accessible **only** from devices on your Tailscale network:

```
http://<tailscale-ip>:8080
```

To find the Tailscale IP:
- Check `kubectl logs -n crowdsec deployment/crowdsec-manager -c tailscale`
- Or visit [Tailscale Admin → Machines](https://login.tailscale.com/admin/machines) and look for `crowdsec-manager`

---

## Injecting a docker-compose.yml (Optional)

The app can manage your Docker services via a `docker-compose.yml`. To inject one:

```bash
kubectl create configmap crowdsec-manager-compose \
  --namespace crowdsec \
  --from-file=docker-compose.yml=/path/to/your/docker-compose.yml
```

Then uncomment the `docker-compose` volume and volumeMount in `deployment.yaml` and re-apply.

---

## Upgrading

```bash
# Update the image tag (triggers Pod recreation via Recreate strategy)
kubectl set image deployment/crowdsec-manager \
  crowdsec-manager=hhftechnology/crowdsec-manager:v1.2.3 \
  -n crowdsec

# Or re-apply the whole manifest after editing
kubectl apply -f deployment.yaml
```

---

## Teardown

```bash
# Remove everything except the keep-annotated PVCs and secret
kubectl delete -f service.yaml -f deployment.yaml -f configmap.yaml

# Also remove PVCs (WARNING: deletes all data and Tailscale identity)
kubectl delete pvc --all -n crowdsec

# Remove the secret
kubectl delete secret crowdsec-manager-tailscale -n crowdsec

# Remove the namespace
kubectl delete namespace crowdsec
```

---

## File Reference

| File | Purpose |
|---|---|
| `namespace.yaml` | Creates the `crowdsec` namespace |
| `secret.yaml` | Tailscale auth key (template — fill in before applying) |
| `configmap.yaml` | All non-secret application environment variables |
| `pvc.yaml` | Five PersistentVolumeClaims (data, config, backups, logs, tailscale-state) |
| `deployment.yaml` | Main Pod spec with Tailscale sidecar + crowdsec-manager containers |
| `service.yaml` | ClusterIP service for in-cluster DNS |

---

## Security Notes

- **Docker socket**: Mounting `/var/run/docker.sock` gives the container effective root on the host node. Mitigate by using `nodeSelector` to restrict which node the Pod lands on, and apply a `NetworkPolicy` to limit egress.
- **Root container**: The app runs as UID 0 (matches the upstream Dockerfile). This is required to write to mounted volumes and communicate with the Docker socket.
- **Tailscale userspace mode**: If your node's kernel does not support WireGuard (Linux < 5.6 without backport), set `TS_USERSPACE: "true"` in `deployment.yaml`. Remove the `SYS_MODULE` capability and the `/dev/net/tun` volume in that case.
- **Auth key**: Use a reusable Tailscale auth key. After first boot, the identity is stored in the `tailscale-state` PVC — the key is only needed on initial registration or if the PVC is lost.
