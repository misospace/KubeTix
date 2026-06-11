# Helm Upgrade & Rollback Runbook

## Overview

KubeTix is deployed via a Helm chart (`charts/kubetix/`). This runbook covers
safe upgrade procedures, failure scenarios, and rollback steps.

---

## Pre-Upgrade Checklist

Before running any Helm upgrade:

- [ ] All CI checks pass on the branch being deployed
- [ ] Chart version has been incremented in `Chart.yaml`
- [ ] Values changes have been reviewed (especially `secretKey`, database config)
- [ ] Database migrations are backwards-compatible (or a migration plan exists)
- [ ] Backup of current state exists (see Backup & Restore runbook)
- [ ] Rollback procedure has been tested in staging

---

## Standard Helm Upgrade Procedure

### Dry Run First

```bash
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --values values-custom.yaml \
  --dry-run --debug
```

### Apply the Upgrade

```bash
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --values values-custom.yaml \
  --wait --timeout 5m
```

### Post-Upgrade Verification

```bash
# Check all pods are running
kubectl get pods -n <namespace> -l app.kubernetes.io/name=kubetix-api

# Check API health
kubectl exec -n <namespace> deploy/kubetix-api -- python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('http://localhost:8000/docs')
    print(f'API docs available: {r.status}')
except Exception as e:
    print(f'Health check failed: {e}')
"

# Check logs for errors
kubectl logs -n <namespace> deploy/kubetix-api --tail=100 | grep -i "error\|exception\|traceback"

# Test grant creation (non-destructive)
curl -s -X POST http://<ingress-host>/grants \
  -H "Content-Type: application/json" \
  -d '{"cluster":"test","role":"view","expiry":"1h"}' \
  -H "Authorization: Bearer <admin-token>"
```

---

## Known Upgrade Failure Scenarios

### Scenario 1: JWT Secret Key Changed (Sessions Invalidated)

**Symptoms:**
- All API users receive `401 Unauthorized` after upgrade
- Logs show new JWT signing key was generated

**Cause:** The Helm chart's `secrets.yaml` uses `randAlphaNum 32` when
`secretKey` is not explicitly set, generating a new random key on every upgrade.

**Fix:**

```bash
# Generate a stable secret key
NEW_KEY=$(openssl rand -base64 32)

# Re-apply with explicit key
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set secretKey="$NEW_KEY" \
  --wait --timeout 5m

# Users must re-authenticate. Existing JWTs are no longer valid.
```

**Prevention:** Always set `secretKey` in `values.yaml` or via `--set` for
production deployments. Never rely on the random key generator.

### Scenario 2: Database Migration Fails

**Symptoms:**
- API pods crash-looping with database error messages
- Helm upgrade hangs or times out

**Fix:**

```bash
# Rollback to previous release
helm rollback kubetix 1 -n <namespace>

# Investigate the migration failure
kubectl logs -n <namespace> deploy/kubetix-api --tail=200

# If using PostgreSQL, check schema version
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  psql -h <postgres-host> -U kubetix -d kubetix -c "SELECT * FROM alembic_version;"

# Fix the migration script, then retry
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --wait --timeout 5m
```

### Scenario 3: SQLite Lock Contention After Scaling Up

**Symptoms:**
- Intermittent `database is locked` errors in logs
- API returns 500 errors under load

**Cause:** SQLite does not support concurrent writes from multiple replicas.
If `replicaCount > 1` with SQLite enabled, write contention will occur.

**Fix:**

```bash
# Option A: Scale back to single replica
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set replicaCount=1 \
  --wait --timeout 5m

# Option B: Switch to PostgreSQL (recommended for production)
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set database.sqlite.enabled=false \
  --set database.postgresql.enabled=true \
  --set database.postgresql.host=<host> \
  --set database.postgresql.port=5432 \
  --set database.postgresql.database=kubetix \
  --set database.postgresql.username=kubetix \
  --set database.postgresql.password=<password> \
  --set replicaCount=2 \
  --wait --timeout 5m
```

### Scenario 4: Image Pull Failure

**Symptoms:**
- Pods stuck in `ImagePullBackOff` or `ErrImagePull`
- Helm upgrade hangs waiting for deployment rollout

**Fix:**

```bash
# Check image reference
kubectl describe pod -n <namespace> -l app.kubernetes.io/name=kubetix-api | grep Image

# Verify image exists in registry
docker pull ghcr.io/misospace/kubetix-api:<tag>

# If using wrong tag, correct it
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set image.tag="<correct-tag>" \
  --wait --timeout 5m

# Or rollback if the new image is broken
helm rollback kubetix 1 -n <namespace>
```

### Scenario 5: Ingress/SSL Breakage

**Symptoms:**
- Users cannot reach the API via HTTPS
- TLS certificate errors in browser

**Fix:**

```bash
# Check ingress status
kubectl get ingress -n <namespace> | grep kubetix

# Check cert-manager
kubectl get certificates -n <namespace>
kubectl describe certificate -n <namespace> kubetix-tls

# If cert is expired or failed, force renewal
kubectl delete certificate kubetix-tls -n <namespace>
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --wait --timeout 5m
```

---

## Rollback Procedures

### Helm Rollback (Fastest)

```bash
# List release history
helm history kubetix -n <namespace>

# Rollback to previous revision
helm rollback kubetix 1 -n <namespace>

# Verify rollback
kubectl rollout status deployment/kubetix-api -n <namespace>
```

### Manual Rollback (If Helm Fails)

```bash
# Scale down the new version
kubectl scale deployment kubetix-api --replicas=0 -n <namespace>

# Restore from backup (see Backup & Restore runbook)
# ... restore database and secrets ...

# Re-apply the previous Helm release manually
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --values values-backup.yaml \
  --wait --timeout 5m
```

### Emergency: Full Cluster Reset

If the deployment is completely broken and cannot be rolled back:

1. **Back up current state** (even if broken) for forensics
2. **Delete the Helm release:**
   ```bash
   helm uninstall kubetix -n <namespace>
   ```
3. **Restore from known-good backup:**
   ```bash
   # Restore database from backup
   # Restore secrets from backup
   ```
4. **Re-deploy from scratch:**
   ```bash
   helm install kubetix ./charts/kubetix \
     --namespace <namespace> \
     --values values-known-good.yaml \
     --wait --timeout 10m
   ```

---

## Upgrade Frequency Recommendations

| Change Type | Frequency | Method |
|-------------|-----------|--------|
| Security patches | As released | Helm upgrade with `--wait` |
| Feature releases | Weekly or per sprint | Helm upgrade with dry-run first |
| Dependency updates | Monthly | Renovate PRs reviewed individually |
| Chart version bump | Per release cycle | Full pre-upgrade checklist |

## Important Notes

1. **Always use `helm history`** to track what was deployed and when.
2. **Never skip the dry run** — it catches template errors before they hit production.
3. **Keep values backups.** Save a copy of the current `values.yaml` before each upgrade.
4. **Test upgrades in staging first.** The staging environment should mirror production.
5. **Document every upgrade.** Add a note to the Helm release history or an upgrade log.
