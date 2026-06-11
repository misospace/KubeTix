# Secret Rotation Runbook

## Overview

KubeTix uses several secrets that require periodic rotation:

| Secret | Purpose | Storage | Rotation Impact |
|--------|---------|---------|-----------------|
| `secret-key` (JWT) | JWT HS256 signing | Kubernetes Secret / Helm values | **All sessions invalidated immediately** |
| `KUBECONFIG_ENCRYPTION_KEY` | Fernet encryption of kubeconfigs | Environment variable | Existing grants become unreadable |
| PostgreSQL credentials | DB authentication | Kubernetes Secret / values | API loses database connectivity |
| OIDC client secrets | SSO provider auth | Kubernetes Secret / env var | SSO login stops working |

---

## JWT Secret Key Rotation

### Prerequisites

- Helm 3+ installed and configured with cluster access
- The new secret key (32 bytes, base64-encoded)

### Generate a New Key

```bash
openssl rand -base64 32
# Save the output — you will need it for the --set flag below
```

### Rotate via Helm Upgrade

**WARNING:** This invalidates ALL active JWT sessions immediately. Plan for a maintenance window.

```bash
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set secretKey="<NEW_BASE64_KEY>" \
  --wait --timeout 5m
```

### Verify

```bash
# Check all pods are running with the new config
kubectl get pods -n <namespace> -l app.kubernetes.io/name=kubetix-api

# Verify no startup warnings about missing secret key
kubectl logs -n <namespace> deploy/kubetix-api --tail=50 | grep -i "warning\|error"
```

### Rollback (if needed)

```bash
helm rollback kubetix 1 -n <namespace>
```

---

## Fernet Encryption Key Rotation

### Impact Assessment

The Fernet key (`KUBECONFIG_ENCRYPTION_KEY`) is used to encrypt kubeconfigs at rest.
**Rotating this key will make all existing encrypted kubeconfigs unreadable.**
This is a breaking change — plan accordingly.

### Option A: Rotate with Grace Period (Recommended)

If you need to rotate the key but want to avoid data loss:

1. **Set both old and new keys temporarily** (only if your code supports dual-key decryption).
2. As users request access, their kubeconfigs are re-encrypted with the new key.
3. Once all active grants have been re-issued, remove the old key.

*Note: KubeTix currently does not support dual-key decryption natively.
See Option B for a safe procedure.*

### Option B: Full Rotation (Breaking Change)

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -base64 32)
echo "New key: $NEW_KEY"  # Save this securely!

# 2. Update the deployment
kubectl set env deployment/kubetix-api \
  -n <namespace> \
  KUBECONFIG_ENCRYPTION_KEY="$NEW_KEY"

# 3. Verify pods restarted successfully
kubectl rollout status deployment/kubetix-api -n <namespace>

# 4. Notify users that existing grants may fail to decrypt
# Users will need to request new grants after this rotation.
```

---

## PostgreSQL Credential Rotation

### Prerequisites

- Access to the PostgreSQL server (or Helm subchart)
- A new password

### Rotate via Helm Upgrade

```bash
# If using an existing Kubernetes Secret:
kubectl create secret generic kubetix-db-secret \
  --namespace <namespace> \
  --from-literal=password="<NEW_PASSWORD>" \
  --dry-run=client -o yaml | kubectl apply -f -

# Then trigger a rolling restart
helm upgrade kubetix ./charts/kubetix \
  --namespace <namespace> \
  --set database.postgresql.password="<NEW_PASSWORD>" \
  --wait --timeout 5m
```

### If Using an External PostgreSQL Server

1. Change the password on the PostgreSQL server:
   ```sql
   ALTER USER kubetix WITH PASSWORD '<NEW_PASSWORD>';
   ```
2. Update the Kubernetes Secret:
   ```bash
   kubectl create secret generic kubetix-db-secret \
     --namespace <namespace> \
     --from-literal=password="<NEW_PASSWORD>" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
3. Restart the API deployment:
   ```bash
   kubectl rollout restart deployment/kubetix-api -n <namespace>
   ```

---

## OIDC Client Secret Rotation

### General Procedure

1. **Register the new client secret** with your OIDC provider (Google, GitHub, Okta, etc.).
2. **Update the Kubernetes Secret or environment variable** with the new secret.
3. **Restart the API deployment** to pick up the new configuration.
4. **Test SSO login** before decommissioning the old secret.

```bash
# Update env var (example for Google OIDC)
kubectl set env deployment/kubetix-api \
  -n <namespace> \
  GOOGLE_CLIENT_SECRET="<NEW_SECRET>"

# Restart
kubectl rollout restart deployment/kubetix-api -n <namespace>
```

---

## Rotation Schedule Recommendations

| Secret | Recommended Frequency | Method |
|--------|----------------------|--------|
| JWT signing key | Every 90 days or after personnel changes | Helm upgrade (breaking) |
| Fernet encryption key | Annually, with careful user notification | Deployment env update (breaking) |
| PostgreSQL credentials | Every 90 days | Helm upgrade or kubectl set env |
| OIDC client secrets | Per provider policy (typically annually) | kubectl set env |

## Important Notes

1. **Store rotated keys securely** — use a secrets manager (Vault, AWS Secrets Manager, etc.)
   rather than Helm values files.
2. **JWT rotation invalidates all sessions.** Communicate this to users in advance.
3. **Fernet key rotation breaks existing grants.** Users will need new kubeconfigs.
4. **Always test rotation in a staging environment first.**
5. **Keep old keys for a grace period** if possible (e.g., keep old JWT key for 24h
   alongside the new one during transition).
