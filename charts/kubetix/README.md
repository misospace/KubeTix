# KubeTix Helm Chart

Helm chart for deploying KubeTix - Temporary Kubernetes Access Manager.

## Prerequisites

- Kubernetes 1.25+
- Helm 3+
- Ingress controller (nginx recommended)
- cert-manager (optional, for TLS)

## Install

### Quick Start (SQLite - Default)

```bash
# Install with SQLite (simple, persistent storage)
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace
```

### Production (PostgreSQL)

```bash
# Install with PostgreSQL
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace \
  --set database.postgresql.enabled=true \
  --set database.postgresql.host=<your-db-host> \
  --set database.postgresql.password=<secure-password>
```

## Uninstall

```bash
helm uninstall kubetix --namespace kubetix
```

## Configuration

The following table lists the configurable parameters of the KubeTix chart and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | API image repository | `ghcr.io/joryirving/kubetix-api` |
| `image.tag` | API image tag | `Chart.AppVersion` |
| `replicaCount` | Number of API replicas | `1` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8000` |
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.className` | Ingress class | `nginx` |
| `ingress.hosts[0].host` | Ingress host | `kubetix.example.com` |
| `ingress.tls` | TLS configuration | `kubetix-tls` |
| `resources` | Resource limits | See values.yaml |
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `1` |
| `autoscaling.maxReplicas` | Maximum replicas | `5` |
| `database.sqlite.enabled` | Use SQLite (default) | `true` |
| `database.sqlite.persistence.size` | SQLite storage size | `1Gi` |
| `database.postgresql.enabled` | Use PostgreSQL | `false` |
| `database.postgresql.host` | PostgreSQL host | `""` |
| `database.postgresql.password` | PostgreSQL password | `""` |
| `oidc.enabled` | Enable OIDC | `false` |
| `oidc.issuer` | OIDC issuer URL | `""` |
| `oidc.clientId` | OIDC client ID | `""` |
| `oidc.clientSecret` | OIDC client secret | `""` |

### Database Configuration

KubeTix supports SQLite (default) and PostgreSQL.

#### SQLite (Default - Quick Start)

SQLite is enabled by default for easy setup. Data is persisted to a PVC.

```bash
# Install with SQLite (default)
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace
```

**Pros:**
- ✅ No external dependencies
- ✅ Quick setup
- ✅ Persistent storage included
- ✅ Perfect for development/testing

**Cons:**
- ❌ Not recommended for production
- ❌ No connection pooling
- ❌ Limited concurrent access

#### PostgreSQL (Production Recommended)

```bash
# Install with PostgreSQL
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace \
  --set database.postgresql.enabled=true \
  --set database.postgresql.host=postgres.example.com \
  --set database.postgresql.password=<secure-password> \
  --set database.postgresql.username=kubetix \
  --set database.postgresql.database=kubetix
```

#### Using Existing PostgreSQL Secret

```bash
# Create secret with database URL
kubectl create secret generic kubetix-db \
  --namespace kubetix \
  --from-literal=database-url=postgresql://user:pass@host:5432/kubetix

# Install with existing secret
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --set database.postgresql.enabled=true \
  --set database.postgresql.existingSecret=kubetix-db \
  --set database.postgresql.existingSecretPasswordKey=database-url
```

### OIDC Configuration

Enable OIDC authentication (e.g., Authentik, Keycloak, Okta):

```bash
helm install kubetix kubetix/kubetix \
  --set oidc.enabled=true \
  --set oidc.issuer=https://authentik.example.com \
  --set oidc.clientId=kubetix \
  --set oidc.clientSecret=<your-secret> \
  --set oidc.redirectUri=https://kubetix.example.com/api/v1/auth/oidc/callback
```

### Autoscaling

Enable horizontal pod autoscaling:

```bash
helm install kubetix kubetix/kubetix \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10 \
  --set autoscaling.targetCPUUtilizationPercentage=70
```

### External Secrets Manager

KubeTix supports external secrets managers for production deployments. When enabled, inline secret generation is disabled and secrets are fetched from an external provider instead.

**Prerequisites:** The [External Secrets Operator](https://external-secrets.io/) must be installed in the cluster before enabling external secrets.

#### HashiCorp Vault

```bash
# Install with Vault external secrets
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace \
  --set externalSecrets.enabled=true \
  --set externalSecrets.vault.enabled=true \
  --set externalSecrets.vault.address=https://vault.example.com:8200 \
  --set externalSecrets.vault.role=kubetix \
  --set externalSecrets.vault.secretPath=secret/data/kubetix
```

Before deploying, configure Vault:

1. **Create the secret** in Vault at the configured path containing `database-url` and `secret-key`:
   ```bash
   vault kv put secret/data/kubetix \
     database-url="postgresql://user:pass@host:5432/kubetix" \
     secret-key="$(openssl rand -base64 32)"
   ```

2. **Enable Kubernetes auth** and create a role:
   ```bash
   vault auth enable kubernetes
   vault write auth/kubernetes/config \
     token_reviewer_jwt="<JWT>" \
     kubernetes_host="https://kubernetes.default.svc"
   vault write auth/kubernetes/role/kubetix \
     bound_service_account_names=kubetix-kubetix \
     bound_service_account_namespaces=kubetix \
     policies=kubetix \
     ttl=1h
   ```

3. **Grant Vault Agent annotations** on the ServiceAccount if using Vault Agent Injector:
   ```bash
   kubectl annotate serviceaccount kubetix-kubetix \
     vault.hashicorp.com/agent-inject=true \
     --namespace kubetix
   ```

The chart auto-creates a `ClusterSecretStore` (`<release>-vault-backend`) and an `ExternalSecret` resource. The Vault Agent Injector sidecar also mounts decrypted secrets at `/vault/secrets`.

#### AWS Secrets Manager

```bash
# Install with AWS Secrets Manager
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --create-namespace \
  --set externalSecrets.enabled=true \
  --set externalSecrets.aws.enabled=true \
  --set externalSecrets.aws.secretArn=arn:aws:secretsmanager:us-east-1:123456789012:secret:kubetix-abc123 \
  --set externalSecrets.aws.region=us-east-1
```

Before deploying, configure AWS:

1. **Create the secret** in AWS Secrets Manager with keys `database-url` and `secret-key`.

2. **Configure authentication**:
   - **IAM role (default)**: Attach an IAM role to the EKS node pool or use IRSA on the ServiceAccount. The chart creates a `SecretStore` (`<release>-aws-backend`) that references the service account for JWT-based auth.
   - **Static credentials**: Set `externalSecrets.aws.credentialsSecret` to an existing Kubernetes secret containing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

The chart auto-creates a `SecretStore` (`<release>-aws-backend`) and an `ExternalSecret` resource.

## Values File

See `values.yaml` for complete configuration options.

## Troubleshooting

```bash
# Check deployment status
helm status kubetix --namespace kubetix

# View logs
kubectl logs -l app.kubernetes.io/name=kubetix --namespace kubetix

# Check events
kubectl get events --namespace kubetix --sort-by='.lastTimestamp'

# Debug database
kubectl run db-test --rm -it --image=postgres:15-alpine --restart=Never \
  --namespace kubetix \
  -- psql -h <your-db-host> -U kubetix -d kubetix
```

## License

MIT License
