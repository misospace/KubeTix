# KubeTix Kubernetes Deployment

Self-host KubeTix on your Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (v1.25+)
- kubectl configured
- Ingress controller (nginx, traefik, etc.)
- TLS certificates (cert-manager recommended)

## Quick Start

### 1. Create Namespace

```bash
kubectl create namespace kubetix
```

### 2. Create Secrets

```bash
# Generate secret key
kubectl create secret generic kubetix-secrets \
  --namespace kubetix \
  --from-literal=secret-key=$(openssl rand -hex 32) \
  --from-literal=database-url=postgresql://kubetix:kubetix@kubetix-db:5432/kubetix

# Create database credentials
kubectl create secret generic kubetix-db-credentials \
  --namespace kubetix \
  --from-literal=username=kubetix \
  --from-literal=password=kubetix
```

### 3. Deploy with Helm (Recommended)

```bash
# Add Helm repo
helm repo add kubetix https://joryirving.github.io/kubetix-helm
helm repo update

# Install
helm install kubetix kubetix/kubetix \
  --namespace kubetix \
  --set api.replicas=1 \
  --set web.replicas=1 \
  --set db.postgresql.persistence.size=10Gi
```

### 4. Deploy with kubectl

```bash
# Apply all manifests
kubectl apply -f manifests/

# Wait for deployment
kubectl rollout status deployment/kubetix-api -n kubetix
kubectl rollout status deployment/kubetix-web -n kubetix
```

## Architecture

```
┌─────────────┐
│   Ingress   │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────┐
│  kubetix    │────▶│  kubetix    │
│    web      │     │    api      │
└─────────────┘     └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  kubetix-db │
                    │ (PostgreSQL)│
                    └─────────────┘
```

## Components

### kubetix-api
- FastAPI backend
- JWT authentication
- PostgreSQL database
- 1-3 replicas recommended

### kubetix-web
- Next.js frontend
- Static export (can run without Node.js)
- 1-2 replicas recommended

### kubetix-db
- PostgreSQL 15
- Persistent storage (10GB+)
- Daily backups recommended

## Configuration

### Environment Variables

#### API
```yaml
DATABASE_URL: postgresql://kubetix:kubetix@kubetix-db:5432/kubetix
KUBETIX_SECRET_KEY: <generated-secret>
KUBECONFIG: /etc/kubeconfig/config (optional)
```

#### Web
```yaml
NEXT_PUBLIC_API_URL: http://kubetix-api:8000
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubetix-config
  namespace: kubetix
data:
  API_URL: http://kubetix-api:8000
  MAX_GRANT_HOURS: "720"
  DEFAULT_GRANT_HOURS: "24"
```

## Ingress Configuration

### nginx Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubetix-ingress
  namespace: kubetix
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - kubetix.yourdomain.com
    secretName: kubetix-tls
  rules:
  - host: kubetix.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubetix-web
            port:
              number: 80
```

### cert-manager TLS

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kubetix-tls
  namespace: kubetix
spec:
  secretName: kubetix-tls
  duration: 2160h # 90 days
  renewBefore: 360h # 15 days
  subject:
    organizations:
    - Your Organization
  commonName: kubetix.yourdomain.com
  issuers:
  - clusterIssuer: letsencrypt-prod
```

## Database Setup

### Option 1: External PostgreSQL

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kubetix-db-external
  namespace: kubetix
type: Opaque
stringData:
  username: kubetix
  password: <secure-password>
  host: <external-db-host>
  port: "5432"
  database: kubetix
```

### Option 2: Bitnami PostgreSQL Helm Chart

```yaml
db:
  postgresql:
    auth:
      username: kubetix
      password: kubetix
      database: kubetix
    persistence:
      size: 10Gi
    resources:
      requests:
        memory: 256Mi
        cpu: 100m
      limits:
        memory: 512Mi
        cpu: 500m
```

## Resource Limits

### API

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "500m"
```

### Web

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "500m"
```

### Database

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

## Scaling

### Horizontal Pod Autoscaler (HPA)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: kubetix-api-hpa
  namespace: kubetix
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: kubetix-api
  minReplicas: 1
  maxReplicas: 5
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Backups

### Database Backups

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kubetix-backup-credentials
  namespace: kubetix
stringData:
  AWS_ACCESS_KEY_ID: <key>
  AWS_SECRET_ACCESS_KEY: <secret>
```

```yaml
apiVersion: batch.volcano.sh/v1alpha1
kind: Job
metadata:
  name: kubetix-db-backup
  namespace: kubetix
spec:
  tasks:
  - replicas: 1
    name: backup
    template:
      spec:
        containers:
        - name: backup
          image: postgres:15-alpine
          command: ["sh", "-c", "pg_dump -h kubetix-db -U kubetix kubetix > /backup/kubetix-$(date +%Y%m%d).sql"]
          volumeMounts:
          - name: backup
            mountPath: /backup
        volumes:
        - name: backup
          persistentVolumeClaim:
            claimName: kubetix-backup-pvc
```

## Monitoring

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kubetix-api
  namespace: kubetix
spec:
  selector:
    matchLabels:
      app: kubetix-api
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Grafana Dashboard

Import dashboard ID `12345` (or create custom) with these metrics:
- `kubetix_api_requests_total`
- `kubetix_api_request_duration_seconds`
- `kubetix_grants_active`
- `kubetix_database_connections`

## Troubleshooting

### API won't start

```bash
# Check logs
kubectl logs deployment/kubetix-api -n kubetix

# Check secrets
kubectl get secrets kubetix-secrets -n kubetix -o yaml

# Verify database connection
kubectl run debug --rm -it --image=postgres:15-alpine --restart=Never \
  --namespace kubetix \
  -- psql -h kubetix-db -U kubetix -d kubetix
```

### Web UI shows 502

```bash
# Check API health
kubectl port-forward svc/kubetix-api 8000 -n kubetix
curl http://localhost:8000/health

# Check ingress
kubectl describe ingress kubetix-ingress -n kubetix
```

### Database connection errors

```bash
# Check database pod
kubectl get pods -n kubetix -l app.kubernetes.io/name=postgresql

# Check database logs
kubectl logs deployment/kubetix-db -n kubetix

# Verify credentials
kubectl get secret kubetix-db-credentials -n kubetix -o yaml
```

---

## 🔐 Authentik/OIDC Integration

KubeTix supports authentication via any OIDC provider, including **Authentik**, Keycloak, Okta, Google, GitHub, and Azure AD.

### 1. Authentik Setup

#### Create OAuth2 Provider in Authentik

1. Log into Authentik admin panel
2. Go to **Applications > Providers**
3. Create new **OAuth2/OpenID Provider**
4. Configure:
   - **Name**: KubeTix
   - **Client ID**: `kubetix`
   - **Client Secret**: Generate secure secret
   - **Authorization flow**: Default
   - **Signing Key**: Select your certificate
   - **Redirect URIs**:
     - `http://localhost:8000/api/v1/auth/oidc/callback`
     - `https://kubetix.yourdomain.com/api/v1/auth/oidc/callback`

#### Create Application in Authentik

1. Go to **Applications > Applications**
2. Create new Application:
   - **Name**: KubeTix
   - **Slug**: kubetix
   - **Provider**: Select the provider you created
   - **Launch URL**: `https://kubetix.yourdomain.com`

### 2. Kubernetes Secrets

```bash
# Create OIDC secrets
kubectl create secret generic kubetix-oidc \
  --namespace kubetix \
  --from-literal=oidc-client-secret=<your-client-secret>
```

### 3. Update API Deployment

```yaml
env:
- name: OIDC_ENABLED
  value: "true"
- name: OIDC_ISSUER
  value: "https://authentik.yourdomain.com"
- name: OIDC_CLIENT_ID
  value: "kubetix"
- name: OIDC_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: kubetix-oidc
      key: oidc-client-secret
- name: OIDC_REDIRECT_URI
  value: "https://kubetix.yourdomain.com/api/v1/auth/oidc/callback"
```

### 4. Update Web Deployment

```yaml
env:
- name: NEXT_PUBLIC_OIDC_ENABLED
  value: "true"
- name: NEXT_PUBLIC_OIDC_ISSUER
  value: "https://authentik.yourdomain.com"
```

### 5. Authentik Ingress (for OIDC)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authentik-ingress
  namespace: kubetix
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - authentik.yourdomain.com
    secretName: authentik-tls
  rules:
  - host: authentik.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: authentik-server
            port:
              number: 80
```

### 6. Complete Authentik + KubeTix Stack

```yaml
# docker-compose.yml for local testing
version: '3.8'

services:
  authentik:
    image: ghcr.io/goauthentik/server:latest
    container_name: authentik
    restart: unless-stopped
    ports:
      - "9000:9000"
      - "9443:9443"
    environment:
      - AUTHENTIK_SECRET_KEY=changeme
      - AUTHENTIK_LOG_LEVEL=info
    volumes:
      - ./authentik/data:/var/lib/authentik

  kubetix-db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=kubetix
      - POSTGRES_PASSWORD=kubetix
      - POSTGRES_DB=kubetix
    volumes:
      - ./kubetix/db:/var/lib/postgresql/data

  kubetix-api:
    image: ghcr.io/joryirving/kubetix-api:latest
    environment:
      - DATABASE_URL=postgresql://kubetix:kubetix@kubetix-db:5432/kubetix
      - OIDC_ENABLED=true
      - OIDC_ISSUER=http://localhost:9000
      - OIDC_CLIENT_ID=kubetix
      - OIDC_CLIENT_SECRET=changeme
      - OIDC_REDIRECT_URI=http://localhost:8000/api/v1/auth/oidc/callback
    depends_on:
      - kubetix-db

  kubetix-web:
    image: ghcr.io/joryirving/kubetix-web:latest
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
      - NEXT_PUBLIC_OIDC_ENABLED=true
      - NEXT_PUBLIC_OIDC_ISSUER=http://localhost:9000
    ports:
      - "3000:3000"
    depends_on:
      - kubetix-api
```

### 7. Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `OIDC_ENABLED` | Enable OIDC auth | `true` |
| `OIDC_ISSUER` | OIDC provider URL | `https://authentik.yourdomain.com` |
| `OIDC_CLIENT_ID` | OAuth client ID | `kubetix` |
| `OIDC_CLIENT_SECRET` | OAuth client secret | `secret-from-authentik` |
| `OIDC_REDIRECT_URI` | Callback URL | `https://kubetix.yourdomain.com/api/v1/auth/oidc/callback` |
| `OIDC_SCOPES` | OAuth scopes | `openid profile email` |

### 8. Supported Providers

KubeTix supports OIDC/OAuth2 with:

- ✅ **Authentik** (recommended for self-hosted)
- ✅ **Keycloak**
- ✅ **Okta**
- ✅ **Google Workspace**
- ✅ **GitHub OAuth**
- ✅ **Azure AD**
- ✅ **Any standard OIDC provider**

### 9. Troubleshooting OIDC

```bash
# Check OIDC configuration
kubectl exec deployment/kubetix-api -n kubetix -- env | grep OIDC

# Test OIDC discovery
curl https://authentik.yourdomain.com/.well-known/openid-configuration

# Check auth logs
kubectl logs deployment/kubetix-api -n kubetix | grep -i oidc
```

---

## Maintenance

### Rolling Update

```bash
kubectl rollout restart deployment/kubetix-api -n kubetix
kubectl rollout restart deployment/kubetix-web -n kubetix
```

### Database Migration

```bash
# Run migrations
kubectl run kubetix-migrate --rm -it --image=kubetix-api:latest --restart=Never \
  --namespace kubetix \
  -- python -m alembic upgrade head
```

### Backup and Restore

```bash
# Backup
kubectl exec deployment/kubetix-db -n kubetix -- pg_dump -U kubetix kubetix > backup.sql

# Restore
kubectl exec -i deployment/kubetix-db -n kubetix -- psql -U kubetix kubetix < backup.sql
```

## Security Best Practices

1. **Use TLS everywhere** - Enable HTTPS with cert-manager
2. **Network policies** - Restrict pod-to-pod communication
3. **RBAC** - Use least privilege for service accounts
4. **Secrets management** - Use external secrets manager (Vault, AWS Secrets Manager)
5. **Regular updates** - Keep images and dependencies updated
6. **Audit logging** - Enable Kubernetes audit logs
7. **Resource limits** - Prevent resource exhaustion

## Support

- **Issues**: https://github.com/joryirving/KubeTix/issues
- **Docs**: https://github.com/joryirving/KubeTix/blob/main/kubetix-api/README.md
- **Community**: Join our Discord (link in repo)
