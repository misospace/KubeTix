# Backup & Restore Runbook

## Overview

KubeTix stores grants and audit logs in either SQLite (default) or PostgreSQL.
This runbook covers backup and restore procedures for both backends.

**Critical:** SQLite is only supported with `replicaCount: 1` and local/persistent
storage. Multi-replica deployments require PostgreSQL.

---

## SQLite Backup & Restore

### Backup

#### Automatic (via Persistent Volume)

If using a Kubernetes PVC for SQLite (`database.sqlite.persistence.enabled: true`):

```bash
# List PVCs
kubectl get pvc -n <namespace> | grep kubetix

# Snapshot the PVC using Velero or Kubernetes VolumeSnapshot
velero snapshot create kubetix-sqlite-$(date +%Y%m%d-%H%M) \
  --include-namespaces <namespace> \
  --include-resources persistentvolumeclaims
```

#### Manual (file-level copy)

```bash
# Exec into the pod and copy the database
kubectl exec -n <namespace> deploy/kubetix-api -- cp /app/data/kubetix.db /tmp/kubetix.db
kubectl cp <namespace>/kubetix-api-<pod-hash>:/tmp/kubetix.db ./kubetix.db

# Verify the copy
sqlite3 ./kubetix.db "SELECT count(*) FROM grants;"
```

#### Scheduled backups (cronjob)

Create a cronjob to back up the database daily:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kubetix-sqlite-backup
  namespace: <namespace>
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: alpine/sqlite:latest
              command: ["/bin/sh", "-c"]
              args:
                - |
                  BACKUP_DATE=$(date +%Y%m%d-%H%M)
                  kubectl exec deploy/kubetix-api -- cp /app/data/kubetix.db /tmp/kubetix-${BACKUP_DATE}.db
                  kubectl cp <namespace>/kubetix-api-$(kubectl get pods -n <namespace> -l app.kubernetes.io/name=kubetix-api -o jsonpath='{.items[0].metadata.name}'):/tmp/kubetix-${BACKUP_DATE}.db ./backups/kubetix-${BACKUP_DATE}.db
              volumeMounts:
                - name: backup-volume
                  mountPath: /backups
          volumes:
            - name: backup-volume
              persistentVolumeClaim:
                claimName: kubetix-backup-pvc
          restartPolicy: OnFailure
```

### Restore

```bash
# Stop the API to prevent writes during restore
kubectl scale deployment kubetix-api --replicas=0 -n <namespace>

# Replace the database file
kubectl cp ./kubetix.db.backup <namespace>/kubetix-api-<pod-hash>:/app/data/kubetix.db

# Verify integrity
kubectl exec -n <namespace> deploy/kubetix-api -- sqlite3 /app/data/kubetix.db "PRAGMA integrity_check;"

# Restart the API
kubectl scale deployment kubetix-api --replicas=1 -n <namespace>
```

---

## PostgreSQL Backup & Restore

### Backup

#### pg_dump (single-database)

```bash
# Full dump
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  pg_dump -h <postgres-host> -U kubetix -d kubetix > kubetix-full-$(date +%Y%m%d-%H%M).sql

# Schema-only dump (for migration testing)
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  pg_dump -h <postgres-host> -U kubetix -d kubetix --schema-only > kubetix-schema.sql

# With compression
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  pg_dump -h <postgres-host> -U kubetix -d kubetix --format=custom -f kubetix-$(date +%Y%m%d-%H%M).dump
```

#### Automated backups with pgBackRest (recommended for production)

If using the PostgreSQL Helm subchart:

```bash
# Create a backup
kubectl exec -n <namespace> statefulset/postgresql -- \
  /backups/run_pgbackrest.sh backup full kubetix

# List available backups
kubectl exec -n <namespace> statefulset/postgresql -- \
  pgbackrest info
```

### Restore

```bash
# For pg_dump SQL files
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  psql -h <postgres-host> -U kubetix -d kubetix -f kubetix-full-YYYYMMDD-HHMM.sql

# For pg_dump custom format
PGPASSWORD=$(kubectl get secret kubetix-db-secret -n <namespace> -o jsonpath='{.data.password}' | base64 -d) \
  pg_restore -h <postgres-host> -U kubetix -d kubetix --clean --if-exists kubetix.dump

# For pgBackRest point-in-time recovery
kubectl exec -n <namespace> statefulset/postgresql -- \
  pgbackrest --stanza=kubetix restore --type=time \
    --target="2026-06-10 01:59:00 UTC"
```

---

## Backup Verification

After every restore, verify data integrity:

```sql
-- SQLite
sqlite3 kubetix.db "SELECT count(*) FROM grants WHERE expires_at > datetime('now');"
sqlite3 kubetix.db "SELECT count(*) FROM audit_log;"

-- PostgreSQL
psql -U kubetix -d kubetix -c "SELECT count(*) FROM grants WHERE expires_at > now();"
psql -U kubetix -d kubetix -c "SELECT count(*) FROM audit_log;"
```

## Retention Policy

| Backend | Recommended Retention | Method |
|---------|----------------------|--------|
| SQLite | 7 daily backups on PV | PVC snapshot or manual copy |
| PostgreSQL | 30 days with pgBackRest | Automated pgBackRest retention |

## Important Notes

1. **Always back up the secret key alongside the database.** Without it,
   encrypted kubeconfigs cannot be decrypted after restore.
2. **Test restores quarterly.** A backup that hasn't been tested is not a backup.
3. **Never store backups in the same cluster** as the source database.
4. **Encrypt backup files at rest** if stored externally (e.g., S3, GCS).
