# repo-auth-iam

Auth & IAM — JWT/OIDC, RBAC/ABAC, MFA, device credentials

## Local

- Install:       npm ci
- Build:       npm run build
- Test:       npm test -- --passWithNoTests

## Runtime

- Health:         GET /health
- Metrics:         GET /metrics

## Bootstrap First Admin

Recommended install-time flow:

```bash
npm run build
AUTH_BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
AUTH_BOOTSTRAP_ADMIN_PASSWORD='replace-with-strong-password' \
npm run bootstrap:admin
```

Optional startup bootstrap (explicit opt-in, idempotent):

- `AUTH_BOOTSTRAP_ROOT_ENABLED` (default: `false`)
- `AUTH_BOOTSTRAP_ROOT_EMAIL` (required when enabled)
- `AUTH_BOOTSTRAP_ROOT_PASSWORD` (required when enabled)
- `AUTH_BOOTSTRAP_ROOT_ROLE` (default: `admin`)
- `AUTH_BOOTSTRAP_ROOT_RESET_PASSWORD` (default: `false`)
