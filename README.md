# repo-auth-iam

Auth & IAM — JWT/OIDC, RBAC/ABAC, MFA, device credentials

## Local

- Install:       npm ci
- Build:       npm run build
- Test:       npm test -- --passWithNoTests

## Runtime

- Health:         GET /health
- Metrics:         GET /metrics

## Bootstrap Root User

On startup, service can bootstrap a root account (idempotent):

- `AUTH_BOOTSTRAP_ROOT_ENABLED` (default: `true`)
- `AUTH_BOOTSTRAP_ROOT_EMAIL` (default: `root`)
- `AUTH_BOOTSTRAP_ROOT_PASSWORD` (default: `admin`)
- `AUTH_BOOTSTRAP_ROOT_ROLE` (default: `admin`)
- `AUTH_BOOTSTRAP_ROOT_RESET_PASSWORD` (default: `false`)
