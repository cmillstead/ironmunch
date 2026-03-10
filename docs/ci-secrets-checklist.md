# CI Secrets Checklist

## Current Status

No secrets are currently required by the CI pipeline.

## If Secrets Are Needed

When adding secrets to the pipeline:

### Setup
1. Go to GitHub repo → Settings → Secrets and variables → Actions
2. Add secret with appropriate scope (repository or environment)
3. Reference in workflow as `${{ secrets.SECRET_NAME }}`

### Security Rules
- Never echo or print secret values in CI logs
- Never use secrets directly in `run:` block expressions — pass through `env:` intermediaries
- Use minimal scope (prefer environment secrets over repo secrets)
- Rotate secrets on a regular schedule
- Document all required secrets in this file

### Audit
- [ ] All secrets are documented below
- [ ] No secrets are hardcoded in workflow files
- [ ] No secrets appear in artifact uploads
- [ ] Secret rotation schedule is defined

## Secret Inventory

| Secret | Scope | Purpose | Rotation |
|--------|-------|---------|----------|
| _(none required)_ | — | — | — |
