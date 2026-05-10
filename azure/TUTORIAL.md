# Drax Security — Azure Quick Connect

Complete in **under 60 seconds**. You're already in Azure Cloud Shell — run
the command below.

## Why Cloud Shell (not Deploy-to-Azure)

Creating an Azure AD service principal requires Microsoft Graph permissions
that Azure RBAC alone cannot grant. Cloud Shell runs as your signed-in
identity, which already has those permissions during the onboarding session.

This is the same pattern Wiz and Orca Security use for Azure onboarding.

## What this does

1. Creates an Azure AD service principal named `drax-readonly-<your-tenant-slug>`
   (deterministic — survives ExternalId rotations).
2. Issues a fresh client secret (24-month expiry, auto-rotated by Drax at
   month 22).
3. Assigns four read-only RBAC roles at subscription scope:
   - **Reader** — full subscription read access for inventory.
   - **Cost Management Reader** — FinOps insights.
   - **Security Reader** — Defender for Cloud signals.
   - **Storage Blob Data Reader** — sensitive data discovery.
4. Posts the credentials directly to Drax over HMAC-signed TLS. **Nothing is
   ever printed to your terminal.**

## Run

```bash
bash <(curl -sSL "$DRAX_GIT_REPO/raw/main/azure/onboard.sh")
```

Optional: scope to your entire management group instead of one subscription:

```bash
DRAX_MGMT_GROUP_ID="<your-mgmt-group-id>" \
    bash <(curl -sSL "$DRAX_GIT_REPO/raw/main/azure/onboard.sh")
```

## Re-run safely

The script is **fully idempotent** — same outcome on every run:
- **Service principal**: looked up by deterministic display name; reused if
  found, created otherwise. ExternalId rotation does NOT rotate the SP name,
  so role assignments + audit history stay continuous.
- **Client secret**: every re-run rotates via `az ad app credential reset`
  (no `--append`), invalidating any prior secret. Limits blast radius of a
  leaked secret to the re-run interval.
- **RBAC role assignments**: `az role assignment create` errors are
  swallowed when the binding already exists, leaving the assignment intact.

Safe to re-run after a Drax template upgrade, a credential rotation request,
or a tenant ExternalId rotation.

## What if I see "Insufficient privileges"?

Your account needs:
- **Application Administrator** (or Cloud App Admin / Global Admin) in Azure AD
- **Owner** or **User Access Administrator** on the subscription / mgmt group

Ask your AAD admin to run this script in their Cloud Shell session.
