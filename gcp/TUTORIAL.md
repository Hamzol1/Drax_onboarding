# Drax Security — GCP Quick Connect

This Cloud Shell tutorial onboards your GCP project with **read-only** access
in under 60 seconds. No browsing the GCP console, no manual IAM clicks.

## What gets created

A single read-only **service account** in your project, named:

```
drax-readonly-<your-tenant-slug>@<your-project>.iam.gserviceaccount.com
```

Bound to these read-only roles at **project scope**:

- `roles/viewer`
- `roles/iam.securityReviewer`
- `roles/securitycenter.adminViewer`

Plus, **at organization or billing-account scope only** (skipped on a
project-only run — see below):

- `roles/billing.viewer` *(needed for FinOps / cost data)*

The script never grants write or delete permissions. You can audit the
service account and bindings at any time:

- **GCP Console → IAM & Admin → Service Accounts** → look for
  `drax-readonly-<your-tenant-slug>`.
- **GCP Console → IAM & Admin → IAM** → filter members by the same email.

## APIs the script enables (idempotent)

The script calls `gcloud services enable` for these APIs — no-op if already
enabled:

- `cloudresourcemanager.googleapis.com`
- `iam.googleapis.com`
- `cloudbilling.googleapis.com`
- `bigquery.googleapis.com`
- `securitycenter.googleapis.com`
- `logging.googleapis.com`
- `monitoring.googleapis.com`

If a Drax service later asks for an API that isn't on this list, re-running
the latest version of the script enables it for you.

## Steps

1. **Paste the 5-line `export` block** from the Drax UI's **GCP Quick
   Connect** tab into this Cloud Shell terminal. It sets `DRAX_TENANT_ID`,
   `DRAX_EXTERNAL_ID`, `DRAX_WEBHOOK_URL`, and `DRAX_TEMPLATE_VER`.
2. Run the onboard script:

   ```bash
   bash onboard.sh
   ```

That's it. **You don't need to run `gcloud config set project` first** —
the script auto-discovers the project:

- If you already have a default project, it uses that.
- If you have exactly one accessible project, it auto-selects + persists it.
- If you have several, it prints a numbered picker — pick the project to onboard.
- If you have zero, it tells you which gcloud account is signed in and
  asks you to authenticate.

To force a specific project without prompts, set
`export DRAX_PROJECT_ID=<project-id>` before running.

## What the script actually does

1. Validates env vars (`DRAX_TENANT_ID`, `DRAX_EXTERNAL_ID`,
   `DRAX_WEBHOOK_URL`).
2. Resolves the target project (auto-discover ladder above).
3. Enables the required APIs.
4. Creates the read-only service account (idempotent — reuses if it exists).
5. Binds the read-only roles at project scope.
6. **Rotates** the SA JSON key — deletes any prior user-managed key, mints
   exactly one fresh key. Avoids the GCP 10-key cap and limits blast radius.
7. POSTs the new credentials (HMAC-signed with your tenant's ExternalId)
   to the Drax registration webhook over TLS.
8. Deletes the local key file from disk.

The key never appears on stdout.

## Organization-wide onboarding (recommended for multi-project orgs)

To onboard **all** projects in your GCP Organization at once, set
`DRAX_ORG_ID` before running:

```bash
export DRAX_ORG_ID=123456789012
bash onboard.sh
```

The script then binds the project-scoped roles **and** `roles/billing.viewer`
at organization scope. Future projects added to the org are automatically
covered without re-running this script.

This matches the "Connect Organization" / "Org Onboarding" pattern used by
Wiz, Orca, and Prisma Cloud — single SA, org-wide read.

## Billing data only (no full org binding)

If you want FinOps data but don't have Org Admin to do an org-wide bind,
use a billing-account-scope binding instead:

```bash
export DRAX_BILLING_ACCOUNT_ID=01ABCD-EF1234-567890
bash onboard.sh
```

The script will bind `roles/billing.viewer` on the billing account.
Requires `roles/billing.admin` on that billing account.

## Project-only mode (the default)

Running with neither `DRAX_ORG_ID` nor `DRAX_BILLING_ACCOUNT_ID` is fine —
Drax will work with full CSPM, CIEM, asset and compliance data on the
selected project. The only thing skipped is FinOps (cost) data, which the
script clearly logs as a NOTE so you know what's missing.

## Re-running

The script is **fully idempotent**:

- **Service account**: looked up by deterministic name
  (`drax-readonly-<your-tenant-slug>`). Reused if it exists; never duplicated.
- **API enables**: `gcloud services enable` is a no-op when already enabled.
- **Role bindings**: `add-iam-policy-binding` is a no-op when the binding
  already exists.
- **JSON key**: every re-run **rotates the key** — Drax deletes prior
  user-managed keys on this SA before issuing a fresh one (10-key cap
  avoidance). System-managed keys (Google's own, used internally) are
  untouched.

Safe to re-run after a Drax template upgrade, a key rotation request, or a
tenant ExternalId rotation.

## Disconnecting

1. Use the **Disconnect** button in the Drax UI to deactivate credentials.
2. Delete the service account on your end:

```bash
gcloud iam service-accounts delete \
  drax-readonly-<your-tenant-slug>@<your-project>.iam.gserviceaccount.com
```
