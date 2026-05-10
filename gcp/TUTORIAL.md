# Drax Security — GCP Quick Connect

This Cloud Shell tutorial onboards your GCP project with **read-only** access
in under 60 seconds.

## What gets created

A single service account in your project with these read-only roles:

- `roles/viewer`
- `roles/iam.securityReviewer`
- `roles/billing.viewer`
- `roles/securitycenter.adminViewer`

The script never grants write or delete permissions. You can audit the binding
in IAM → Service Accounts after onboarding.

## Steps

1. **Paste the 5-line `export` block** shown in the Drax UI's GCP Quick Connect
   tab into this Cloud Shell terminal. It sets `DRAX_TENANT_ID`,
   `DRAX_EXTERNAL_ID`, `DRAX_WEBHOOK_URL`, and `DRAX_TEMPLATE_VER` — the
   per-tenant values the script needs.
2. Make sure the right project is selected:

   ```bash
   gcloud config set project YOUR_PROJECT_ID
   ```
3. Run the onboard script:

   ```bash
   bash onboard.sh
   ```

That's it. The script:

1. Enables the necessary APIs (idempotent).
2. Creates the read-only service account.
3. Binds the four roles above.
4. Generates a JSON key.
5. Uploads the key + project metadata to Drax over TLS, signed with your
   tenant's ExternalId so we can verify the call came from your Cloud Shell.

The key never appears on stdout and is deleted from the local filesystem when
the script exits.

## Organization-wide onboarding

To onboard all projects in your GCP Organization, set `DRAX_ORG_ID` before
running:

```bash
export DRAX_ORG_ID=123456789012
bash onboard.sh
```

The script will additionally bind the four roles at the organization scope.

## Re-running

The script is **fully idempotent** — same outcome whether it's the first run,
the tenth, or after a Drax template upgrade:

- **Service account**: looked up by deterministic name (`drax-readonly-<your-tenant-slug>`).
  Reused if it already exists; never duplicated. ExternalId rotation does NOT
  rotate the SA name, so role bindings + audit history stay continuous.
- **API enables**: `gcloud services enable` is a no-op when already enabled.
- **Role bindings**: `add-iam-policy-binding` is a no-op when the binding
  already exists.
- **JSON key**: every re-run **rotates the key** — Drax deletes prior
  user-managed keys on this SA before issuing a fresh one. This avoids the
  GCP 10-key cap and limits the blast radius of any leaked key to the
  re-run interval. SYSTEM_MANAGED keys (Google's own, used internally) are
  untouched.

Safe to re-run after a Drax template upgrade, a key rotation request, or a
tenant ExternalId rotation.

## Disconnecting

Use the **Disconnect** button in the Drax UI to deactivate credentials, then
delete the service account in IAM:

```bash
gcloud iam service-accounts delete drax-readonly-<your-tenant-slug>@YOUR_PROJECT_ID.iam.gserviceaccount.com
```
