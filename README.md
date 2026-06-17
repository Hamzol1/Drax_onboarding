# Drax Security — Cloud Onboarding Scripts

Public mirror of the Drax CNAPP customer-side onboarding scripts. Drax's
GCP and Azure Cloud Shell deep links clone this repository so customers
can run a one-command setup that creates a **read-only** principal in
their cloud account and registers it with Drax.

> **Heads up:** these scripts run in **your** cloud shell, in **your**
> account. They are designed to be readable end-to-end before you hit
> Enter — please review before running. The Drax UI generates per-tenant
> environment variables (`DRAX_TENANT_ID`, `DRAX_EXTERNAL_ID`,
> `DRAX_WEBHOOK_URL`, `DRAX_TEMPLATE_VER`) which the script consumes; they
> are also displayed in the Drax UI so you can copy/paste them into the
> shell yourself if you prefer.

## Layout

```text
.
├── docs/
│   └── linkedin-poster/
│       └── privacy-policy.html   # Public privacy policy for LinkedIn Poster (GitHub Pages)
├── gcp/
│   ├── onboard.sh    # Cloud Shell entry point (GCP)
│   └── TUTORIAL.md   # Step-by-step guide rendered in the Cloud Shell tutorial pane
└── azure/
    ├── onboard.sh    # Cloud Shell entry point (Azure)
    └── TUTORIAL.md   # Step-by-step guide rendered in the Cloud Shell tutorial pane
```

## LinkedIn Poster privacy policy

The **LinkedIn Poster** Windows app (Drax Security) uses this public URL for the LinkedIn Developer Portal **Privacy policy URL** field:

**https://github.com/Hamzol1/Drax_onboarding/blob/main/PRIVACY-LINKEDIN-POSTER.md**

Rendered HTML (GitHub Pages, after Pages is enabled on the repo):  
**https://hamzol1.github.io/Drax_onboarding/linkedin-poster/privacy-policy.html**

Sources: [`PRIVACY-LINKEDIN-POSTER.md`](PRIVACY-LINKEDIN-POSTER.md) · [`docs/linkedin-poster/privacy-policy.html`](docs/linkedin-poster/privacy-policy.html)

## What the scripts do

### GCP (`gcp/onboard.sh`)

- Enables read-only APIs (resourcemanager, iam, billing, securitycenter,
  logging, monitoring, bigquery).
- Creates a service account `drax-readonly-<tenant-slug>` with the
  Wiz/Orca-equivalent read-only role bundle:
  - `roles/viewer`
  - `roles/iam.securityReviewer`
  - `roles/billing.viewer`
  - `roles/securitycenter.adminViewer`
- Rotates the user-managed JSON key (deletes prior keys before issuing a
  new one — avoids GCP's 10-key cap on re-runs).
- Posts the SA email + key to Drax over TLS, HMAC-signed with the
  per-tenant ExternalId. The key never appears on stdout.

### Azure (`azure/onboard.sh`)

- Creates an Entra ID Application + Service Principal
  `drax-readonly-<tenant-slug>` with **Reader** + **Security Reader** built-in
  RBAC roles at the subscription scope (org-wide via management group when
  `DRAX_MGMT_GROUP_ID` is set).
- Rotates the client secret on every re-run via
  `az ad app credential reset` (no `--append` — single live secret).
- Posts the SP credentials to Drax over TLS, HMAC-signed.

## Idempotency

Both scripts are **fully idempotent**. Service-account / service-principal
names derive from the tenant slug (not the rotating ExternalId), so rerunning
after a credential rotation reuses the existing principal and rotates only
the secret/key. See each provider's `TUTORIAL.md` for details.

## Security

- Scripts are read by the customer in their own Cloud Shell — no opaque
  binaries, no curl-pipe-bash from a third party. Source of truth lives
  here; the Drax UI shows the same URL you'd open from this README.
- All network IO out of the scripts is HTTPS to a single endpoint:
  `https://<your-drax-host>/api/v1/webhooks/cloud-onboarding`. The
  `DRAX_WEBHOOK_URL` env var is what the script POSTs to — verify it
  matches the host you onboarded with.
- Payloads are HMAC-SHA256 signed with the per-tenant `ExternalId`. The
  Drax backend verifies the signature against its stored ExternalId before
  accepting the registration.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
