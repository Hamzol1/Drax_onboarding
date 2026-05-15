#!/usr/bin/env bash
###############################################################################
# Drax Security — Azure Quick Connect onboard script (Cloud Shell)
#
# Why Cloud Shell, not Deploy-to-Azure (ARM):
#   ARM deployment scripts run as a managed identity. Creating an AAD service
#   principal (`az ad sp create-for-rbac`) requires Microsoft Graph perms
#   ("Application.ReadWrite.OwnedBy" or higher) which are NOT granted by any
#   Azure RBAC role — they require AAD admin consent. Cloud Shell runs as the
#   signed-in user (who is typically a Global Admin during onboarding) and
#   already has those Graph perms. Wiz/Orca use the same pattern.
#
# What this script does (idempotent):
#   1. Resolves subscription / AAD tenant context.
#   2. Creates (or reuses) an AAD application + service principal:
#        drax-readonly-{ext_short}  (display name)
#   3. Issues a fresh client secret with a 24-month expiry (rotated by the
#      Drax credential health job at 22 months).
#   4. Registers required Azure Resource Providers (Microsoft.Security,
#      Microsoft.PolicyInsights, Microsoft.Insights) — idempotent. Without
#      these registered, Prowler's Defender / policy / monitoring CIS checks
#      return 404 "provider not registered" and skip silently.
#   5. Assigns the four read-only RBAC roles at subscription scope:
#        - Reader                              (acdd72a7-...)
#        - Cost Management Reader              (72fafb9e-...)
#        - Security Reader                     (39bc4728-...)
#        - Storage Blob Data Reader            (2a2b9908-...)
#   6. Assigns the Azure AD "Global Reader" role at tenant scope via Microsoft
#      Graph. Required for Prowler CIS §1.x checks (MFA, Conditional Access,
#      password policies). Graceful skip with warning if caller lacks
#      Privileged Role Administrator / Global Administrator. Idempotent.
#   7. POSTs the credentials (HMAC-signed with the Drax ExternalId) to Drax's
#      registration webhook. Customer never copy/pastes anything.
#
# Required env (Cloud Shell deep link supplies these):
#   DRAX_TENANT_ID        — Drax tenant slug
#   DRAX_EXTERNAL_ID      — drax-{slug}-azure-{16hex}
#   DRAX_WEBHOOK_URL      — https://<api>/api/v1/webhooks/cloud-onboarding
#   DRAX_TEMPLATE_VER     — semver (default 1.1.0)
#
# Optional:
#   DRAX_SUBSCRIPTION_ID  — defaults to current `az account show` selection
#   DRAX_MGMT_GROUP_ID    — set to onboard at management-group scope (org-wide)
#
# Exit 0 on success; non-zero with detailed error on failure. Secrets are
# never echoed to stdout — only sent to the Drax webhook over TLS.
###############################################################################

set -euo pipefail

err() { echo "[drax] ERROR: $*" >&2; exit 1; }
log() { echo "[drax] $*"; }

command -v az      >/dev/null 2>&1 || err "az (Azure CLI) not found. Run inside Azure Cloud Shell."
command -v jq      >/dev/null 2>&1 || err "jq not found."
command -v curl    >/dev/null 2>&1 || err "curl not found."
command -v openssl >/dev/null 2>&1 || err "openssl not found (required for HMAC)."

DRAX_TENANT_ID="${DRAX_TENANT_ID:-}"
DRAX_EXTERNAL_ID="${DRAX_EXTERNAL_ID:-}"
DRAX_WEBHOOK_URL="${DRAX_WEBHOOK_URL:-}"
DRAX_TEMPLATE_VER="${DRAX_TEMPLATE_VER:-1.1.0}"

[[ -n "$DRAX_TENANT_ID"   ]] || err "DRAX_TENANT_ID not set."
[[ -n "$DRAX_EXTERNAL_ID" ]] || err "DRAX_EXTERNAL_ID not set."
[[ -n "$DRAX_WEBHOOK_URL" ]] || err "DRAX_WEBHOOK_URL not set."

[[ "$DRAX_EXTERNAL_ID" =~ ^drax-[a-z0-9-]+-azure-[a-f0-9]{16}$ ]] \
    || err "DRAX_EXTERNAL_ID format invalid (expected drax-<slug>-azure-<16hex>)."

# Resolve subscription + tenant from active az session unless overridden.
ACCT_JSON=$(az account show --output json 2>/dev/null || true)
[[ -n "$ACCT_JSON" ]] || err "Not logged into Azure. Run 'az login' first."

SUBSCRIPTION_ID="${DRAX_SUBSCRIPTION_ID:-$(echo "$ACCT_JSON" | jq -r .id)}"
AAD_TENANT_ID="$(echo "$ACCT_JSON" | jq -r .tenantId)"

[[ -n "$SUBSCRIPTION_ID" && "$SUBSCRIPTION_ID" != "null" ]] || err "Could not resolve subscription id."
[[ -n "$AAD_TENANT_ID"   && "$AAD_TENANT_ID"   != "null" ]] || err "Could not resolve AAD tenant id."

EXT_SHORT="${DRAX_EXTERNAL_ID##*-}"   # audit only
# AAD app display name derives from the tenant slug, NOT the ExternalId hex.
# Same rationale as the GCP script: rotating ExternalId must NOT orphan the
# App Registration + RBAC role assignments. AAD display name has no hard
# length cap that matters here, but we sanitize for parity / safety.
SP_SLUG="$(echo "$DRAX_TENANT_ID" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/-\+/-/g; s/^-//; s/-$//')"
SP_SLUG="${SP_SLUG:0:32}"
SP_SLUG="${SP_SLUG%-}"
[[ -n "$SP_SLUG" ]] || err "tenant_id collapses to empty — cannot derive SP name."
SP_NAME="drax-readonly-${SP_SLUG}"

log "Subscription:   $SUBSCRIPTION_ID"
log "AAD tenant:     $AAD_TENANT_ID"
log "Service princ:  $SP_NAME"
log "Drax tenant:    $DRAX_TENANT_ID"
log "Template ver:   $DRAX_TEMPLATE_VER"

###############################################################################
# 1. Register required Azure Resource Providers (idempotent).
#    Without these registered in the subscription, Prowler's CIS Azure checks
#    for Microsoft Defender, Policy compliance, and monitoring return
#    "NoRegisteredProviderFound" / 404 and skip silently — identical in impact
#    to the GCP serviceusage.googleapis.com disabled problem.
#    `az provider register --wait` is idempotent (no-op if already registered).
###############################################################################
log "Registering required Azure resource providers (idempotent)..."
for ns in \
    Microsoft.Security \
    Microsoft.PolicyInsights \
    Microsoft.Insights; do
    az provider register \
        --namespace "$ns" \
        --subscription "$SUBSCRIPTION_ID" \
        --wait \
        --output none 2>/dev/null \
        || log "  WARN: could not register $ns (checks using this provider may be partial)"
done

###############################################################################
# 2. Create or reuse AAD app + SP. We do NOT pass `--skip-assignment` —
#    it was REMOVED in Azure CLI 2.43+ (Nov 2022) and now errors out.
#    The default behaviour since 2.43 is "no implicit role assignment", so
#    omission gives us the same outcome we want (explicit RBAC step #2).
###############################################################################
EXISTING_APP_ID=$(az ad app list --display-name "$SP_NAME" --query '[0].appId' -o tsv 2>/dev/null || true)

if [[ -n "$EXISTING_APP_ID" && "$EXISTING_APP_ID" != "null" ]]; then
    log "AAD app already exists ($EXISTING_APP_ID). Issuing fresh secret..."
    APP_ID="$EXISTING_APP_ID"
    # `--display-name` is the canonical flag (Credential Arguments group) for
    # labelling the new password credential; `--years 2` produces a 24-month
    # expiry. Reference:
    # https://learn.microsoft.com/en-us/cli/azure/ad/app/credential#az-ad-app-credential-reset
    SECRET_JSON=$(az ad app credential reset \
        --id "$APP_ID" \
        --display-name "drax-quickconnect" \
        --years 2 \
        -o json)
    CLIENT_ID=$(echo "$SECRET_JSON" | jq -r .appId)
    CLIENT_SECRET=$(echo "$SECRET_JSON" | jq -r .password)
else
    log "Creating new SP $SP_NAME..."
    # `--years 2` controls secret lifetime. No `--scopes` / `--role` so the
    # CLI does not assign anything implicitly; we drive RBAC ourselves below.
    SP_JSON=$(az ad sp create-for-rbac \
        --name "$SP_NAME" \
        --years 2 \
        -o json)
    CLIENT_ID=$(echo "$SP_JSON" | jq -r .appId)
    CLIENT_SECRET=$(echo "$SP_JSON" | jq -r .password)
fi

[[ -n "$CLIENT_ID" && "$CLIENT_ID" != "null"   ]] || err "Failed to obtain CLIENT_ID."
[[ -n "$CLIENT_SECRET" && "$CLIENT_SECRET" != "null" ]] || err "Failed to obtain CLIENT_SECRET."

# Wait for AAD propagation — `az ad sp create-for-rbac` returns before the SP
# is queryable in some regions. Up to 60s of polling.
SP_OBJECT_ID=""
for i in {1..12}; do
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)
    [[ -n "$SP_OBJECT_ID" ]] && break
    sleep 5
done
[[ -n "$SP_OBJECT_ID" ]] || err "SP object id not visible after 60s — AAD replication delay?"

###############################################################################
# 3. Assign read-only RBAC roles. Subscription scope is the default; org scope
#    is optional (DRAX_MGMT_GROUP_ID).
###############################################################################
ROLES=(
    "acdd72a7-3385-48ef-bd42-f606fba81ae7"   # Reader
    "72fafb9e-0641-4937-9268-a91bfd8191a3"   # Cost Management Reader
    "39bc4728-0917-49c7-9d2c-d95423bc2eb4"   # Security Reader
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"   # Storage Blob Data Reader
)

SCOPE="/subscriptions/$SUBSCRIPTION_ID"
if [[ -n "${DRAX_MGMT_GROUP_ID:-}" ]]; then
    SCOPE="/providers/Microsoft.Management/managementGroups/$DRAX_MGMT_GROUP_ID"
    log "Using management-group scope: $SCOPE"
fi

for role_id in "${ROLES[@]}"; do
    log "Assigning role $role_id at scope $SCOPE..."
    # `|| true` handles the idempotent re-run case (role already assigned).
    az role assignment create \
        --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "$role_id" \
        --scope "$SCOPE" >/dev/null 2>&1 || true
done

###############################################################################
# 4. Assign Azure AD "Global Reader" role at tenant scope (idempotent).
#    Required for Prowler CIS Azure §1.x checks: MFA enforcement, Conditional
#    Access policies, password policies, guest user settings.
#    Role def GUID f2ef992c-3afb-46b9-b7cf-a126ee74c451 is stable / built-in.
#    Requires caller to have Privileged Role Administrator or Global Admin in
#    the AAD tenant — graceful skip with warning if missing. If the role is
#    already assigned the Graph API returns 400 "already assigned", which we
#    also suppress (idempotent).
###############################################################################
GLOBAL_READER_ROLE_ID="f2ef992c-3afb-46b9-b7cf-a126ee74c451"
log "Assigning Azure AD 'Global Reader' role at tenant scope (CIS §1.x checks)..."
az rest \
    --method POST \
    --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"@odata.type\":\"#microsoft.graph.unifiedRoleAssignment\",\"roleDefinitionId\":\"$GLOBAL_READER_ROLE_ID\",\"principalId\":\"$SP_OBJECT_ID\",\"directoryScopeId\":\"/\"}" \
    --output none 2>/dev/null \
    || log "  NOTE: Could not assign Global Reader AAD role (need Privileged Role Administrator or Global Admin — or already assigned). MFA / Conditional Access CIS checks may be partial."

###############################################################################
# 5. Build payload + HMAC, POST to Drax webhook.
###############################################################################
PAYLOAD=$(jq -nc \
    --arg p azure \
    --arg t "$DRAX_TENANT_ID" \
    --arg e "$DRAX_EXTERNAL_ID" \
    --arg ev Create \
    --arg ver "$DRAX_TEMPLATE_VER" \
    --arg at "$AAD_TENANT_ID" \
    --arg ci "$CLIENT_ID" \
    --arg cs "$CLIENT_SECRET" \
    --arg si "$SUBSCRIPTION_ID" \
    --arg mg "${DRAX_MGMT_GROUP_ID:-}" \
    '{provider:$p, tenant_id:$t, external_id:$e, event_type:$ev,
      template_version:$ver, azure_tenant_id:$at, client_id:$ci,
      client_secret:$cs, subscription_id:$si, management_group_id:$mg}')

SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$DRAX_EXTERNAL_ID" | awk '{print $2}')

log "Posting registration to Drax..."
HTTP_STATUS=$(curl -sS -o /tmp/drax-webhook-resp.txt -w "%{http_code}" \
    -X POST "$DRAX_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -H "X-Drax-Signature: $SIG" \
    -H "X-Drax-Tenant-Id: $DRAX_TENANT_ID" \
    -H "User-Agent: drax-azure-onboard/1.0" \
    --data "$PAYLOAD" || echo "000")

if [[ "$HTTP_STATUS" != "200" ]]; then
    err "Webhook returned $HTTP_STATUS: $(cat /tmp/drax-webhook-resp.txt 2>/dev/null || echo unknown)"
fi

log "Drax registration: OK"
log "Azure Quick Connect complete."
