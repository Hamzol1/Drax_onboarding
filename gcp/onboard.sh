#!/usr/bin/env bash
###############################################################################
# Drax Security — GCP Quick Connect onboard script
#
# What this script does (idempotent, safe to re-run):
#   1. Validates that gcloud is authenticated and has a target project set.
#   2. Enables the read APIs Drax needs:
#        - cloudresourcemanager.googleapis.com  (project metadata)
#        - iam.googleapis.com                   (SA + role bindings)
#        - cloudbilling.googleapis.com          (FinOps)
#        - bigquery.googleapis.com              (data discovery)
#        - securitycenter.googleapis.com        (CSPM)
#        - logging.googleapis.com               (audit log read)
#        - monitoring.googleapis.com            (asset metadata)
#   3. Creates a service account `drax-readonly-{ext_id_short}` with the
#      Wiz/Orca-equivalent read-only role bundle:
#        - roles/viewer
#        - roles/iam.securityReviewer
#        - roles/billing.viewer
#        - roles/securitycenter.adminViewer
#   4. Generates a single SA JSON key (rotated every 90d via Drax's health
#      check job — caller can also rotate manually with `--rotate`).
#   5. POSTs the new credentials (HMAC-signed with the Drax ExternalId) to
#      Drax's registration webhook so the customer never copy/pastes anything.
#
# Required env (the Drax UI shows a 5-line `export ...` block to paste into
# the Cloud Shell terminal before running this script — Cloud Shell's
# `cloudshell_print` URL parameter takes a file path with restricted
# chars, not free-text, so it can't be used to inject these values):
#   DRAX_TENANT_ID    — tenant slug
#   DRAX_EXTERNAL_ID  — `drax-{slug}-gcp-{16hex}` (per-tenant secret)
#   DRAX_WEBHOOK_URL  — https://<api>/api/v1/webhooks/cloud-onboarding
#   DRAX_TEMPLATE_VER — semver (defaults to 1.1.0)
#
# Optional:
#   DRAX_PROJECT_ID   — gcloud config get-value project will be used if absent
#   DRAX_ORG_ID       — set to onboard at organization scope (org-wide)
#
# Exit code 0 on full success; non-zero on any failure with a detailed error
# printed to stderr. The script never echoes the SA key to stdout — only
# uploads it to the Drax webhook over TLS.
###############################################################################

set -euo pipefail

err() { echo "[drax] ERROR: $*" >&2; exit 1; }
log() { echo "[drax] $*"; }

command -v gcloud >/dev/null 2>&1 || err "gcloud not found. Install Google Cloud CLI first."
command -v curl >/dev/null 2>&1 || err "curl not found."
command -v openssl >/dev/null 2>&1 || err "openssl not found (required for HMAC)."
command -v python3 >/dev/null 2>&1 || err "python3 not found (required for JSON encoding)."

DRAX_TENANT_ID="${DRAX_TENANT_ID:-}"
DRAX_EXTERNAL_ID="${DRAX_EXTERNAL_ID:-}"
DRAX_WEBHOOK_URL="${DRAX_WEBHOOK_URL:-}"
DRAX_TEMPLATE_VER="${DRAX_TEMPLATE_VER:-1.1.0}"

[[ -n "$DRAX_TENANT_ID"   ]] || err "DRAX_TENANT_ID not set."
[[ -n "$DRAX_EXTERNAL_ID" ]] || err "DRAX_EXTERNAL_ID not set."
[[ -n "$DRAX_WEBHOOK_URL" ]] || err "DRAX_WEBHOOK_URL not set."

[[ "$DRAX_EXTERNAL_ID" =~ ^drax-[a-z0-9-]+-gcp-[a-f0-9]{16}$ ]] \
    || err "DRAX_EXTERNAL_ID format invalid."

###############################################################################
# Project resolution — Cloud Shell starts with NO default project. Force-asking
# the customer to run `gcloud config set project <ID>` before our script is
# friction Wiz/Orca/Prisma do not have. Resolution order:
#   1. DRAX_PROJECT_ID env (explicit override).
#   2. `gcloud config get-value project` (existing user default).
#   3. List projects the active gcloud principal can see; if exactly one,
#      adopt it (also persist via `gcloud config set project` so re-runs are
#      instant). If multiple, prompt with a numbered picker — silent failure
#      is worse than one prompt for multi-project orgs.
#   4. Hard error only if zero projects visible (auth issue, not UX issue).
###############################################################################
PROJECT_ID="${DRAX_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
if [[ -z "$PROJECT_ID" || "$PROJECT_ID" == "(unset)" ]]; then
    log "No default GCP project configured — discovering accessible projects..."
    # `gcloud projects list` returns ACTIVE projects only by default; that is
    # what we want (deleted/pending projects can't be onboarded).
    mapfile -t _DRAX_PROJECTS < <(
        gcloud projects list \
            --filter='lifecycleState:ACTIVE' \
            --format='value(projectId)' 2>/dev/null \
            | awk 'NF'
    )
    case "${#_DRAX_PROJECTS[@]}" in
        0)
            err "No GCP projects visible to $(gcloud config get-value account 2>/dev/null || echo 'this account'). Sign in with an account that has at least Viewer on the target project, or set DRAX_PROJECT_ID."
            ;;
        1)
            PROJECT_ID="${_DRAX_PROJECTS[0]}"
            log "Found single accessible project: $PROJECT_ID — auto-selecting."
            gcloud config set project "$PROJECT_ID" --quiet >/dev/null 2>&1 || true
            ;;
        *)
            # Multi-project picker. Honors non-interactive shells too: if stdin
            # is not a TTY (CI / piped), we refuse to guess and bail out with
            # a clear instruction instead of silently picking [0].
            if [[ ! -t 0 ]]; then
                err "Multiple GCP projects visible (${#_DRAX_PROJECTS[@]}). Set DRAX_PROJECT_ID or run \`gcloud config set project <ID>\` first. Visible: ${_DRAX_PROJECTS[*]}"
            fi
            echo "[drax] Multiple GCP projects visible. Pick the one to onboard:" >&2
            # NOTE: `local` is invalid outside a function under `set -u`. Use a
            # plain shell variable here.
            _DRAX_I=1
            for _p in "${_DRAX_PROJECTS[@]}"; do
                echo "  [$_DRAX_I] $_p" >&2
                _DRAX_I=$((_DRAX_I + 1))
            done
            _DRAX_CHOICE=""
            while [[ -z "$_DRAX_CHOICE" ]]; do
                read -r -p "[drax] Project number (1-${#_DRAX_PROJECTS[@]}): " _DRAX_CHOICE </dev/tty || true
                if ! [[ "$_DRAX_CHOICE" =~ ^[0-9]+$ ]] \
                    || (( _DRAX_CHOICE < 1 || _DRAX_CHOICE > ${#_DRAX_PROJECTS[@]} )); then
                    echo "[drax] Invalid choice — enter 1-${#_DRAX_PROJECTS[@]}." >&2
                    _DRAX_CHOICE=""
                fi
            done
            PROJECT_ID="${_DRAX_PROJECTS[$((_DRAX_CHOICE - 1))]}"
            log "Selected project: $PROJECT_ID"
            gcloud config set project "$PROJECT_ID" --quiet >/dev/null 2>&1 || true
            ;;
    esac
fi
[[ -n "$PROJECT_ID" && "$PROJECT_ID" != "(unset)" ]] \
    || err "No GCP project resolved (unexpected). Set DRAX_PROJECT_ID and retry."

EXT_SHORT="${DRAX_EXTERNAL_ID##*-}"          # last 16 hex (audit only)
# Service account ID derives from the tenant slug, NOT the ExternalId hex.
# Why: rotating the ExternalId must NOT orphan the SA + role bindings + keys.
# GCP local-part limit is 30 chars: `drax-readonly-` (14) leaves 16 for slug
# (truncate + sanitize defensively — backend already enforces this shape).
SA_SLUG="$(echo "$DRAX_TENANT_ID" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed 's/-\+/-/g; s/^-//; s/-$//')"
# Truncate first, then strip a trailing hyphen that 16-char cut may have left
# behind (GCP SA local-part must end in [a-z0-9], not '-').
SA_SLUG="${SA_SLUG:0:16}"
SA_SLUG="${SA_SLUG%-}"
[[ -n "$SA_SLUG" ]] || err "tenant_id collapses to empty — cannot derive SA name."
SA_NAME="drax-readonly-${SA_SLUG}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="$(mktemp -t drax-sa-key-XXXXXX.json)"
trap 'rm -f "$KEY_FILE"' EXIT

log "Project:        $PROJECT_ID"
log "Service acct:   $SA_EMAIL"
log "Tenant:         $DRAX_TENANT_ID"
log "Template ver:   $DRAX_TEMPLATE_VER"

###############################################################################
# 1. Enable APIs (idempotent — gcloud is no-op if already enabled)
###############################################################################
log "Enabling required APIs (idempotent)..."
gcloud services enable \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    cloudbilling.googleapis.com \
    bigquery.googleapis.com \
    securitycenter.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    --project="$PROJECT_ID" \
    --quiet

###############################################################################
# 2. Create SA (idempotent)
###############################################################################
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
    log "Creating service account $SA_EMAIL..."
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="Drax Security Read-Only ($DRAX_TENANT_ID)" \
        --description="Drax CNAPP read-only access. ExternalId=$DRAX_EXTERNAL_ID" \
        --project="$PROJECT_ID" \
        --quiet
else
    log "Service account already exists; skipping create."
fi

###############################################################################
# 3. Bind project-level roles (idempotent — gcloud add-iam-policy-binding
#    is no-op when binding already exists)
###############################################################################
ROLES=(
    "roles/viewer"
    "roles/iam.securityReviewer"
    "roles/billing.viewer"
    "roles/securitycenter.adminViewer"
)
for role in "${ROLES[@]}"; do
    log "Binding $role..."
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="$role" \
        --condition=None \
        --quiet >/dev/null
done

# Optional: organization-scope binding (covers all projects under the org).
if [[ -n "${DRAX_ORG_ID:-}" ]]; then
    log "Binding organization-scope roles (org $DRAX_ORG_ID)..."
    for role in "${ROLES[@]}"; do
        gcloud organizations add-iam-policy-binding "$DRAX_ORG_ID" \
            --member="serviceAccount:$SA_EMAIL" \
            --role="$role" \
            --condition=None \
            --quiet >/dev/null
    done
fi

###############################################################################
# 4. Rotate SA JSON key.
#    GCP enforces a hard cap of 10 USER_MANAGED keys per service account.
#    A naive `keys create` on every re-run accumulates orphans until the
#    11th run errors out (`FAILED_PRECONDITION: Maximum number of keys ...`)
#    and leaves a long tail of valid 90-day credentials in the customer's
#    project — Wiz / Orca / Prisma all rotate by deleting prior user-managed
#    keys before issuing a fresh one. We do the same: list user-managed keys
#    on this SA and delete them, then mint exactly one new key. SYSTEM_MANAGED
#    keys (Google's, used internally by GCP) are filtered out by `KEY_TYPE`.
###############################################################################
log "Rotating prior user-managed keys (Drax owns this SA — single live key)..."
EXISTING_KEYS=$(gcloud iam service-accounts keys list \
    --iam-account="$SA_EMAIL" \
    --project="$PROJECT_ID" \
    --managed-by=user \
    --format='value(name.basename())' 2>/dev/null || true)
if [[ -n "$EXISTING_KEYS" ]]; then
    while IFS= read -r KEY_ID; do
        [[ -z "$KEY_ID" ]] && continue
        log "  Deleting stale key $KEY_ID"
        gcloud iam service-accounts keys delete "$KEY_ID" \
            --iam-account="$SA_EMAIL" \
            --project="$PROJECT_ID" \
            --quiet >/dev/null 2>&1 || \
            log "  WARN: could not delete $KEY_ID (already gone or missing perm)"
    done <<< "$EXISTING_KEYS"
fi

log "Generating service account key (write to $(dirname "$KEY_FILE"))..."
gcloud iam service-accounts keys create "$KEY_FILE" \
    --iam-account="$SA_EMAIL" \
    --project="$PROJECT_ID" \
    --quiet

###############################################################################
# 5. Build payload + HMAC, POST to Drax webhook.
#    Payload schema mirrors src/api/cloud_onboarding_webhook.py.
#
#    QUOTED heredoc (`<<'PYEOF'`) — bash MUST NOT expand $VAR inside the
#    Python source. Tenant slug / project ID are constrained, but the SA key
#    JSON we read from disk contains `"` and `\n` that would otherwise
#    corrupt Python parsing on unquoted heredocs. Values are passed via
#    os.environ (set on the python3 sub-process) instead.
###############################################################################
PAYLOAD=$(
    DRAX_KEY_FILE="$KEY_FILE" \
    DRAX_TENANT_ID="$DRAX_TENANT_ID" \
    DRAX_EXTERNAL_ID="$DRAX_EXTERNAL_ID" \
    DRAX_TEMPLATE_VER="$DRAX_TEMPLATE_VER" \
    DRAX_PROJECT_ID="$PROJECT_ID" \
    DRAX_SA_EMAIL="$SA_EMAIL" \
    DRAX_ORG_ID="${DRAX_ORG_ID:-}" \
    python3 - <<'PYEOF'
import json, os
with open(os.environ["DRAX_KEY_FILE"]) as f:
    key = f.read()
print(json.dumps({
    "provider": "gcp",
    "tenant_id": os.environ["DRAX_TENANT_ID"],
    "external_id": os.environ["DRAX_EXTERNAL_ID"],
    "event_type": "Create",
    "template_version": os.environ["DRAX_TEMPLATE_VER"],
    "project_id": os.environ["DRAX_PROJECT_ID"],
    "sa_email": os.environ["DRAX_SA_EMAIL"],
    "sa_key_json": key,
    "organization_id": os.environ.get("DRAX_ORG_ID", ""),
}, separators=(",", ":")))
PYEOF
)

SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$DRAX_EXTERNAL_ID" | awk '{print $2}')

log "Posting registration to Drax..."
HTTP_STATUS=$(curl -sS -o /tmp/drax-webhook-resp.txt -w "%{http_code}" \
    -X POST "$DRAX_WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -H "X-Drax-Signature: $SIG" \
    -H "X-Drax-Tenant-Id: $DRAX_TENANT_ID" \
    -H "User-Agent: drax-gcp-onboard/1.0" \
    --data "$PAYLOAD" || echo "000")

if [[ "$HTTP_STATUS" != "200" ]]; then
    err "Webhook returned $HTTP_STATUS: $(cat /tmp/drax-webhook-resp.txt 2>/dev/null || echo unknown)"
fi

log "Drax registration: OK"
log "GCP Quick Connect complete."
