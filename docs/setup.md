# Setup guide

This document covers the one-time GCP and GitHub configuration needed before
the compliance workflow can run.

---

## 1. Enable required GCP APIs

```bash
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  logging.googleapis.com \
  cloudasset.googleapis.com \
  cloudkms.googleapis.com \
  admin.googleapis.com \
  securitycenter.googleapis.com \
  --project=$GCP_PROJECT_ID
```

---

## 2. Create the GCP service account

```bash
gcloud iam service-accounts create grc-compliance-reader \
  --display-name="GRC Compliance Reader" \
  --project=$GCP_PROJECT_ID

for ROLE in \
  roles/viewer \
  roles/iam.securityReviewer \
  roles/logging.viewer \
  roles/cloudasset.viewer \
  roles/securitycenter.findingsViewer; do
  gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:grc-compliance-reader@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="$ROLE"
done
```

---

## 3. Configure Workload Identity Federation (no long-lived keys)

```bash
# Create pool
gcloud iam workload-identity-pools create "github-pool" \
  --project=$GCP_PROJECT_ID --location="global"

# Create OIDC provider
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --project=$GCP_PROJECT_ID --location="global" \
  --workload-identity-pool="github-pool" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# Bind to service account (replace YOUR_ORG/YOUR_REPO)
gcloud iam service-accounts add-iam-policy-binding \
  grc-compliance-reader@$GCP_PROJECT_ID.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_ORG/YOUR_REPO"
```

---

## 4. Configure GitHub repository secrets and variables

Go to **Settings → Secrets and variables → Actions**.

### Secrets (encrypted)

| Name | Value |
|---|---|
| `WIF_PROVIDER` | Workload Identity Provider resource name |
| `WIF_SERVICE_ACCOUNT` | `grc-compliance-reader@<project>.iam.gserviceaccount.com` |
| `WORKSPACE_SA_JSON` | Base64-encoded service account JSON for Workspace Admin SDK |

### Variables (visible in logs)

| Name | Value |
|---|---|
| `GCP_PROJECT_ID` | `my-project-123` |
| `WORKSPACE_DOMAIN` | `mycompany.com` |
| `WORKSPACE_ADMIN_EMAIL` | `admin@mycompany.com` |

---

## 5. Google Workspace domain-wide delegation

1. Go to **Admin Console → Security → API Controls → Domain-wide Delegation**
2. Add the service account client ID
3. Grant these OAuth scopes:
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`

---

## 6. Create GitHub issue labels

The workflow tags issues with `compliance`, `automated`, and a per-source label.

| Label | Suggested colour |
|---|---|
| `compliance` | `#0075ca` |
| `automated` | `#e4e669` |
| `gcp-iam-posture` | `#d93f0b` |
| `gcp-audit-logging` | `#d93f0b` |
| `gcp-encryption` | `#d93f0b` |
| `gcp-scc-findings` | `#d93f0b` |
| `workspace-access-control` | `#d93f0b` |

---

## 7. Run it manually the first time

Go to **Actions → Compliance — collect and report → Run workflow**.

Check the job summary tab after it completes to see fail counts, and look at
**Issues** to see any automatically opened gaps.

Evidence and reports are committed directly to the repo — you get a full audit
trail via git history with timestamps and run IDs in every commit message,
matching the AWS version behaviour exactly.
