# Google GRC Compliance as Code

Automated compliance evidence collection for **Google Cloud Platform (GCP)**
and **Google Workspace**. Mirrors the structure of the AWS version exactly.

## Frameworks covered

| Framework | Scope |
|-----------|-------|
| PCI-DSS v4.0 | Payment card data security |
| SOC 2 Type II | Trust Service Criteria |
| ISO 27001:2022 | Information security ISMS |
| ISO 42001:2023 | AI management system |

## Repository structure

```
google-grc-compliance/
├── .github/workflows/
│   └── compliance.yml       Weekly cron + on-demand trigger
├── collectors/
│   ├── base.py              Shared BaseCollector (standard artifact envelope)
│   ├── collect_iam.py       GCP IAM posture
│   ├── collect_logging.py   Cloud Logging & audit log sinks
│   ├── collect_encryption.py  KMS key rotation, SSL policies
│   ├── collect_scc.py       Security Command Center findings
│   ├── collect_workspace.py  Workspace MFA, login audit, sharing
│   └── run_all.py           Orchestrator — runs all collectors
├── controls.yaml            Signal → framework control ID mappings
├── generate_report.py       Produces three CSV reports from evidence
├── evidence/                Artifacts committed back to repo (gitignored *.json except controls)
│   └── <evidence_id>/
│       ├── latest.json
│       └── YYYYMMDD_HHMMSS.json
├── reports/
│   ├── 01_summary.csv
│   ├── 02_control_coverage.csv
│   └── 03_findings_detail.csv
├── docs/
│   └── setup.md
└── requirements.txt
```

## Quick start

```bash
# Authenticate
gcloud auth application-default login

# Run all collectors locally
export GCP_PROJECT_ID="my-project"
export WORKSPACE_DOMAIN="mycompany.com"
export EVIDENCE_DIR="$(pwd)/evidence"

cd collectors
python run_all.py --project $GCP_PROJECT_ID \
  --domain $WORKSPACE_DOMAIN \
  --sa-file /path/to/sa.json \
  --admin-email admin@mycompany.com

# Generate reports
cd ..
python generate_report.py
```

## Evidence overlap — collect once, satisfy multiple frameworks

Controls across PCI-DSS, SOC 2, ISO 27001, and ISO 42001 share significant
evidence. The `overlap` field in `controls.yaml` marks efficiency:

- **HIGH** — signal satisfies 3–4 frameworks simultaneously
- **MEDIUM** — satisfies 2 frameworks
- **LOW** — framework-specific

Key overlaps identified:
- IAM / MFA evidence → 13 controls across all 4 frameworks
- Audit logging evidence → 10 controls across all 4 frameworks
- SCC findings → 8 controls across PCI-DSS, SOC 2, ISO 27001

## How it matches the AWS version

| AWS | Google |
|-----|--------|
| `base.py` BaseCollector | Identical pattern, `gcp_project` instead of `aws_account` |
| `evidence/<id>/latest.json` | Identical path structure |
| `controls.yaml` | Identical schema, Google signal names |
| `generate_report.py` | Identical — same 3 CSV outputs |
| `compliance.yml` | Same structure: collect → report → git commit → Issues |
| OIDC auth (no keys) | Workload Identity Federation instead of AWS OIDC |
| Security Hub | Security Command Center (`collect_scc.py`) |
| CloudTrail | Cloud Logging + Audit Logs (`collect_logging.py`) |
| IAM Credential Report | IAM posture + Workspace Admin SDK |
