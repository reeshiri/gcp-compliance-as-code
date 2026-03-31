# GCP Compliance as Code

Automated compliance evidence collection for Google Cloud Platform and Google
Workspace, mapped to four frameworks simultaneously: PCI-DSS v4, SOC 2 Type II,
ISO 27001:2022, and ISO 42001:2023.

Instead of collecting evidence manually before an audit, this runs every week
on a schedule. It queries GCP and Workspace, evaluates each control, commits
the results to git as a timestamped audit trail, and opens a GitHub Issue for
every failing control with the affected resource and a remediation step.

Workspace coverage extends two NIST CSF 2.0 subcategories beyond what
infrastructure-only tools reach: user activity monitoring (DE.CM-03) and
data exfiltration detection (PR.DS-10).

---
## Compliance documents

| Document | Description |
|---|---|
| [NIST CSF 2.0 Crosswalk](docs/NIST_CSF2_Crosswalk_GCP.docx) | Maps all evidence signals to NIST CSF 2.0 subcategories |
