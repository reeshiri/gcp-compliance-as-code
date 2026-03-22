"""
generate_report.py — compliance gap report generator

Reads evidence/*/latest.json and controls.yaml, then writes three CSVs
that exactly mirror the AWS version's output format:

  reports/
  ├── 01_summary.csv           one row per signal, pass/fail, all frameworks
  ├── 02_control_coverage.csv  one row per framework control, status + evidence
  └── 03_findings_detail.csv   raw findings (users without MFA, stale keys, etc.)

Usage:
    python generate_report.py [--evidence-dir EVIDENCE_DIR] [--controls CONTROLS_YAML]
"""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

FRAMEWORKS = ["pci_dss", "soc2", "iso_27001", "iso_42001"]
FRAMEWORK_LABELS = {
    "pci_dss":   "PCI-DSS",
    "soc2":      "SOC 2",
    "iso_27001": "ISO 27001",
    "iso_42001": "ISO 42001",
}

# Signals that carry list values — these become rows in findings detail
DETAIL_SIGNALS = {
    "users_without_mfa": {
        "title": "Workspace user without MFA enrolled",
        "evidence_id": "workspace_access_control",
        "severity": "HIGH",
        "remediation": "Enable 2-Step Verification for the user in Admin Console > Security.",
    },
    "admin_users_without_mfa": {
        "title": "Workspace admin without MFA enrolled",
        "evidence_id": "workspace_access_control",
        "severity": "CRITICAL",
        "remediation": "Enforce MFA immediately for admin accounts in Admin Console > Security.",
    },
    "stale_sa_keys": {
        "title": "Service account key older than 90 days",
        "evidence_id": "gcp_iam_posture",
        "severity": "HIGH",
        "remediation": "Rotate or delete the key in IAM > Service Accounts > Keys.",
    },
    "kms_keys_missing_rotation": {
        "title": "KMS key without automatic rotation enabled",
        "evidence_id": "gcp_encryption",
        "severity": "MEDIUM",
        "remediation": "Enable automatic rotation in Cloud KMS > Key rings.",
    },
    "ssl_policies_below_tls12": {
        "title": "SSL policy permits TLS below 1.2 (PCI-DSS Req 4.2.1 failure)",
        "evidence_id": "gcp_encryption",
        "severity": "HIGH",
        "remediation": "Update the SSL policy to set minTlsVersion to TLS_1_2 or higher.",
    },
}


def load_evidence(evidence_dir: Path) -> dict:
    evidence = {}
    for latest in evidence_dir.glob("*/latest.json"):
        evidence_id = latest.parent.name
        try:
            evidence[evidence_id] = json.loads(latest.read_text())
        except json.JSONDecodeError as exc:
            print(f"  [WARN] Could not parse {latest}: {exc}")
    return evidence


def load_controls(controls_path: Path) -> list:
    with open(controls_path) as f:
        return yaml.safe_load(f)["controls"]


def get_signal_value(artifact: dict, signal: str):
    if artifact.get("status") == "error":
        return None
    return (artifact.get("data") or {}).get("compliance_signals", {}).get(signal)


def signal_status(value) -> str:
    if value is None:
        return "ERROR"
    if isinstance(value, bool):
        return "PASS" if value else "FAIL"
    if isinstance(value, list):
        return "PASS" if len(value) == 0 else "FAIL"
    if isinstance(value, int):
        return "PASS" if value == 0 else "INFO"
    return "UNKNOWN"


def write_summary(controls, evidence, out_path, run_at):
    fieldnames = [
        "evidence_id", "signal", "description", "status",
        "collected_at", "gcp_project",
    ] + [FRAMEWORK_LABELS[f] for f in FRAMEWORKS]

    rows = []
    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        row = {
            "evidence_id": eid,
            "signal": signal,
            "description": ctrl["description"],
            "status": status,
            "collected_at": artifact.get("collected_at", "N/A"),
            "gcp_project": artifact.get("gcp_project", "N/A"),
        }
        for fw in FRAMEWORKS:
            ids = ctrl.get("frameworks", {}).get(fw, [])
            row[FRAMEWORK_LABELS[fw]] = "; ".join(ids) if ids else ""
        rows.append(row)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  +  {out_path}  ({len(rows)} rows)")


def write_control_coverage(controls, evidence, out_path, run_at):
    coverage = {}
    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        for fw in FRAMEWORKS:
            for ctrl_id in ctrl.get("frameworks", {}).get(fw, []):
                key = (FRAMEWORK_LABELS[fw], ctrl_id)
                coverage.setdefault(key, [])
                coverage[key].append({
                    "signal": signal, "status": status,
                    "description": ctrl["description"], "evidence_id": eid,
                })

    fieldnames = [
        "framework", "control_id", "overall_status", "evidence_count",
        "passing_signals", "failing_signals", "evidence_ids", "signal_descriptions",
    ]
    rows = []
    for (framework, ctrl_id), entries in sorted(coverage.items()):
        passing = [e for e in entries if e["status"] == "PASS"]
        failing = [e for e in entries if e["status"] in ("FAIL", "ERROR")]
        overall = "FAIL" if failing else ("PASS" if passing else "UNKNOWN")
        rows.append({
            "framework": framework,
            "control_id": ctrl_id,
            "overall_status": overall,
            "evidence_count": len(entries),
            "passing_signals": len(passing),
            "failing_signals": len(failing),
            "evidence_ids": "; ".join(sorted({e["evidence_id"] for e in entries})),
            "signal_descriptions": " | ".join(e["description"] for e in entries),
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    pass_c = sum(1 for r in rows if r["overall_status"] == "PASS")
    fail_c = sum(1 for r in rows if r["overall_status"] == "FAIL")
    print(f"  +  {out_path}  ({len(rows)} controls: {pass_c} pass, {fail_c} fail)")


def write_findings_detail(evidence, out_path, run_at):
    fieldnames = [
        "evidence_id", "finding_type", "severity", "resource",
        "detail", "remediation", "collected_at", "gcp_project",
    ]
    rows = []

    # Structured list signals (users without MFA, stale keys, etc.)
    for sig_key, meta in DETAIL_SIGNALS.items():
        eid = meta["evidence_id"]
        artifact = evidence.get(eid, {})
        if not artifact or artifact.get("status") == "error":
            continue
        collected_at = artifact.get("collected_at", "N/A")
        gcp_project = artifact.get("gcp_project", "N/A")
        signals = (artifact.get("data") or {}).get("compliance_signals", {})
        items = signals.get(sig_key, [])
        for item in items:
            if isinstance(item, dict):
                resource = item.get("service_account") or item.get("user") or str(item)
                detail = "; ".join(f"{k}={v}" for k, v in item.items()
                                   if k not in ("service_account", "user"))
            else:
                resource = str(item)
                detail = ""
            rows.append({
                "evidence_id": eid,
                "finding_type": meta["title"],
                "severity": meta["severity"],
                "resource": resource,
                "detail": detail,
                "remediation": meta["remediation"],
                "collected_at": collected_at,
                "gcp_project": gcp_project,
            })

    # SCC critical/high findings
    scc = evidence.get("gcp_scc_findings", {})
    if scc and scc.get("status") != "error":
        data = scc.get("data") or {}
        for sev_key in ("critical_findings_sample", "high_findings_sample"):
            for f in data.get(sev_key, []):
                rows.append({
                    "evidence_id": "gcp_scc_findings",
                    "finding_type": f"SCC {f.get('severity', '')} finding: {f.get('category', '')}",
                    "severity": f.get("severity", "UNKNOWN"),
                    "resource": f.get("resource", "N/A"),
                    "detail": f.get("name", ""),
                    "remediation": "Review and remediate in Security Command Center console.",
                    "collected_at": scc.get("collected_at", "N/A"),
                    "gcp_project": scc.get("gcp_project", "N/A"),
                })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    high = sum(1 for r in rows if r["severity"] in ("CRITICAL", "HIGH"))
    print(f"  +  {out_path}  ({len(rows)} findings, {high} high/critical)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", default="evidence")
    parser.add_argument("--controls", default="controls.yaml")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    controls_path = Path(args.controls)
    output_dir = Path(args.output_dir)
    run_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*56}")
    print(f"  Google GRC Report Generator")
    print(f"  run at  : {run_at}")
    print(f"  evidence: {evidence_dir}")
    print(f"  controls: {controls_path}")
    print(f"\n{'='*56}\n")

    if not evidence_dir.exists():
        print(f"[ERROR] Evidence directory not found: {evidence_dir}")
        print("  Run collectors/run_all.py first.")
        raise SystemExit(1)

    evidence = load_evidence(evidence_dir)
    controls = load_controls(controls_path)
    print(f"  Loaded {len(evidence)} evidence artifact(s)")
    print(f"  Loaded {len(controls)} control mapping(s)\n")

    write_summary(controls, evidence, output_dir / "01_summary.csv", run_at)
    write_control_coverage(controls, evidence, output_dir / "02_control_coverage.csv", run_at)
    write_findings_detail(evidence, output_dir / "03_findings_detail.csv", run_at)

    print(f"\n  Reports written to {output_dir}/")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
