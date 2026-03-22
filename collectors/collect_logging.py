"""
collect_logging.py — Cloud Logging & Audit Trail evidence collector

Evidence ID : gcp_audit_logging
Permissions : roles/logging.viewer, roles/iam.securityReviewer

Controls satisfied — see controls.yaml for full mapping:
  PCI-DSS   10.2.1, 10.3.2, 10.5.1, 10.7.1
  SOC 2     CC7.2, CC7.3
  ISO 27001 A.8.15, A.8.16
  ISO 42001 9.1, 9.1.2
"""

import json
import subprocess
from base import BaseCollector

REQUIRED_RETENTION_DAYS = 365   # PCI-DSS Req 10.5.1: 12 months
SERVICES_NEEDING_DATA_ACCESS = [
    "storage.googleapis.com",
    "bigquery.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
]


def gcloud(args: list) -> object:
    cmd = ["gcloud"] + args + ["--format=json"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(r.stdout) if r.stdout.strip() else []


class GCPLoggingCollector(BaseCollector):

    def collect(self) -> dict:
        # 1. Log sinks — prove logs are exported / preserved
        sinks = gcloud(["logging", "sinks", "list", f"--project={self.project}"])
        sink_report = []
        for s in sinks:
            filt = s.get("filter", "")
            exports_audit = "DATA_ACCESS" in filt or "cloudaudit" in filt or not filt
            sink_report.append({
                "name": s["name"],
                "destination": s.get("destination", ""),
                "exports_audit_logs": exports_audit,
                "disabled": s.get("disabled", False),
            })
        active_audit_sinks = [s for s in sink_report
                               if s["exports_audit_logs"] and not s["disabled"]]

        # 2. Log bucket retention
        try:
            buckets = gcloud(["logging", "buckets", "list",
                               f"--project={self.project}", "--location=global"])
        except subprocess.CalledProcessError:
            buckets = []
        bucket_report = []
        for b in buckets:
            ret = b.get("retentionDays", 0)
            bucket_report.append({
                "name": b["name"],
                "retention_days": ret,
                "meets_pci_requirement": ret >= REQUIRED_RETENTION_DAYS,
                "locked": b.get("locked", False),
            })

        # 3. Data Access audit log enablement per service
        policy = gcloud(["projects", "get-iam-policy", self.project])
        audit_configs = {
            a["service"]: {c["logType"] for c in a.get("auditLogConfigs", [])}
            for a in policy.get("auditConfigs", [])
        }
        data_access_report = []
        for svc in SERVICES_NEEDING_DATA_ACCESS:
            types = audit_configs.get(svc, set())
            data_access_report.append({
                "service": svc,
                "data_write_enabled": "DATA_WRITE" in types,
                "data_read_enabled": "DATA_READ" in types,
                "admin_read_enabled": "ADMIN_READ" in types,
            })

        all_retention_compliant = all(b["meets_pci_requirement"] for b in bucket_report)
        all_data_write_logged = all(s["data_write_enabled"] for s in data_access_report)

        return {
            "log_sinks": sink_report,
            "active_audit_sink_count": len(active_audit_sinks),
            "log_buckets": bucket_report,
            "data_access_logging": data_access_report,
            "compliance_signals": {
                "audit_log_sink_active": len(active_audit_sinks) > 0,
                "log_retention_meets_pci_365d": all_retention_compliant,
                "data_write_logging_enabled": all_data_write_logged,
                "log_validation_via_locked_bucket": any(
                    b["locked"] for b in bucket_report
                ),
            },
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    result = GCPLoggingCollector("gcp_audit_logging", args.project).run()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        icon = "+" if v else "x"
        print(f"  {icon}  {k}")
