"""
collect_scc.py — Security Command Center findings evidence collector

Evidence ID : gcp_scc_findings
Permissions : roles/securitycenter.findingsViewer

Mirrors the role of AWS Security Hub in the AWS version.

Controls satisfied — see controls.yaml for full mapping:
  PCI-DSS   6.3.3, 11.3.1, 11.3.2
  SOC 2     CC7.1, CC7.2
  ISO 27001 A.8.8
  ISO 42001 6.6.2
"""

import json
import subprocess
from collections import defaultdict
from base import BaseCollector

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# SCC built-in security sources we expect to be active
EXPECTED_SOURCES = {
    "Security Health Analytics",
    "Web Security Scanner",
    "Container Threat Detection",
}


def gcloud(args: list) -> object:
    cmd = ["gcloud"] + args + ["--format=json"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(r.stdout) if r.stdout.strip() else []


class SCCCollector(BaseCollector):

    def collect(self) -> dict:
        # 1. Check SCC is enabled by listing sources
        try:
            sources = gcloud([
                "scc", "sources", "list",
                f"--project={self.project}",
            ])
            scc_enabled = True
        except subprocess.CalledProcessError:
            return {
                "scc_enabled": False,
                "compliance_signals": {
                    "scc_enabled": False,
                    "no_critical_findings": False,
                    "no_high_findings": False,
                    "security_health_analytics_active": False,
                },
            }

        enabled_source_names = {s.get("displayName", "") for s in sources}
        source_signals = {
            src: src in enabled_source_names for src in EXPECTED_SOURCES
        }

        # 2. Active findings
        try:
            findings_raw = gcloud([
                "scc", "findings", "list",
                f"--project={self.project}",
                "--filter=state=ACTIVE",
                "--page-size=1000",
            ])
        except subprocess.CalledProcessError:
            findings_raw = []

        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        critical_sample = []
        high_sample = []

        for f in findings_raw:
            sev = f.get("finding", {}).get("severity", "UNKNOWN").upper()
            severity_counts[sev] += 1
            cat = f.get("finding", {}).get("category", "UNKNOWN")
            category_counts[cat] += 1

            summary = {
                "name": f.get("finding", {}).get("name", ""),
                "category": cat,
                "severity": sev,
                "resource": f.get("resource", {}).get("name", ""),
                "event_time": f.get("finding", {}).get("eventTime"),
            }
            if sev == "CRITICAL" and len(critical_sample) < 10:
                critical_sample.append(summary)
            elif sev == "HIGH" and len(high_sample) < 10:
                high_sample.append(summary)

        return {
            "scc_enabled": scc_enabled,
            "enabled_sources": list(enabled_source_names),
            "total_active_findings": len(findings_raw),
            "findings_by_severity": dict(severity_counts),
            "top_finding_categories": sorted(
                category_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "critical_findings_sample": critical_sample,
            "high_findings_sample": high_sample,
            "compliance_signals": {
                "scc_enabled": scc_enabled,
                "security_health_analytics_active": source_signals.get(
                    "Security Health Analytics", False),
                "no_critical_findings": severity_counts.get("CRITICAL", 0) == 0,
                "no_high_findings": severity_counts.get("HIGH", 0) == 0,
                "critical_finding_count": severity_counts.get("CRITICAL", 0),
                "high_finding_count": severity_counts.get("HIGH", 0),
            },
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    result = SCCCollector("gcp_scc_findings", args.project).run()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, (list, int)):
            print(f"  i  {k}: {v}")
        else:
            icon = "+" if v else "x"
            print(f"  {icon}  {k}")
