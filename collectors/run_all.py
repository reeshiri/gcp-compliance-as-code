"""
run_all.py — run every collector and print a summary.

Mirrors the AWS version exactly in structure and output format.

Usage:
    python run_all.py --project my-gcp-project
    python run_all.py --project my-gcp-project --domain myco.com \
                      --sa-file /path/to/sa.json --admin-email admin@myco.com

The EVIDENCE_DIR environment variable controls where artifacts are written.
Defaults to ./evidence relative to the working directory.
"""

import argparse
import sys

from collect_iam import GCPIAMCollector
from collect_logging import GCPLoggingCollector
from collect_encryption import GCPEncryptionCollector
from collect_scc import SCCCollector
from collect_workspace import WorkspaceCollector

# GCP-only collectors — always run when --project is provided
GCP_COLLECTORS = [
    ("gcp_iam_posture",    GCPIAMCollector),
    ("gcp_audit_logging",  GCPLoggingCollector),
    ("gcp_encryption",     GCPEncryptionCollector),
    ("gcp_scc_findings",   SCCCollector),
]


def run_collector(evidence_id, CollectorClass, **kwargs):
    try:
        artifact = CollectorClass(evidence_id, **kwargs).run()
        return artifact
    except Exception as exc:
        print(f"     x  COLLECTOR CRASHED: {exc}")
        return {"evidence_id": evidence_id, "status": "error", "error": str(exc), "data": None}


def print_signals(artifact: dict):
    signals = (artifact.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            tag = "i" if not v else "!"
            label = "(none)" if not v else ", ".join(str(x) for x in v[:3])
            print(f"     {tag}  {k}: {label}")
        elif isinstance(v, int):
            print(f"     i  {k}: {v}")
        else:
            icon = "+" if v else "x"
            print(f"     {icon}  {k}")


def main():
    parser = argparse.ArgumentParser(description="Run all Google GRC compliance collectors")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--domain", help="Google Workspace domain (e.g. company.com)")
    parser.add_argument("--sa-file", help="Service account JSON key for Workspace")
    parser.add_argument("--admin-email", help="Workspace super admin for delegation")
    parser.add_argument("--region", default="global", help="GCP region (informational)")
    args = parser.parse_args()

    print(f"\n{'='*56}")
    print(f"  Google GRC Compliance Collectors")
    print(f"  project : {args.project}")
    if args.domain:
        print(f"  domain  : {args.domain}")
    print(f"{'='*56}\n")

    errors = []
    results = {}

    # GCP collectors
    for evidence_id, CollectorClass in GCP_COLLECTORS:
        print(f"── {evidence_id}")
        artifact = run_collector(evidence_id, CollectorClass, project=args.project)
        results[evidence_id] = artifact
        print_signals(artifact)
        if artifact.get("status") == "error":
            errors.append(evidence_id)
        print()

    # Workspace collector — only if credentials provided
    if args.domain and args.sa_file and args.admin_email:
        evidence_id = "workspace_access_control"
        print(f"── {evidence_id}")
        try:
            artifact = WorkspaceCollector(
                evidence_id, args.domain, args.sa_file, args.admin_email
            ).run()
            results[evidence_id] = artifact
            print_signals(artifact)
            if artifact.get("status") == "error":
                errors.append(evidence_id)
        except Exception as exc:
            print(f"     x  COLLECTOR CRASHED: {exc}")
            errors.append(evidence_id)
        print()
    else:
        print("── workspace_access_control  [SKIPPED — pass --domain, --sa-file, --admin-email]\n")

    # Summary
    total = len(GCP_COLLECTORS) + (1 if args.domain else 0)
    ok = total - len(errors)
    print(f"{'='*56}")
    print(f"  {ok}/{total} collectors succeeded")
    if errors:
        print(f"  Failed: {', '.join(errors)}")
    print(f"  Evidence written to: ./evidence/")
    print(f"{'='*56}\n")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
