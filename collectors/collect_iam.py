"""
collect_iam.py — GCP IAM posture evidence collector

Evidence ID : gcp_iam_posture
Permissions : roles/iam.securityReviewer, roles/viewer

Controls satisfied — see controls.yaml for full mapping:
  PCI-DSS   7.2.1, 7.2.2, 8.2.1, 8.6.1
  SOC 2     CC6.1, CC6.2, CC6.3
  ISO 27001 A.5.15, A.5.16, A.5.18, A.8.2
  ISO 42001 6.1.2, 8.4
"""

import json
import subprocess
from datetime import datetime, timezone
from base import BaseCollector

PRIVILEGED_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.organizationAdmin",
}
MAX_KEY_AGE_DAYS = 90  # PCI-DSS Req 8.3.9


def gcloud(args: list) -> object:
    cmd = ["gcloud"] + args + ["--format=json"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(r.stdout) if r.stdout.strip() else []


class GCPIAMCollector(BaseCollector):

    def collect(self) -> dict:
        # 1. IAM policy — privileged bindings
        policy = gcloud(["projects", "get-iam-policy", self.project])
        bindings = policy.get("bindings", [])
        privileged_bindings = [
            {"role": b["role"], "members": b.get("members", [])}
            for b in bindings if b["role"] in PRIVILEGED_ROLES
        ]
        privileged_member_count = sum(len(b["members"]) for b in privileged_bindings)

        # 2. Service accounts + key age
        sas = gcloud(["iam", "service-accounts", "list", f"--project={self.project}"])
        stale_keys = []
        sa_report = []
        for sa in sas:
            keys = gcloud([
                "iam", "service-accounts", "keys", "list",
                f"--iam-account={sa['email']}", f"--project={self.project}",
                "--managed-by=user",
            ])
            aged = []
            for k in keys:
                created = datetime.fromisoformat(k["validAfterTime"].replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - created).days
                if age > MAX_KEY_AGE_DAYS:
                    aged.append({"key_id": k["name"].split("/")[-1], "age_days": age})
                    stale_keys.append({"service_account": sa["email"], "age_days": age})
            sa_report.append({
                "email": sa["email"],
                "disabled": sa.get("disabled", False),
                "user_managed_key_count": len(keys),
                "stale_keys": aged,
            })

        # 3. Org policies (key security constraints)
        constraints = [
            "constraints/iam.disableServiceAccountKeyCreation",
            "constraints/iam.disableServiceAccountKeyUpload",
            "constraints/compute.requireOsLogin",
            "constraints/storage.uniformBucketLevelAccess",
            "constraints/iam.allowedPolicyMemberDomains",
        ]
        org_policies = []
        for c in constraints:
            try:
                p = gcloud(["resource-manager", "org-policies", "describe",
                            c, f"--project={self.project}"])
                org_policies.append({
                    "constraint": c,
                    "enforced": bool(p.get("booleanPolicy", {}).get("enforced", False)),
                })
            except subprocess.CalledProcessError:
                org_policies.append({"constraint": c, "enforced": False})

        return {
            "total_bindings": len(bindings),
            "privileged_bindings": privileged_bindings,
            "privileged_member_count": privileged_member_count,
            "service_account_count": len(sas),
            "service_accounts": sa_report,
            "org_policies": org_policies,
            "stale_key_threshold_days": MAX_KEY_AGE_DAYS,
            "compliance_signals": {
                "no_stale_sa_keys_over_90d": len(stale_keys) == 0,
                "sa_key_creation_disabled": any(
                    p["constraint"] == "constraints/iam.disableServiceAccountKeyCreation"
                    and p["enforced"] for p in org_policies
                ),
                "uniform_bucket_access_enforced": any(
                    p["constraint"] == "constraints/storage.uniformBucketLevelAccess"
                    and p["enforced"] for p in org_policies
                ),
                "os_login_required": any(
                    p["constraint"] == "constraints/compute.requireOsLogin"
                    and p["enforced"] for p in org_policies
                ),
                "privileged_member_count": privileged_member_count,
                "stale_sa_keys": stale_keys,
            },
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    result = GCPIAMCollector("gcp_iam_posture", args.project).run()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            tag = "i" if not v else "!"
            print(f"  {tag}  {k}: {v if v else "(none)"}")
        elif isinstance(v, int):
            print(f"  i  {k}: {v}")
        else:
            icon = "+" if v else "x"
            print(f"  {icon}  {k}")
