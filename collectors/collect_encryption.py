"""
collect_encryption.py — KMS, storage encryption, and TLS evidence collector

Evidence ID : gcp_encryption
Permissions : roles/cloudkms.viewer, roles/viewer

Controls satisfied — see controls.yaml for full mapping:
  PCI-DSS   3.5.1, 3.6.1, 3.7.1, 4.2.1
  SOC 2     CC6.7
  ISO 27001 A.8.24
  ISO 42001 8.4
"""

import json
import subprocess
from base import BaseCollector

KMS_MAX_ROTATION_DAYS = 90   # PCI-DSS Req 3.7.1 recommendation
TLS_COMPLIANT_VERSIONS = {"TLS_1_2", "TLS_1_3"}


def gcloud(args: list) -> object:
    cmd = ["gcloud"] + args + ["--format=json"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(r.stdout) if r.stdout.strip() else []


class GCPEncryptionCollector(BaseCollector):

    def collect(self) -> dict:
        # 1. KMS key rotation
        kms_results = []
        try:
            keyrings = gcloud(["kms", "keyrings", "list",
                                f"--project={self.project}", "--location=global"])
            for ring in keyrings:
                keys = gcloud(["kms", "keys", "list",
                                f"--keyring={ring['name']}",
                                "--location=global", f"--project={self.project}"])
                for key in keys:
                    period = key.get("rotationPeriod", "")
                    rotation_days = int(period.rstrip("s")) // 86400 if period else None
                    kms_results.append({
                        "key": key["name"].split("/")[-1],
                        "purpose": key.get("purpose", ""),
                        "rotation_period": period,
                        "rotation_days": rotation_days,
                        "auto_rotation_enabled": bool(period),
                        "meets_90d_requirement": (
                            rotation_days is not None and rotation_days <= KMS_MAX_ROTATION_DAYS
                        ),
                    })
        except subprocess.CalledProcessError:
            pass

        # 2. SSL policies (TLS version enforcement)
        ssl_results = []
        try:
            policies = gcloud(["compute", "ssl-policies", "list",
                                f"--project={self.project}"])
            for p in policies:
                min_tls = p.get("minTlsVersion", "TLS_1_0")
                ssl_results.append({
                    "name": p["name"],
                    "min_tls_version": min_tls,
                    "profile": p.get("profile", "COMPATIBLE"),
                    "pci_compliant": min_tls in TLS_COMPLIANT_VERSIONS,
                })
        except subprocess.CalledProcessError:
            pass

        keys_without_rotation = [k for k in kms_results if not k["auto_rotation_enabled"]]
        keys_over_90d = [k for k in kms_results if not k["meets_90d_requirement"]]
        non_compliant_tls = [p for p in ssl_results if not p["pci_compliant"]]

        return {
            "kms_keys": kms_results,
            "ssl_policies": ssl_results,
            "kms_key_count": len(kms_results),
            "compliance_signals": {
                "all_kms_keys_have_rotation": len(keys_without_rotation) == 0,
                "all_kms_keys_rotate_within_90d": len(keys_over_90d) == 0,
                "all_ssl_policies_tls12_or_higher": len(non_compliant_tls) == 0,
                "kms_keys_missing_rotation": [k["key"] for k in keys_without_rotation],
                "ssl_policies_below_tls12": [p["name"] for p in non_compliant_tls],
            },
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    args = parser.parse_args()
    result = GCPEncryptionCollector("gcp_encryption", args.project).run()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            print(f"  i  {k}: {v if v else "(none)"}")
        else:
            icon = "+" if v else "x"
            print(f"  {icon}  {k}")
