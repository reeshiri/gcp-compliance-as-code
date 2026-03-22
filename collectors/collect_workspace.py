"""
collect_workspace.py — Google Workspace access control evidence collector

Evidence ID : workspace_access_control
Platform    : workspace (uses Admin SDK, not gcloud)
Permissions : Admin SDK domain-wide delegation
              scopes: admin.reports.audit.readonly, admin.directory.user.readonly

Controls satisfied — see controls.yaml for full mapping:
  PCI-DSS   8.4.2, 8.4.3, 8.3.9, 7.2.1, 10.2.1
  SOC 2     CC6.1, CC6.2, CC6.3, CC6.6, CC7.2
  ISO 27001 A.5.15, A.5.17, A.5.18, A.8.5
  ISO 42001 6.1.2, 6.5
"""

from datetime import datetime, timedelta, timezone
from base import BaseCollector

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
]


class WorkspaceCollector(BaseCollector):

    def __init__(self, evidence_id: str, domain: str, sa_file: str, admin_email: str):
        super().__init__(evidence_id, project=domain, platform="workspace")
        self.domain = domain
        self.sa_file = sa_file
        self.admin_email = admin_email

    def _svc(self, api: str, version: str):
        if not SDK_AVAILABLE:
            raise RuntimeError("google-api-python-client not installed")
        creds = service_account.Credentials.from_service_account_file(
            self.sa_file, scopes=SCOPES, subject=self.admin_email
        )
        return build(api, version, credentials=creds, cache_discovery=False)

    def collect(self) -> dict:
        dir_svc = self._svc("admin", "directory_v1")
        rep_svc = self._svc("reports", "v1")

        # 1. MFA enrollment across all active users
        users_raw = dir_svc.users().list(
            domain=self.domain, maxResults=500, orderBy="email"
        ).execute().get("users", [])

        mfa_enrolled = 0
        mfa_not_enrolled = []
        admin_no_mfa = []
        for u in users_raw:
            if u.get("suspended"):
                continue
            if u.get("isEnrolledIn2Sv"):
                mfa_enrolled += 1
            else:
                mfa_not_enrolled.append(u["primaryEmail"])
                if u.get("isAdmin"):
                    admin_no_mfa.append(u["primaryEmail"])

        total_active = len([u for u in users_raw if not u.get("suspended")])
        mfa_pct = round(mfa_enrolled / total_active * 100, 1) if total_active else 0

        # 2. Suspicious login events (last 7 days)
        start = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        login_events = rep_svc.activities().list(
            userKey="all", applicationName="login", startTime=start, maxResults=1000
        ).execute().get("items", [])

        suspicious_events = []
        for a in login_events:
            for e in a.get("events", []):
                if e.get("name") in ("login_failure", "suspicious_login",
                                      "account_disabled_hijacking"):
                    suspicious_events.append({
                        "time": a.get("id", {}).get("time"),
                        "user": a.get("actor", {}).get("email"),
                        "event": e.get("name"),
                        "ip": a.get("ipAddress"),
                    })

        # 3. Admin privilege grants (last 30 days)
        start30 = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        priv_events = rep_svc.activities().list(
            userKey="all", applicationName="admin",
            eventName="GRANT_ADMIN_PRIVILEGE",
            startTime=start30, maxResults=200,
        ).execute().get("items", [])

        privilege_grants = []
        for a in priv_events:
            privilege_grants.append({
                "time": a.get("id", {}).get("time"),
                "granted_by": a.get("actor", {}).get("email"),
                "granted_to": next(
                    (p.get("value") for e in a.get("events", [])
                     for p in e.get("parameters", []) if p.get("name") == "USER_EMAIL"),
                    "unknown"
                ),
            })

        # 4. External Drive sharing (last 30 days)
        drive_events = rep_svc.activities().list(
            userKey="all", applicationName="drive",
            eventName="change_acl_editors",
            startTime=start30, maxResults=500,
        ).execute().get("items", [])

        external_shares = []
        for a in drive_events:
            for e in a.get("events", []):
                for p in e.get("parameters", []):
                    if p.get("name") == "target_domain" and p.get("value", "") != self.domain:
                        external_shares.append({
                            "time": a.get("id", {}).get("time"),
                            "user": a.get("actor", {}).get("email"),
                            "target_domain": p.get("value"),
                        })

        return {
            "domain": self.domain,
            "total_active_users": total_active,
            "mfa_enrolled_count": mfa_enrolled,
            "mfa_adoption_pct": mfa_pct,
            "suspicious_login_events": suspicious_events,
            "privilege_grants_30d": privilege_grants,
            "external_shares_30d": external_shares,
            "compliance_signals": {
                "all_users_have_mfa": len(mfa_not_enrolled) == 0,
                "no_admins_without_mfa": len(admin_no_mfa) == 0,
                "no_suspicious_login_events": len(suspicious_events) == 0,
                "no_unreviewed_admin_grants": len(privilege_grants) == 0,
                "no_external_drive_sharing": len(external_shares) == 0,
                "users_without_mfa": mfa_not_enrolled,
                "admin_users_without_mfa": admin_no_mfa,
            },
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--sa-file", required=True)
    parser.add_argument("--admin-email", required=True)
    args = parser.parse_args()
    result = WorkspaceCollector(
        "workspace_access_control", args.domain, args.sa_file, args.admin_email
    ).run()
    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            tag = "i" if not v else "!"
            print(f"  {tag}  {k}: {v if v else "(none)"}")
        else:
            icon = "+" if v else "x"
            print(f"  {icon}  {k}")
