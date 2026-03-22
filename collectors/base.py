"""
base.py — shared collector base class for Google GRC evidence collectors.

Mirrors the AWS version exactly. All collectors inherit this to ensure
a consistent output envelope across every artifact.

Artifact format:
{
    "evidence_id":    str  — unique ID matching controls.yaml
    "collector":      str  — class name
    "collected_at":   str  — ISO 8601 UTC
    "gcp_project":    str  — project ID (or "workspace" for Admin SDK collectors)
    "platform":       str  — "gcp" | "workspace"
    "status":         str  — "ok" | "error"
    "data":           any  — collector-specific payload
    "error":          str  — only present if status == "error"
}
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class BaseCollector:
    EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "evidence"))

    def __init__(self, evidence_id: str, project: str, platform: str = "gcp"):
        self.evidence_id = evidence_id
        self.project = project
        self.platform = platform
        self.collected_at = datetime.now(timezone.utc).isoformat()

    def collect(self) -> dict:
        """Override in each collector. Return the data payload."""
        raise NotImplementedError

    def run(self) -> dict:
        """Run collect(), wrap in standard envelope, save to disk."""
        try:
            data = self.collect()
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "gcp_project": self.project,
                "platform": self.platform,
                "status": "ok",
                "data": data,
            }
        except Exception as exc:
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "gcp_project": self.project,
                "platform": self.platform,
                "status": "error",
                "error": str(exc),
                "data": None,
            }

        self._save(artifact)
        return artifact

    def _save(self, artifact: dict):
        """Write to evidence/<evidence_id>/latest.json and a timestamped copy."""
        folder = self.EVIDENCE_DIR / self.evidence_id
        folder.mkdir(parents=True, exist_ok=True)

        (folder / "latest.json").write_text(
            json.dumps(artifact, indent=2, default=str)
        )
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        (folder / f"{date_str}.json").write_text(
            json.dumps(artifact, indent=2, default=str)
        )

        status = artifact["status"].upper()
        print(f"[{status}] {self.evidence_id} → {folder}/latest.json")
