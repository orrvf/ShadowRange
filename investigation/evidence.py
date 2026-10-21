"""Validate a single ShadowRange investigation and its detection evidence."""

import hashlib
import json
from pathlib import Path

MAX_EVIDENCE_BYTES = 20 * 1024 * 1024


def _sha256(path):
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"Evidence file too large: {path}")
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_records(path):
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"Evidence file too large: {path}")
    records = []
    with path.open("r", encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{number}: invalid JSON: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{number}: expected a JSON object")
            records.append(record)
    return records


def load_evidence(telemetry_path, alerts_path):
    """Fail closed when alerts are stale, modified, or not from this telemetry."""
    manifest_path = alerts_path.with_name(alerts_path.stem + ".meta.json")
    with manifest_path.open("r", encoding="utf-8") as source:
        manifest = json.load(source)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Unsupported or invalid evidence manifest")
    if manifest.get("telemetry_sha256") != _sha256(telemetry_path):
        raise ValueError("Telemetry differs from the detection run; rerun detection")
    if manifest.get("alerts_sha256") != _sha256(alerts_path):
        raise ValueError("Alerts differ from the detection run; rerun detection")

    telemetry = read_records(telemetry_path)
    alerts = read_records(alerts_path)
    if type(manifest.get("alert_count")) is not int or manifest["alert_count"] != len(alerts):
        raise ValueError("Alert count does not match evidence manifest")

    processes = [item for item in telemetry if item.get("type") == "process"]
    regions = [item for item in telemetry if item.get("type", "memory_region") == "memory_region"]
    if len(processes) != 1:
        raise ValueError("Expected exactly one process record in telemetry")
    process = processes[0]
    pid = process.get("pid")
    if type(pid) is not int or pid <= 0:
        raise ValueError("Process record has an invalid PID")
    if any(region.get("pid") != pid for region in regions):
        raise ValueError("Memory regions contain a different PID")
    if any(alert.get("pid") != pid for alert in alerts):
        raise ValueError("Alerts contain a different PID; rerun detection")
    if any(type(alert.get("rule")) is not str for alert in alerts):
        raise ValueError("Alert record has an invalid rule")
    return process, regions, alerts, manifest
