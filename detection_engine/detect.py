"""Validate ShadowRange telemetry and safely generate memory-permission alerts."""

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

INPUT_FILE = Path("shadowrange.telemetry")
OUTPUT_FILE = Path("alerts.jsonl")
METADATA_FILE = Path("alerts.meta.json")
RULE_FILE = Path(__file__).resolve().parent / "rules" / "memory_wx.yaml"
MAX_LINE_BYTES = 1024 * 1024  # A single telemetry JSONL record must be <= 1 MiB.
MAX_INPUT_BYTES = 20 * 1024 * 1024  # Bound total telemetry input size.


class TelemetryError(ValueError):
    """Telemetry is inconsistent or cannot be trusted for this investigation."""


def load_rule():
    with RULE_FILE.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError("Rule must be a YAML object")

    rule_id = rule["id"]
    severity = rule["severity"]
    required = rule["condition"]["permissions_all"]

    if not all(isinstance(value, str) and value for value in (rule_id, severity, required)):
        raise ValueError("Invalid rule fields")

    if not isinstance(rule["condition"], dict):
        raise ValueError("Invalid rule condition")

    return rule


def matches_rule(region, rule):
    permissions = region.get("permissions", "")
    required = rule["condition"]["permissions_all"]
    return isinstance(permissions, str) and all(char in permissions for char in required)


def _positive_pid(value):
    return type(value) is int and value > 0


def analyze(source, rule, hasher=None):
    """Analyze a bounded JSONL stream; produce alerts only for consistent input.

    Legacy telemetry without a process record is supported for existing tests.
    """
    total = 0
    invalid = 0
    alerts = []
    metadata_pid = None
    seen_process = False
    region_pids = set()
    regions_without_pid = 0
    total_bytes = 0

    for line_number, line in enumerate(source, 1):
        raw_line = line.encode("utf-8")
        if hasher is not None:
            hasher.update(raw_line)
        line_bytes = len(raw_line)
        total_bytes += line_bytes
        if line_bytes > MAX_LINE_BYTES:
            raise TelemetryError(f"Line {line_number} exceeds 1 MiB limit")
        if total_bytes > MAX_INPUT_BYTES:
            raise TelemetryError("Telemetry exceeds 20 MiB limit")

        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("Expected a JSON object")
        except (json.JSONDecodeError, ValueError) as error:
            print(f"Invalid record at line {line_number}: {error}")
            invalid += 1
            continue

        record_type = record.get("type", "memory_region")
        if record_type == "process":
            if seen_process:
                raise TelemetryError("Multiple process records in telemetry")
            pid = record.get("pid")
            if not _positive_pid(pid):
                raise TelemetryError(f"Invalid process PID at line {line_number}")
            seen_process = True
            metadata_pid = pid
            continue

        if record_type != "memory_region":
            continue

        pid = record.get("pid")
        if pid is not None:
            if not _positive_pid(pid):
                raise TelemetryError(f"Invalid memory-region PID at line {line_number}")
            region_pids.add(pid)

        else:
            regions_without_pid += 1

        permissions = record.get("permissions")
        if not isinstance(permissions, str) or len(permissions) != 4 or any(
            char not in "rwxps-" for char in permissions
        ):
            # Accept only the Linux maps four-character permission form.
            raise TelemetryError(f"Invalid memory permissions at line {line_number}")
        if permissions[0] not in "r-" or permissions[1] not in "w-" or permissions[2] not in "x-" or permissions[3] not in "ps":
            raise TelemetryError(f"Invalid memory permissions at line {line_number}")

        total += 1
        if matches_rule(record, rule):
            alerts.append({
                "rule": rule["id"],
                "severity": rule["severity"],
                "pid": pid,
                "permissions": permissions,
                "start": record.get("start"),
                "end": record.get("end"),
                "path": record.get("path"),
            })

    if seen_process:
        if regions_without_pid or region_pids != {metadata_pid}:
            raise TelemetryError("Memory regions are missing a PID or belong to a different process")
        if any(alert["pid"] != metadata_pid for alert in alerts):
            raise TelemetryError("Alert PID disagrees with process metadata")
    elif len(region_pids) > 1:
        raise TelemetryError("Legacy telemetry mixes several PIDs")

    return total, invalid, alerts


def _atomic_json(path, data):
    fd, temp_path = tempfile.mkstemp(prefix=".shadowrange-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(data, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def write_alerts_atomically(alerts, telemetry_sha256):
    """Publish alerts, then a checksum manifest. Readers reject incomplete pairs."""
    fd, temp_path = tempfile.mkstemp(prefix=".shadowrange-alerts-", suffix=".tmp", dir=OUTPUT_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            for alert in alerts:
                output.write(json.dumps(alert) + "\n")
            output.flush()
            os.fsync(output.fileno())
        with open(temp_path, "rb") as source:
            alerts_sha256 = hashlib.file_digest(source, "sha256").hexdigest()
        manifest = {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "telemetry_sha256": telemetry_sha256,
            "alerts_sha256": alerts_sha256,
            "alert_count": len(alerts),
        }
        os.replace(temp_path, OUTPUT_FILE)
        _atomic_json(METADATA_FILE, manifest)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def main():
    if len(sys.argv) > 2:
        print("Usage: python3 detection_engine/detect.py [telemetry_file]")
        return 1

    input_file = Path(sys.argv[1]) if len(sys.argv) == 2 else INPUT_FILE
    if not input_file.is_file():
        print(f"Telemetry file not found: {input_file}")
        return 1

    try:
        rule = load_rule()
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as error:
        print(f"Cannot load rule: {error}")
        return 1

    try:
        hasher = hashlib.sha256()
        with input_file.open("r", encoding="utf-8", newline="") as source:
            total, invalid, alerts = analyze(source, rule, hasher=hasher)
        write_alerts_atomically(alerts, hasher.hexdigest())
    except (OSError, UnicodeError, TelemetryError) as error:
        print(f"Detection error: {error}")
        return 1

    print("ShadowRange Detection Engine")
    print(f"Rule loaded: {rule['id']}")
    print(f"Regions analyzed: {total}")
    print(f"Invalid records: {invalid}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Evidence manifest: {METADATA_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
