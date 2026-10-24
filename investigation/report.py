"""Create an evidence-bound JSON investigation report with safe replacement."""

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from evidence import load_evidence, load_windows_snapshot, telemetry_platform
from windows_detection import find_unusual_modules


def create_report(telemetry_path, alerts_path):
    if telemetry_platform(telemetry_path) == "windows":
        process, modules, snapshot_hash = load_windows_snapshot(telemetry_path)
        findings = find_unusual_modules(process, modules)
        return {
            "project": "ShadowRange",
            "platform": "windows",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "evidence": {"snapshot_sha256": snapshot_hash},
            "process": {
                "pid": process["pid"],
                "name": process["name"],
                "ppid": process.get("ppid"),
                "exe": process.get("exe"),
                "cmdline": process.get("cmdline"),
                "start_time_utc": process.get("start_time_utc"),
                "collected_at_utc": process.get("collected_at_utc"),
            },
            "summary": {
                "modules_collected": len(modules),
                "windows_detection_status": "evaluated",
                "windows_findings": len(findings),
            },
            "modules": modules,
            "alerts": findings,
            "conclusion": (
                "Unusual Windows module paths found; review the listed modules."
                if findings else "No unusual module paths matched; this does not prove the process is safe."
            ),
            "limitations": [
                "Only an unusual module path indicator was evaluated; no match does not prove safety.",
                "AppData and Temp module paths can be legitimate; findings require manual review.",
                "Module access may be incomplete or unavailable; the collector does not record completeness in telemetry.",
                "The snapshot SHA256 is calculated at report time, not verified against an independent trusted baseline.",
            ],
        }
    process, regions, alerts, manifest = load_evidence(telemetry_path, alerts_path)
    wx_count = sum(
        isinstance(region.get("permissions"), str)
        and "w" in region["permissions"] and "x" in region["permissions"]
        for region in regions
    )
    conclusion = (
        "Detection rule matches found; investigate the listed evidence."
        if alerts else "No rule matches found; this does not prove the process is safe."
    )
    return {
        "project": "ShadowRange",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "telemetry_sha256": manifest["telemetry_sha256"],
            "alerts_sha256": manifest["alerts_sha256"],
            "detection_generated_at_utc": manifest["generated_at_utc"],
        },
        "process": {
            "pid": process["pid"],
            "name": process.get("name", "unknown"),
            "state": process.get("state", "unknown"),
            "ppid": process.get("ppid"),
            "cmdline": process.get("cmdline", "unknown"),
            "exe": process.get("exe", "unknown"),
        },
        "summary": {
            "memory_regions": len(regions),
            "writable_executable_regions": wx_count,
            "detection_alerts": len(alerts),
        },
        "alerts": alerts,
        "conclusion": conclusion,
        "limitations": [
            "Only the collected snapshot and configured detection rules were evaluated.",
            "A matching rule is not proof of malicious activity.",
            "The report timestamp is generation time, not collection time.",
            "SHA256 detects mismatches but does not authenticate who collected or modified the evidence.",
        ],
    }


def write_report_atomically(output_path, report):
    fd, temp_path = tempfile.mkstemp(prefix=".shadowrange-report-", suffix=".tmp", dir=output_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as destination:
            json.dump(report, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temp_path, output_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def main():
    parser = argparse.ArgumentParser(description="Generate a ShadowRange JSON report")
    parser.add_argument("--telemetry", type=Path, default=Path("shadowrange.telemetry"))
    parser.add_argument("--alerts", type=Path, default=Path("alerts.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    args = parser.parse_args()
    try:
        report = create_report(args.telemetry, args.alerts)
        write_report_atomically(args.output, report)
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(1, f"Report error: {error}\n")
    print("ShadowRange Report")
    print(f"PID: {report['process']['pid']}")
    if report.get("platform") == "windows":
        print(f"Modules: {report['summary']['modules_collected']}")
        print(f"Windows suspicious-path findings: {report['summary']['windows_findings']}")
    else:
        print(f"Memory regions: {report['summary']['memory_regions']}")
        print(f"Alerts: {report['summary']['detection_alerts']}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
