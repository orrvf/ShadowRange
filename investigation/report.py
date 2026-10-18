"""Create a basic JSON investigation report from ShadowRange outputs."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from investigate import read_records


def create_report(telemetry_path, alerts_path):
    telemetry = read_records(telemetry_path)
    alerts = read_records(alerts_path)

    processes = [item for item in telemetry if item.get("type") == "process"]
    regions = [
        item for item in telemetry
        if item.get("type", "memory_region") == "memory_region"
    ]

    if len(processes) != 1:
        raise ValueError("Expected exactly one process record in telemetry")

    process = processes[0]
    pid = process.get("pid")

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise ValueError("Process record has an invalid PID")

    if any(region.get("pid") != pid for region in regions):
        raise ValueError("Memory regions contain a different PID")

    if any(alert.get("pid") != pid for alert in alerts):
        raise ValueError("Alerts contain a different PID; rerun detection")

    wx_count = sum(
        isinstance(region.get("permissions"), str)
        and "w" in region["permissions"]
        and "x" in region["permissions"]
        for region in regions
    )

    if alerts:
        conclusion = "Detection rule matches found; investigate the listed evidence."
    else:
        conclusion = "No rule matches found; this does not prove the process is safe."

    return {
        "project": "ShadowRange",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "process": {
            "pid": pid,
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
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a ShadowRange JSON report")
    parser.add_argument("--telemetry", type=Path, default=Path("shadowrange.telemetry"))
    parser.add_argument("--alerts", type=Path, default=Path("alerts.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    args = parser.parse_args()

    try:
        report = create_report(args.telemetry, args.alerts)
        with args.output.open("w", encoding="utf-8") as destination:
            json.dump(report, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Report error: {error}\n")

    print("ShadowRange Report")
    print(f"PID: {report['process']['pid']}")
    print(f"Memory regions: {report['summary']['memory_regions']}")
    print(f"Alerts: {report['summary']['detection_alerts']}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
