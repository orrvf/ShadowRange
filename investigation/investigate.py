"""Display a readable investigation summary from ShadowRange JSONL outputs."""

import argparse
import json
from pathlib import Path


def read_records(path):
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


def investigate(telemetry_path, alerts_path):
    telemetry = read_records(telemetry_path)
    alerts = read_records(alerts_path)

    processes = [item for item in telemetry if item.get("type") == "process"]
    regions = [item for item in telemetry if item.get("type", "memory_region") == "memory_region"]

    if not processes:
        raise ValueError("No process metadata found in telemetry; collect again with the current monitor")
    if len(processes) != 1:
        raise ValueError("Expected telemetry for exactly one process")

    process = processes[0]
    pid = process.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool):
        raise ValueError("Process metadata has an invalid PID")

    if any(region.get("pid") != pid for region in regions):
        raise ValueError("Telemetry contains memory regions for another PID")

    if any(alert.get("pid") != pid for alert in alerts):
        raise ValueError("Alerts belong to another PID; run detection on this telemetry first")

    wx_regions = sum(
        isinstance(region.get("permissions"), str)
        and "w" in region["permissions"]
        and "x" in region["permissions"]
        for region in regions
    )

    print("ShadowRange Investigation")
    print("=" * 32)
    print(f"PID:        {pid}")
    print(f"Name:       {process.get('name', 'unknown')}")
    print(f"State:      {process.get('state', 'unknown')}")
    print(f"Parent PID: {process.get('ppid', 'unknown')}")
    print(f"Command:    {process.get('cmdline', 'unknown')}")
    print(f"Executable: {process.get('exe', 'unknown')}")
    print()
    print(f"Memory regions:            {len(regions)}")
    print(f"Writable + executable:     {wx_regions}")
    print(f"Detection alerts:          {len(alerts)}")

    if alerts:
        print("\nAlerts")
        print("-" * 32)
        for index, alert in enumerate(alerts, start=1):
            print(f"{index}. Rule: {alert.get('rule', 'unknown')} | Severity: {alert.get('severity', 'unknown')}")
            print(f"   Permissions: {alert.get('permissions', 'unknown')}")
            print(f"   Address: {alert.get('start', '?')} - {alert.get('end', '?')}")
            print(f"   Path: {alert.get('path', 'unknown')}")
    else:
        print("\nNo alerts matched the current detection rule.")

    print("\nNote: Rule matches are not proof of malicious activity; no matches do not prove safety.")


def main():
    parser = argparse.ArgumentParser(description="Inspect ShadowRange telemetry and alerts")
    parser.add_argument("--telemetry", type=Path, default=Path("shadowrange.telemetry"))
    parser.add_argument("--alerts", type=Path, default=Path("alerts.jsonl"))
    args = parser.parse_args()

    try:
        investigate(args.telemetry, args.alerts)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Investigation error: {error}\n")


if __name__ == "__main__":
    main()
