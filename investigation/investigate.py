"""Display a readable investigation summary from validated ShadowRange evidence."""

import argparse
from pathlib import Path
from evidence import load_evidence, load_windows_snapshot, telemetry_platform
from windows_detection import find_unusual_modules


def investigate(telemetry_path, alerts_path):
    if telemetry_platform(telemetry_path) == "windows":
        process, modules, snapshot_hash = load_windows_snapshot(telemetry_path)
        print("ShadowRange Investigation — Windows")
        print("=" * 32)
        print(f"PID:        {process['pid']}")
        print(f"Name:       {process['name']}")
        print(f"Parent PID: {process.get('ppid', 'unknown')}")
        print(f"Command:    {process.get('cmdline', 'unknown')}")
        print(f"Executable: {process.get('exe', 'unknown')}")
        print(f"Started UTC:   {process.get('start_time_utc', 'unknown')}")
        print(f"Collected UTC: {process.get('collected_at_utc', 'unknown')}")
        print(f"Modules collected: {len(modules)}")
        print(f"Snapshot SHA256: {snapshot_hash}")
        findings = find_unusual_modules(process, modules)
        print(f"Windows suspicious-path findings: {len(findings)}")
        for finding in findings[:10]:
            print(f"  {finding['module']}: {finding['path']} ({finding['reason']})")
        if len(findings) > 10:
            print(f"  ... {len(findings) - 10} additional findings in report")
        print("First 10 modules:")
        for module in modules[:10]:
            print(f"  {module['name']}: {module['path']}")
        print("Note: Unusual paths are investigation leads, not proof of malware.")
        print("Snapshot SHA256 is a local fingerprint, not proof of authenticity.")
        return
    process, regions, alerts, manifest = load_evidence(telemetry_path, alerts_path)
    pid = process["pid"]
    wx_regions = sum(
        isinstance(region.get("permissions"), str)
        and "w" in region["permissions"] and "x" in region["permissions"]
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
    print(f"Evidence SHA256:           {manifest['telemetry_sha256']}")
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
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(1, f"Investigation error: {error}\n")


if __name__ == "__main__":
    main()
