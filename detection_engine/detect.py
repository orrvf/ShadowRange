
import json
import sys
from pathlib import Path

import yaml


INPUT_FILE = Path("shadowrange.telemetry")
OUTPUT_FILE = Path("alerts.jsonl")
RULE_FILE = Path("detection_engine/rules/memory_wx.yaml")


def load_rule():
    with RULE_FILE.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError("Rule must be a YAML object")

    rule_id = rule["id"]
    severity = rule["severity"]
    required = rule["condition"]["permissions_all"]

    if not all(
        isinstance(value, str) and value
        for value in (rule_id, severity, required)
    ):
        raise ValueError("Invalid rule fields")

    return rule


def matches_rule(region, rule):
    permissions = region.get("permissions", "")
    required = rule["condition"]["permissions_all"]

    return (
        isinstance(permissions, str)
        and all(char in permissions for char in required)
    )


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

    total = 0
    alerts = 0
    invalid = 0

    try:
        with input_file.open("r", encoding="utf-8") as source:
            with OUTPUT_FILE.open("w", encoding="utf-8") as output:
                for line_number, line in enumerate(source, start=1):
                    try:
                        region = json.loads(line)

                        if not isinstance(region, dict):
                            raise ValueError("Expected a JSON object")

                    except (json.JSONDecodeError, ValueError) as error:
                        print(f"Invalid record at line {line_number}: {error}")
                        invalid += 1
                        continue

                    # Process metadata is not a memory region.
                    # Records without "type" remain supported.
                    if region.get("type", "memory_region") != "memory_region":
                        continue

                    total += 1



                    if matches_rule(region, rule):
                        alert = {
                            "rule": rule["id"],
                            "severity": rule["severity"],
                            "pid": region.get("pid"),
                            "permissions": region.get("permissions"),
                            "start": region.get("start"),
                            "end": region.get("end"),
                            "path": region.get("path"),
                        }
                        output.write(json.dumps(alert) + "\n")
                        alerts += 1




    except OSError as error:
        print(f"File error: {error}")
        return 1

    print("ShadowRange Detection Engine")
    print(f"Rule loaded: {rule['id']}")
    print(f"Regions analyzed: {total}")
    print(f"Invalid records: {invalid}")
    print(f"Alerts generated: {alerts}")
    print(f"Output: {OUTPUT_FILE}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
