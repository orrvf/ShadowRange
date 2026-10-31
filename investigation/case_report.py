"""Combine existing ShadowRange reports into one cross-platform case dossier.

No analysis is invented. Each input remains an independent observation.
"""

import argparse
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_REPORT_BYTES = 10 * 1024 * 1024


def load_report(path, kind):
    if not path.is_file():
        raise ValueError(f"{kind}: file not found: {path}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{kind}: report exceeds 10 MiB")
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind}: invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{kind}: expected JSON object")
    if kind in ("linux", "windows"):
        process = data.get("process")
        if not isinstance(process, dict) or type(process.get("pid")) is not int or process["pid"] <= 0:
            raise ValueError(f"{kind}: missing or invalid process PID")
        if not isinstance(data.get("summary"), dict):
            raise ValueError(f"{kind}: missing summary")
    else:
        digest = data.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[a-fA-F0-9]{64}", digest) is None:
            raise ValueError("pe: missing or invalid SHA-256")
    return {
        "source_file": str(path),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "report": data,
    }


def make_case(inputs):
    if not inputs:
        raise ValueError("Provide at least one report")
    case = {
        "project": "ShadowRange",
        "report_type": "cross_platform_case_dossier",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "observations": inputs,
        "limitations": [
            "Source reports describe separate observations, not necessarily one process or host.",
            "PE static analysis is not automatically linked to either process snapshot.",
            "SHA-256 fingerprints detect changes but do not prove source authenticity.",
            "Rule matches do not prove malicious activity; no matches do not prove safety.",
        ],
    }
    return case


def save_atomic(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".shadowrange-case-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main():
    parser = argparse.ArgumentParser(description="Combine existing ShadowRange reports into one case dossier")
    parser.add_argument("--linux-report", type=Path)
    parser.add_argument("--windows-report", type=Path)
    parser.add_argument("--pe-report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("case-report.json"))
    args = parser.parse_args()
    try:
        pairs = (("linux", args.linux_report), ("windows", args.windows_report), ("pe", args.pe_report))
        inputs = {kind: load_report(path, kind) for kind, path in pairs if path is not None}
        if any(args.output.resolve() == path.resolve() for _, path in pairs if path is not None):
            raise ValueError("Output must not overwrite an input report")
        result = make_case(inputs)
        save_atomic(args.output, result)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Case report error: {exc}\n")
    print("ShadowRange Unified Case Report")
    print("Observations: " + ", ".join(inputs))
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
