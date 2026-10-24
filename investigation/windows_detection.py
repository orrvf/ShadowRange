"""One transparent Windows indicator: modules loaded from user/temp folders."""
from pathlib import PureWindowsPath

RULE_ID = "WINDOWS_MODULE_UNUSUAL_PATH"


def find_unusual_modules(process, modules):
    """Return investigation leads, not verdicts about maliciousness."""
    findings = []
    for module in modules:
        parts = [part.lower() for part in PureWindowsPath(module["path"]).parts]
        # AppData (user-writable), or a directory actually named Temp.
        if "appdata" in parts:
            reason = "Module loaded from AppData"
        elif "temp" in parts:
            reason = "Module loaded from a Temp directory"
        else:
            continue
        findings.append({
            "rule": RULE_ID,
            "severity": "low",
            "pid": process["pid"],
            "module": module["name"],
            "path": module["path"],
            "reason": reason,
        })
    return findings
