# ShadowRange

**ShadowRange** is a lightweight, cross-platform process investigation and security research lab for **Linux and Windows**. It collects process telemetry, applies focused detection rules, examines Portable Executable (PE) files without executing them, and produces JSON investigation reports. A local **controller/agent MVP** can also request collection from Linux and Windows agents over HTTP.

**Workflow:** Select a process → Collect telemetry → Detect indicators → Validate evidence → Investigate → Report

> **Scope:** ShadowRange is an educational, authorized-investigation prototype, **not** an antivirus, EDR, memory-dump forensic framework, or general-purpose remote shell. Findings are investigation leads, not proof of compromise.

## Capabilities

| Area | What ShadowRange does |
| --- | --- |
| Linux process inspection | Reads process metadata and memory mappings from `/proc` using a C collector. |
| Linux detection | Flags memory regions with both write and execute permissions (`MEMORY_WX`). |
| Windows process inspection | Uses PowerShell to gather process metadata and loaded EXE/DLL modules. |
| Windows detection | Flags loaded modules whose paths are in potentially unusual locations, such as `AppData` or temporary directories. |
| PE static analysis | Extracts PE architecture, entry-point RVA, sections and permissions, imports, file size, and SHA-256. |
| Investigation and reporting | Displays process findings, validates evidence according to platform, and writes structured JSON reports. |
| Unified case report | Combines existing Linux, Windows, and PE reports as separate observations without asserting that they concern the same executable or process. |
| Local remote collection | A localhost-only controller queues allowlisted collection tasks for visible Linux and Windows agents and stores returned JSONL telemetry per task. |

## Architecture

```text
Linux                                 Windows
  proc_monitor (C, /proc)               collect.ps1 (PowerShell)
        |                                      |
        v                                      v
  process + memory_region JSONL          process + module JSONL
        |                                      |
        v                                      v
  detect.py (MEMORY_WX)                  windows_detection.py
        |                                      |
        +-------------+------------------------+
                      |
                      v
          investigate.py / report.py
                      |
                      v
                JSON reports
                      |
   PE file --> analyze_pe.py --> PE report
                      |
                      v
           case_report.py (unified report)

Local remote-collection option:
  controller/server.py <-- localhost HTTP polling --> agent/agent.py (Linux)
                     \<-- localhost HTTP polling --> windows/agent.ps1 (Windows)
                      |
                      v
             controller/data/<task-id>/shadowrange.telemetry
             (run the existing investigation pipeline on this file)
```

### Main source files

| Component | Location | Responsibility |
| --- | --- | --- |
| Linux collector | `proc_monitor/src/proc_monitor.c` | Collects process and memory-map data for one PID. |
| Linux rule | `detection_engine/rules/memory_wx.yaml` | Configures the write-and-execute indicator. |
| Linux detection | `detection_engine/detect.py` | Validates JSONL, generates alerts, and records evidence checksums. |
| Windows collector | `windows/collect.ps1` | Collects process metadata and loaded modules. |
| Windows path detection | `investigation/windows_detection.py` | Identifies module paths warranting review. |
| Investigation CLI | `investigation/investigate.py` | Summarizes Linux or Windows evidence. |
| Evidence validation | `investigation/evidence.py` | Checks consistency and evidence integrity according to the investigation path. |
| Report generation | `investigation/report.py` | Exports a platform-specific investigation report. |
| PE analysis | `pe_analysis/analyze_pe.py` | Performs static PE parsing with `pefile`. |
| Unified case report | `investigation/case_report.py` | Aggregates independently produced reports. |
| Lab controller | `controller/server.py` | Queues tasks, receives telemetry, and exposes local status. |
| Linux lab agent | `agent/agent.py` | Polls the controller and invokes the existing Linux collector for an allowed PID. |
| Windows lab agent | `windows/agent.ps1` | Polls the controller and invokes `collect.ps1` for an allowed PID. |

## Requirements

**Linux path:** Linux with `/proc` (tested on Ubuntu under WSL), GCC, Python 3, and PyYAML.

```bash
sudo apt update
sudo apt install gcc python3 python3-yaml
```

**Windows path:** Windows PowerShell 5.1 or later for the collector and Windows agent. The analysis/reporting CLIs run with Python 3. PE static analysis additionally requires [`pefile`](https://pypi.org/project/pefile/):

```powershell
py -3 -m pip install pefile
```

Run the commands below from the repository root unless otherwise noted.

## Local Linux investigation

Build the collector:

```bash
gcc -Wall -Wextra -o proc_monitor/proc_monitor proc_monitor/src/proc_monitor.c
```

Collect your shell's process information and memory maps, detect RWX mappings, inspect the result, and generate a report:

```bash
./proc_monitor/proc_monitor $$
python3 detection_engine/detect.py
python3 investigation/investigate.py
python3 investigation/report.py
```

Outputs include `shadowrange.telemetry`, `alerts.jsonl`, `alerts.meta.json`, and `report.json`.

To investigate a different telemetry file, use the same file consistently across detection and reporting:

```bash
python3 detection_engine/detect.py /path/to/telemetry.jsonl
python3 investigation/investigate.py --telemetry /path/to/telemetry.jsonl
python3 investigation/report.py --telemetry /path/to/telemetry.jsonl --output linux-report.json
```

The default alert and checksum-manifest filenames are written in the repository root. **Run detection immediately before investigating the corresponding Linux telemetry** to avoid mixing evidence from separate runs.

### Linux detection rule

The `MEMORY_WX` rule detects memory mappings whose permissions contain both `w` and `x`.

| Permission example | Match? |
| --- | --- |
| `r--p` | No |
| `r-xp` | No |
| `rw-p` | No |
| `rwxp` | Yes |

This is an indicator requiring review; writable and executable mappings can occur in legitimate software.

## Local Windows investigation

From **Windows PowerShell**, select a process and run the collector:

```powershell
cd C:\ShadowRange
$targetPid = (Get-Process explorer | Select-Object -First 1).Id
.\windows\collect.ps1 -TargetPid $targetPid
```

The collector prints the **actual output path**; its default may be outside the repository directory. Move or copy that JSONL file into the repository as `windows.telemetry` before running the following commands in WSL:

```bash
python3 investigation/investigate.py --telemetry windows.telemetry
python3 investigation/report.py --telemetry windows.telemetry --output windows-report.json
```

The Windows path displays process details, module counts, and suspicious-path findings. It does **not** run the Linux `MEMORY_WX` rule against Windows module records. A module loaded from `AppData` may be entirely legitimate; path-only detection can produce false positives.

## Static PE analysis

Analyze a Windows EXE or DLL **without launching it**:

```powershell
cd C:\ShadowRange
py -3 .\pe_analysis\analyze_pe.py C:\Windows\System32\notepad.exe --output pe-report.json
```

The PE report contains file size, SHA-256, architecture, PE type, entry-point RVA, section permissions, and imported DLLs/functions. Imports show declared dependencies, **not** proof that a function executed.

## Unified case reporting

After separately generating `report.json` (Linux), `windows-report.json` (Windows), and `pe-report.json` (PE analysis), combine them in WSL:

```bash
python3 investigation/case_report.py \
  --linux-report report.json \
  --windows-report windows-report.json \
  --pe-report pe-report.json \
  --output case-report.json
```

The result is a **collection of separate observations**. The tool does not establish that the PE file analyzed is the same executable as a collected process, or that the Linux and Windows observations are related.

## Local remote investigation MVP

The controller and agents add **task-based collection on the same computer**. They were exercised using a Windows host and Ubuntu/WSL over `127.0.0.1:8000`. This is **not** a hardened or internet-accessible C2 service. The agents are launched visibly, operate on an explicitly allowed PID, and do not offer arbitrary shell execution.

### 1. Build the Linux collector

```bash
gcc -Wall -Wextra -o proc_monitor/proc_monitor proc_monitor/src/proc_monitor.c
```

### 2. Create local lab tokens (once)

From WSL in the repository root:

```bash
python3 - <<'PY'
import secrets
from pathlib import Path
p = Path('.shadowrange-lab-tokens')
if p.exists():
    raise SystemExit('Token file already exists')
p.write_text(
    'export SHADOWRANGE_AGENT_TOKEN=' + secrets.token_hex(24) + '\n' +
    'export SHADOWRANGE_ADMIN_TOKEN=' + secrets.token_hex(24) + '\n'
)
p.chmod(0o600)
print('Local lab tokens created')
PY
```

Never commit or publish this file. If the file already exists, reuse it rather than regenerating tokens while agents are running.

### 3. Start the controller (WSL terminal 1)

```bash
cd /mnt/c/ShadowRange
source .shadowrange-lab-tokens
python3 controller/server.py
```

The controller binds to **`127.0.0.1:8000`**. Stop it with `Ctrl+C`.

### 4. Start the Linux agent (WSL terminal 2)

```bash
cd /mnt/c/ShadowRange
source .shadowrange-lab-tokens
TARGET_PID=$$
echo "TARGET_PID=$TARGET_PID"
python3 agent/agent.py --allowed-pid "$TARGET_PID"
```

### 5. Queue a Linux collection (WSL terminal 3)

Use the PID printed in terminal 2:

```bash
cd /mnt/c/ShadowRange
source .shadowrange-lab-tokens
TARGET_PID=12345  # replace with the allowed PID
curl -sS -X POST http://127.0.0.1:8000/admin/task \
  -H "Authorization: Bearer $SHADOWRANGE_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"linux-lab\",\"action\":\"collect_process\",\"pid\":$TARGET_PID}"
```

Check agent and task status:

```bash
curl -sS http://127.0.0.1:8000/admin/status \
  -H "Authorization: Bearer $SHADOWRANGE_ADMIN_TOKEN"
```

When completed, the controller records a task ID and saves telemetry under `controller/data/<task-id>/shadowrange.telemetry`.

### 6. Optional Windows agent on the same PC

First verify that Windows can reach the WSL controller:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Then, in **Windows PowerShell**:

```powershell
cd C:\ShadowRange
$targetPid = (Get-Process explorer | Select-Object -First 1).Id
Unblock-File .\windows\agent.ps1
.\windows\agent.ps1 -AllowedPid $targetPid
```

Use the same `/admin/task` request as above, but set `agent_id` to `windows-lab` and `pid` to the Windows PID shown by PowerShell. The Windows agent calls the existing Windows collector and returns its JSONL output to the controller.

### 7. Analyze collected telemetry

The MVP **does not automatically perform detection or write the investigation report on receipt**. After a task is marked `completed`, run the existing investigation path against its stored file:

**Linux task:**

```bash
TASK_ID=<completed-task-id>
TELEMETRY="controller/data/$TASK_ID/shadowrange.telemetry"
python3 detection_engine/detect.py "$TELEMETRY"
python3 investigation/investigate.py --telemetry "$TELEMETRY"
python3 investigation/report.py --telemetry "$TELEMETRY" --output "controller/data/$TASK_ID/report.json"
```

**Windows task:**

```bash
TASK_ID=<completed-task-id>
TELEMETRY="controller/data/$TASK_ID/shadowrange.telemetry"
python3 investigation/investigate.py --telemetry "$TELEMETRY"
python3 investigation/report.py --telemetry "$TELEMETRY" --output "controller/data/$TASK_ID/report.json"
```

The controller records a SHA-256 fingerprint of returned telemetry. A matching hash verifies the same bytes were used; it does not independently prove their authenticity or trustworthiness.

## Evidence handling and security considerations

- Linux telemetry validation checks process and region PID consistency, memory-permission formats, and limits record/input sizes.
- Linux detection records hashes of telemetry and alerts in `alerts.meta.json`. Investigation/reporting reject mismatched evidence according to this manifest.
- Report-writing paths are designed to avoid replacing an existing report with partial or invalid output.
- Windows module-path findings are heuristic; legitimate applications commonly load components from user-profile directories.
- The Windows investigation snapshot hash is a local fingerprint, **not** a cryptographic chain of custody tied to collection time.
- The localhost remote MVP uses bearer tokens and allowlisted tasks. **HTTP on localhost is not an appropriate secure transport for deployment to separate machines or untrusted networks.** Such use would require transport security, stronger identity and authorization controls, and further hardening.

## Generated and local-only files

These are intended to stay off GitHub (see `.gitignore`):

- Telemetry: `shadowrange.telemetry`, `windows.telemetry`, and `controller/data/`.
- Detection outputs: `alerts.jsonl`, `alerts.meta.json`.
- Reports: `report.json`, `windows-report.json`, `pe-report.json`, `case-report.json`.
- Local lab secrets: `.shadowrange-lab-tokens`.
- Compiled binaries, Python caches, and local test files.

The project was validated with local unit tests and controlled manual scenarios; the local tests are intentionally not part of the published repository.

## Current limitations

- **Point-in-time inspection:** no continuous endpoint monitoring, historical event tracing, or automatic blocking.
- **No RAM-content analysis:** Linux inspects memory mappings/permissions, not bytes or memory dumps; Windows inspects loaded modules, not mapped memory protections.
- **Limited detection coverage:** one Linux RWX rule and basic Windows module-path checks. False positives and false negatives are expected.
- **Basic PE analysis:** no disassembly, decompilation, behavior tracing, or dynamic execution analysis.
- **Separate observations:** the unified report aggregates findings but does not automatically correlate artifacts to a single process or incident.
- **Lab-only controller:** local HTTP polling on one host; not designed for public-network use, stealth, persistence, or arbitrary remote commands.
- **Manual downstream processing:** after remote collection, detection and report generation still run through the existing CLIs.
- **Evidence integrity is limited:** unkeyed SHA-256 checks cannot defend against an adversary who can alter both evidence and its hashes.

## Status

**Current milestone: local cross-platform investigation and remote-collection MVP.** Linux and Windows collection, focused detections, PE static analysis, platform-specific reports, unified case-report generation, and localhost controller/agent collection have been exercised in a lab. This is a research and learning project; only inspect systems and processes you own or are authorized to investigate.
