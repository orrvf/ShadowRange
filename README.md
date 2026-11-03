# ShadowRange

**ShadowRange** is a lightweight, cross-platform process investigation and security research lab for **Linux and Windows**. It collects process telemetry, applies focused detection rules, examines Portable Executable (PE) files without executing them, and produces JSON investigation reports. A local **controller/agent MVP** can also request collection from Linux and Windows agents through persistent WebSocket connections authenticated with HMAC-SHA256.

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
| Local remote collection | A local controller dispatches allowlisted tasks to authenticated Linux and Windows agents over WebSocket and stores returned JSONL telemetry per task. |

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
  controller/server.py <--- WebSocket + HMAC ---> agent/agent.py (Linux)
                      <--- WebSocket + HMAC ---> windows/agent.ps1 (Windows)
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
| Lab controller | `controller/server.py` | Provides an admin API on loopback, dispatches WebSocket tasks, and stores received telemetry. |
| Agent protocol | `remote_protocol.py` | Shared protocol utilities for authenticated agent/controller messages. |
| Lab credential setup | `controller/setup_lab.py` | Generates private per-agent credentials and an admin token. |
| Linux lab agent | `agent/agent.py` | Connects over authenticated WebSocket and invokes the existing Linux collector for an approved PID. |
| Windows lab agent | `windows/agent.ps1` | Starts the Windows Python agent, which invokes `collect.ps1` for an approved PID. |

## Requirements

**Linux path:** Linux with `/proc` (tested on Ubuntu under WSL), GCC, Python 3, and PyYAML.

```bash
sudo apt update
sudo apt install gcc python3 python3-yaml python3-websockets
```

**Windows path:** Windows PowerShell 5.1 or later, Python 3, and `websockets` version 14–16 for the Windows agent. The analysis/reporting CLIs run with Python 3. PE static analysis additionally requires [`pefile`](https://pypi.org/project/pefile/):

```powershell
py -3 -m pip install "websockets>=14,<17" pefile
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

## Local controller/agent lab (WebSocket + HMAC)

This **single-computer lab** was exercised with Windows and Ubuntu under WSL2. The controller pushes only allowlisted `health` and `collect_process` tasks to visible agents over persistent WebSocket connections; it does **not** provide arbitrary shell execution. Agents are restricted to an explicitly approved PID for process collection. There is no continuous HTTP polling.

**Networking:** The admin API listens on `http://127.0.0.1:8000` only. Agents connect to `ws://<controller-ip>:8001/agent/ws`. Multicast discovery uses group `239.255.77.77` and **UDP port `47077`** (replacing `49822`, which fell in a reserved UDP port range on the tested Windows host). HMAC-SHA256 authenticates messages but **does not encrypt network traffic**. Use only on an isolated, trusted lab network; do not expose these ports to the internet.

### 1. Prepare dependencies and Linux collector

In WSL, from the repository root:

```bash
cd /mnt/c/ShadowRange
sudo apt update
sudo apt install -y gcc python3 python3-yaml python3-websockets
gcc -Wall -Wextra -o proc_monitor/proc_monitor proc_monitor/src/proc_monitor.c
python3 -c 'import websockets; print(websockets.__version__)'
```

The tested WSL package version was `15.0.1`. The supported agent/protocol range for this MVP is `websockets>=14,<17`.

In Windows PowerShell (for the Windows agent):

```powershell
cd C:\ShadowRange
py -3 -m pip install "websockets>=14,<17"
py -3 -c "import websockets; print(websockets.__version__)"
Unblock-File -LiteralPath .\windows\agent.ps1
```

The Windows test used `websockets` `16.1.1`. If PowerShell script execution is restricted by your organization's policy, do not override that policy.

### 2. Generate lab credentials (once)

From WSL in the repository root:

```bash
python3 controller/setup_lab.py --agents linux-lab:linux windows-lab:windows
```

This creates private files:

- `controller/agents.json`: the controller's per-agent credential configuration.
- `controller/admin.env`: the local admin token, sourced by the WSL shell.
- `controller/credentials/linux-lab.json` and `controller/credentials/windows-lab.json`: individual agent credentials.

**Do not run setup again when these credentials already exist.** Never commit or publish these files, share one agent's credential with another agent, or paste token values into issues or logs.

### 3. Controller running in WSL (WSL terminal 1)

Determine the current non-loopback IPv4 address of WSL (it may change after restart):

```bash
ip -4 -o addr show dev eth0
```

Example from the tested machine: `172.27.254.221`. Replace it with the address shown on your computer:

```bash
cd /mnt/c/ShadowRange
source controller/admin.env
python3 controller/server.py --bind 172.27.254.221
```

The agent WebSocket endpoint is then `ws://172.27.254.221:8001/agent/ws`, while the admin API remains on `127.0.0.1:8000`. The `--bind` value should be the actual WSL address, not `0.0.0.0` or `127.0.0.1`. Stop with `Ctrl+C`.

### 4. Linux agent via automatic multicast discovery (WSL terminal 2)

```bash
cd /mnt/c/ShadowRange
TARGET_PID=$$
echo "LINUX_PID=$TARGET_PID"
python3 agent/agent.py \
  --config controller/credentials/linux-lab.json \
  --allowed-pid "$TARGET_PID"
```

The tested Linux agent displayed `HMAC verified; connected; waiting for tasks` without a `--server` argument. The PID is specific to that shell session.

### 5. Windows agent connecting to the WSL controller

In Windows PowerShell, use the **explicit** `-Server` argument for this tested Windows-to-WSL2 configuration:

```powershell
cd C:\ShadowRange
$targetPid = (Get-Process explorer | Select-Object -First 1).Id
Write-Host "WINDOWS_PID=$targetPid"
.\windows\agent.ps1 `
  -AllowedPid $targetPid `
  -Config .\controller\credentials\windows-lab.json `
  -Server "ws://172.27.254.221:8001/agent/ws"
```

Replace `172.27.254.221` with the current WSL address from step 3. A reachability check can help:

```powershell
Test-NetConnection 172.27.254.221 -Port 8001
```

**Verified behavior:** On the tested machine, Windows-to-WSL2 multicast discovery did **not** succeed, including after moving discovery to UDP `47077`; explicitly specifying `-Server` connected successfully with HMAC verification and supported both `health` and `collect_process`. This explicit address does **not** bypass agent authentication or PID restrictions. The likely cause of the failed discovery is the WSL2 virtual networking boundary; the exact network-layer cause was not isolated.

### 6. Alternative: Controller and agent both running in Windows

Automatic multicast discovery **was** tested successfully with both controller and Windows agent running on the same Windows host. Use the Windows host's active IPv4 address, e.g., the tested Wi-Fi address `192.168.1.238` (this is an example, not a fixed value):

```powershell
Get-NetIPConfiguration |
  Where-Object { $_.IPv4DefaultGateway } |
  Select-Object InterfaceAlias, IPv4Address
```

Stop the WSL controller first to avoid conflicting services. Then start the Windows controller from a first PowerShell window:

```powershell
cd C:\ShadowRange
$line = Get-Content .\controller\admin.env |
  Where-Object { $_ -match '^export SHADOWRANGE_ADMIN_TOKEN=' } |
  Select-Object -First 1
$env:SHADOWRANGE_ADMIN_TOKEN = $line -replace '^export SHADOWRANGE_ADMIN_TOKEN=', ''
py -3 .\controller\server.py --bind 192.168.1.238
```

In a second PowerShell window, start the Windows agent **without** `-Server`:

```powershell
cd C:\ShadowRange
$targetPid = (Get-Process explorer | Select-Object -First 1).Id
.\windows\agent.ps1 `
  -AllowedPid $targetPid `
  -Config .\controller\credentials\windows-lab.json
```

The tested output showed `HMAC verified; connected; waiting for tasks`, and the controller logged the `windows-lab` connection. This demonstrates local Windows-to-Windows discovery on one host; it is **not** a test between separate physical computers. Do not allow public-network firewall access.

### 7. Queue tasks and inspect status (WSL controller)

In a third WSL terminal:

```bash
cd /mnt/c/ShadowRange
source controller/admin.env

# Connectivity / health check
curl -sS -X POST http://127.0.0.1:8000/admin/task \
  -H "Authorization: Bearer $SHADOWRANGE_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"windows-lab","action":"health"}'

# Process collection: replace 30164 with the Windows agent's currently approved PID
WINDOWS_PID=30164
curl -sS -X POST http://127.0.0.1:8000/admin/task \
  -H "Authorization: Bearer $SHADOWRANGE_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"windows-lab\",\"action\":\"collect_process\",\"pid\":$WINDOWS_PID}"

curl -sS http://127.0.0.1:8000/admin/status \
  -H "Authorization: Bearer $SHADOWRANGE_ADMIN_TOKEN" | python3 -m json.tool
```

For Linux collection, substitute `linux-lab` and the approved Linux PID. The admin API rejected an unsupported `shell` action (`400`), an unapproved PID (`400`), and unauthenticated access to `/admin/status` (`401`) in local tests.

The controller stores received JSONL telemetry at `controller/data/<task-id>/shadowrange.telemetry` and records its SHA-256 fingerprint. `completed` indicates the task finished; it is not a malware verdict.

### 8. Investigate completed telemetry

The MVP **does not automatically run detection or create investigation reports on receipt**. Run the existing analysis CLI against the telemetry for a completed task:

**Linux task:**

```bash
TASK_ID=<completed-linux-task-id>
TELEMETRY="controller/data/$TASK_ID/shadowrange.telemetry"
python3 detection_engine/detect.py "$TELEMETRY"
python3 investigation/investigate.py --telemetry "$TELEMETRY"
python3 investigation/report.py --telemetry "$TELEMETRY" --output "controller/data/$TASK_ID/report.json"
```

**Windows task:**

```bash
TASK_ID=<completed-windows-task-id>
TELEMETRY="controller/data/$TASK_ID/shadowrange.telemetry"
python3 investigation/investigate.py --telemetry "$TELEMETRY"
python3 investigation/report.py --telemetry "$TELEMETRY" --output "controller/data/$TASK_ID/report.json"
```

In local tests, Linux collection returned 43 memory regions with 0 `MEMORY_WX` alerts, and Windows collection returned 407 loaded modules with 2 unusual module-path findings. Those path findings were investigation leads, not malware diagnoses. Matching SHA-256 fingerprints establish that the analyzed bytes matched the collected snapshot; they do not independently prove the snapshot's origin or authenticity.

## Evidence handling and security considerations

- Linux telemetry validation checks process and region PID consistency, memory-permission formats, and limits record/input sizes.
- Linux detection records hashes of telemetry and alerts in `alerts.meta.json`. Investigation/reporting reject mismatched evidence according to this manifest.
- Report-writing paths are designed to avoid replacing an existing report with partial or invalid output.
- Windows module-path findings are heuristic; legitimate applications commonly load components from user-profile directories.
- The Windows investigation snapshot hash is a local fingerprint, **not** a cryptographic chain of custody tied to collection time.
- The local controller/agent MVP uses per-agent credentials, HMAC-SHA256 authenticated WebSocket messages, replay-resistant protocol checks, an admin bearer token, and allowlisted tasks/PIDs. **HMAC does not encrypt traffic**; this lab configuration is unsuitable for untrusted networks or internet exposure. Admin HTTP is loopback-only.

## Generated and local-only files

These are intended to stay off GitHub (see `.gitignore`):

- Telemetry: `shadowrange.telemetry`, `windows.telemetry`, and `controller/data/`.
- Detection outputs: `alerts.jsonl`, `alerts.meta.json`.
- Reports: `report.json`, `windows-report.json`, `pe-report.json`, `case-report.json`.
- Local lab secrets: `controller/agents.json`, `controller/admin.env`, and `controller/credentials/` (plus any legacy `.shadowrange-lab-tokens` file).
- Compiled binaries, Python caches, and local test files.

The project was validated with local unit tests and controlled manual scenarios; the local tests are intentionally not part of the published repository.

## Current limitations

- **Point-in-time inspection:** no continuous endpoint monitoring, historical event tracing, or automatic blocking.
- **No RAM-content analysis:** Linux inspects memory mappings/permissions, not bytes or memory dumps; Windows inspects loaded modules, not mapped memory protections.
- **Limited detection coverage:** one Linux RWX rule and basic Windows module-path checks. False positives and false negatives are expected.
- **Basic PE analysis:** no disassembly, decompilation, behavior tracing, or dynamic execution analysis.
- **Separate observations:** the unified report aggregates findings but does not automatically correlate artifacts to a single process or incident.
- **Lab-only controller:** persistent authenticated WebSocket tasks on one physical host; not designed for public-network use, stealth, persistence, or arbitrary remote commands. Network traffic is not encrypted.
- **WSL2 discovery boundary:** Windows-to-WSL multicast discovery failed in the tested setup; use the explicit `-Server` address. Windows-to-Windows and WSL-to-WSL automatic discovery worked on the same physical PC.
- **No multi-host validation:** no test across two separate physical computers has been performed.
- **Manual downstream processing:** after remote collection, detection and report generation still run through the existing CLIs.
- **Evidence integrity is limited:** unkeyed SHA-256 checks cannot defend against an adversary who can alter both evidence and its hashes.

## Status

**Current milestone: local cross-platform investigation with authenticated WebSocket controller/agents.** Linux and Windows collection, focused detections, PE static analysis, platform-specific reports, unified case-report generation, and HMAC-authenticated controller/agent tasks have been exercised on one Windows PC with WSL2. Fifteen local unit tests passed, along with manual task, access-control, and connectivity checks. This is a research and learning project; only inspect systems and processes you own or are authorized to investigate.
