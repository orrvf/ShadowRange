# ShadowRange

**ShadowRange** is a lightweight Linux process investigation and detection project written in C and Python. It collects process metadata and memory mappings from `/proc`, evaluates a YAML-configured detection rule, and produces alerts and a structured investigation report.

**Workflow:** Observe → Collect → Analyze → Detect → Investigate → Report

## What it does

- Selects a Linux process by PID and collects its metadata and memory mappings.
- Writes structured JSON Lines (JSONL) telemetry.
- Evaluates the `MEMORY_WX` rule for memory regions with both write and execute permissions.
- Writes matching findings to `alerts.jsonl`.
- Displays an investigation summary and exports a JSON report.
- Includes four automated tests for basic memory-permission detection behavior.

## Architecture

| Component | Location | Purpose |
| --- | --- | --- |
| C process monitor | `proc_monitor/src/proc_monitor.c` | Reads Linux `/proc` information for a selected PID |
| Rule configuration | `detection_engine/rules/memory_wx.yaml` | Defines the memory permission detection condition |
| Python detection engine | `detection_engine/detect.py` | Processes telemetry and generates alerts |
| Investigation CLI | `investigation/investigate.py` | Displays process context and findings |
| Report generator | `investigation/report.py` | Exports findings and limitations to JSON |
| Unit tests | `tests/test_detection.py` | Checks four permission combinations |

## Requirements

- Linux with `/proc` (also tested under Ubuntu on WSL)
- GCC
- Python 3
- PyYAML

On Ubuntu:

```bash
sudo apt update
sudo apt install gcc python3 python3-yaml
```

## Build and run

Run all commands from the repository root.

**1. Build the monitor**

```bash
gcc -Wall -Wextra -o proc_monitor/proc_monitor proc_monitor/src/proc_monitor.c
```

**2. Collect telemetry for the current shell**

```bash
./proc_monitor/proc_monitor $$
```

You can replace `$$` with a PID you have permission to inspect. This creates `shadowrange.telemetry`.

**3. Run detection**

```bash
python3 detection_engine/detect.py
```

This reads `shadowrange.telemetry` and writes `alerts.jsonl`.

**4. Investigate**

```bash
python3 investigation/investigate.py
```

**5. Generate a report**

```bash
python3 investigation/report.py
```

This creates `report.json` containing process metadata, alert counts, evidence, conclusions, and limitations.

### Using custom input files

```bash
python3 detection_engine/detect.py /path/to/telemetry.jsonl
python3 investigation/investigate.py --telemetry /path/to/telemetry.jsonl --alerts alerts.jsonl
python3 investigation/report.py --telemetry /path/to/telemetry.jsonl --alerts alerts.jsonl --output /path/to/report.json
```

**Keep telemetry and alerts from the same detection run.** The investigation and reporting tools validate matching PIDs, but do not currently associate files with a unique run ID.

## Detection example

The `MEMORY_WX` rule matches a memory region when its permissions include both `w` and `x`:

| Permissions | Match? |
| --- | --- |
| `r--p` | No |
| `r-xp` | No |
| `rw-p` | No |
| `rwxp` | Yes |

An example alert (from synthetic test data):

```json
{"rule":"MEMORY_WX","severity":"medium","pid":9999,"permissions":"rwxp","start":"3000","end":"4000","path":"/tmp/suspicious"}
```

A match is an **investigation indicator**, not proof of malicious behavior. Legitimate applications can also use writable and executable memory.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The current unit tests cover read-only, executable-only, writable-only, and writable-and-executable regions. Manual end-to-end checks have also been performed against a normal Bash process and synthetic suspicious telemetry, including malformed JSON input to the detection engine.

## Generated files

| File | Contents |
| --- | --- |
| `shadowrange.telemetry` | Process metadata and memory regions in JSONL |
| `alerts.jsonl` | Detection matches in JSONL |
| `report.json` | Structured investigation report |

These files, along with the compiled monitor binary, are excluded from Git.

## Limitations

- This is a single-process, point-in-time snapshot, not continuous monitoring.
- Detection currently uses one rule for writable and executable memory.
- Findings do not prove malicious intent, and no findings do not prove safety.
- Access to process information depends on Linux permissions and `/proc` visibility.
- The report timestamp records report generation time, not telemetry collection time.
- Test coverage is currently limited; this is not production endpoint protection software.

## Status and scope

**MVP v0.1:** The six-stage workflow is implemented and has passed basic manual end-to-end checks. Planned improvements include broader tests, controlled scenarios, and improved command-line ergonomics.

ShadowRange is intended for education and authorized security research. Only inspect systems and processes you are authorized to access.
