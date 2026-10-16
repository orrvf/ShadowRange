# \# ShadowRange

# 

# \*\*ShadowRange\*\* is a Linux-based cybersecurity lab focused on host monitoring, detection engineering, and basic security investigations.

# 

# The project aims to explore how system activity can be collected, analyzed, and used to identify potentially suspicious behavior.

# 

# ShadowRange is being developed as a practical learning project, with an emphasis on understanding Linux systems, investigating security events, and building simple, reliable security tools.

# 

# \## Project Objectives

# 

# \- Collect relevant information about Linux processes and memory activity.

# \- Analyze system telemetry to identify potentially suspicious behavior.

# \- Develop and test detection rules using controlled scenarios.

# \- Generate alerts that can support further investigation.

# \- Document findings, limitations, and lessons learned.

# 

# \## Current Capabilities

# 

# The initial prototype includes:

# 

# \- A C-based process monitor that collects memory mapping information from Linux.

# \- Structured telemetry output using JSON Lines (JSONL).

# \- A Python detection engine that analyzes collected telemetry.

# \- YAML-based detection rule configuration.

# \- An initial detection rule for writable and executable memory regions.

# \- Automated tests for basic detection behavior.

# 

# The current monitor collects memory information from its own process. Support for monitoring additional processes is planned.

# 

# \## Technologies

# 

# \- \*\*Linux\*\* — System information and process monitoring.

# \- \*\*C\*\* — Low-level telemetry collection.

# \- \*\*Python\*\* — Telemetry analysis and detection logic.

# \- \*\*YAML\*\* — Detection rule configuration.

# \- \*\*JSONL\*\* — Structured telemetry and alert storage.

# \- \*\*Git \& GitHub\*\* — Version control and project documentation.

# 

# \## Development Roadmap

# 

# \### Phase 1 — Host Telemetry

# 

# Build a basic Linux process monitor and collect structured information about memory regions.

# 

# \*\*Status:\*\* Initial implementation completed.

# 

# \### Phase 2 — Detection Engineering

# 

# Develop detection rules, analyze telemetry, and validate detection behavior using controlled test cases.

# 

# \*\*Status:\*\* Initial implementation completed; further development planned.

# 

# \### Phase 3 — Investigation

# 

# Expand process monitoring capabilities and introduce basic tools for inspecting and investigating detection results.

# 

# \*\*Status:\*\* Planned.

# 

# \### Phase 4 — Testing and Reporting

# 

# Improve test coverage, evaluate detection limitations, and document investigation findings.

# 

# \*\*Status:\*\* Planned.

# 

# \## Project Status

# 

# \*\*Early working prototype — under active development.\*\*

# 

# ShadowRange currently demonstrates basic telemetry collection and rule-based detection. The project will be expanded gradually, with a focus on practical cybersecurity skills rather than building a full endpoint security product.

# 

# \## Disclaimer

# 

# ShadowRange is intended for educational purposes and authorized security research. It is not a production-ready security monitoring or endpoint protection solution.

