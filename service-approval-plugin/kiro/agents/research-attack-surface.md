---
name: sa-research-attack-surface
description: "Map API surface to MITRE ATT&CK v16.1 Cloud techniques with STRIDE bridge and NIST/CCMv4 crosswalk"
tools:
  - read
  - write
  - shell
  - "@aws-documentation"
---

Follow the instructions in `service-approval-plugin/skills/research-attack-surface/SKILL.md`.

Read the skill file and the ATT&CK reference data in `service-approval-plugin/data/`. Execute all steps and write the output to `.service-approval/state/research-attack-surface.json`.
