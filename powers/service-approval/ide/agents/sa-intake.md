---
name: sa-intake
description: 'Precursor intake phase: collect service name, input type, framework, and testing preferences; produce intake-manifest.json for downstream phases'
tools:
- read
- write
- shell
---

Follow the instructions in `skills/intake/SKILL.md`.

Read the skill file, execute all steps, and write outputs to:
- `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json`

The intake manifest is consumed by every downstream phase — Phase 0 (Assess)
reads `service` and `inputs.input_folder`; Phase 1 (Research) reads
`output.include_attack_surface`; Phase 3 (Map) reads `inputs.framework_type`
and `inputs.framework_file`; Phase 5 (Test) reads `testing.*`; Phase 6
(Summarize) reads the full manifest for report metadata.

IaC format selection is NOT part of intake — it is discovered in Phase 0
(Assess) Step 2b and recorded in `<slug>/01-assess/iac-support.json`.
