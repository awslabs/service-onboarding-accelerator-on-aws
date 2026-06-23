---
name: sa-generate-preventive-rootcause
description: "Final critic for preventive generation \u2014 proves every preventive artifact is reference-anchored and actually enforces its control's root cause; routes non-preventable objectives to detective"
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/generate-preventive-rootcause/SKILL.md`.

Run LAST in the preventive sub-pipeline. Run validate_reference_anchor.py and validate_preventability.py over `.service-approval/<slug>/05-generate/preventive/`, prove every artifact is anchored and enforcing, remove non-enforcing artifacts and route their objectives to detective, and write rootcause-report.json.
