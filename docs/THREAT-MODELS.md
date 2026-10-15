# Published AWS Threat Models

A new run requires a matching model published in
[aws/threat-models-for-aws-services](https://github.com/aws/threat-models-for-aws-services).
Intake downloads it automatically from the latest `main`. Unpublished services
are blocked, even if a local model exists. Local export overrides are unsupported.

## One source version per run

The fetch helper resolves current `main` once, reads the release manifest, and
follows its artifact paths at that immutable commit. It verifies the JSON model's
SHA-256, identity, and required structure. Service names come from the manifest
and model metadata; additions require no bundled list update.

Each new run owns a unique snapshot directory under
`.service-approval/_sources/<commit>/<unique-run>/`. Intake records the absolute
`inputs.threat_model_file` and complete `inputs.threat_model_source`. Copy the
helper's inputs fragment without changing those values. Staging promotion does
not invalidate the path, and later runs cannot overwrite it.

```bash
python3 tools/validate/fetch_threat_model.py --service dsql \
  --output .service-approval/_sources/selected-inputs.json
python3 tools/validate/validate_threat_model_input.py --manifest <intake-manifest-path>
```

Run from the user's workspace with an absolute helper path if installed elsewhere.
The optional output is an inputs fragment, not a complete manifest. A resume
reuses the existing runtime manifest and does NOT run fresh intake or fetch latest:

```bash
python3 tools/validate/validate_threat_model_input.py --slug <slug>
```

All phases and resume read the SAME snapshot. Upstream updates, removal, and
network outages do not change or invalidate an active run. Missing or modified
local bytes stop processing: restore the exact original bytes or explicitly
start a new run. The legacy `--refresh` validation flag now revalidates locally;
it does not contact GitHub. No resume command swaps versions beneath old outputs.
An explicit `--clean` fetches a new model first, then removes only that service's
old phase tree, preserving source snapshots and other services.

New intake needs access to the public GitHub API and raw content hosts. Requests
have a 30-second timeout and a 32 MiB artifact limit. Model retrieval failures,
invalid JSON, wrong service, and a JSON hash mismatch remain hard stops.

## Advisory source defects and readable citations

Broken internal references, duplicate/ambiguous source identities, missing readable
report headings, and unreadable/missing reports are advisory when the JSON model
is usable. They do not require an acceptance flag or stop the run. Failed report
hash/encoding checks prevent citing that report's content but do not discard the
verified JSON model. Unsafe manifest paths are never fetched.

Known aliases with verified headings get links at the fetched commit. Missing
headings fall back to the report page; unavailable reports fall back to the JSON
source URL. Aliases and affected controls are flagged in the integrity findings
and control/framework reports. An absent MITRE mapping alone is not defective;
some mitigations address non-adversarial governance objectives.

These provenance links supplement AWS documentation and policy-reference
citations. Research and Validate still verify capability and feasibility claims.

## Identity, accounting, and disclosure

The source alias, original UUID, and internal `M-*` ID are distinct identities.
Normalized research rows retain `alias` and `source_uuid`; controls use canonical
`mitigation_references[{alias,uuid}]` plus compatible legacy fields. Primary alias
and UUID must match; alias and UUID arrays must correspond position by position.
Assembly repairs unique known pairs and records repairs; ordering already-correct
pairs is ordinary normalization and is not reported as a defect. It preserves references
through deduplication and does not guess ambiguous source identities.

Each original source mitigation is accounted for through Research, Validate, and
Map. Uncovered mitigations need an explicit disposition in the generated controls
file: `mitigation_id`, `mitigation_alias`, `mitigation_uuid`, `status`, `rationale`,
and `guidance` for manual guidance. Valid statuses are `manual_guidance`,
`not_applicable`, and `unresolved`. Unresolved mitigations remain visible gaps;
manual guidance is not counted as an automated control.

After Research, Validate, Map, and after writing the summary, run:

```bash
python3 tools/validate/audit_threat_model.py --slug <slug>
```

This writes `threat-model-integrity.json` and `threat-model-integrity.md` at the
service root and adds a concise appendix at the end of `framework-mapping.md`,
after the citation/review sections. Summary and control catalog have no integrity
banner. The appendix separates source-reference defects from processing findings;
the linked detailed audit retains affected controls and correction history.
Hooks also recompute it after validated
writes. P14 checks the actual snapshot and current state, requiring complete,
current disclosure. Findings themselves are not failures; stale or omitted
reporting fails the check. Reports distinguish source-author defects from
processing gaps and show affected control IDs and recorded repairs.

Source mitigation coverage and framework mapping are different checks. Every
source mitigation must be accounted for, but a useful control need not match an
objective in the selected framework. Rule 7 requires a genuine mapping or an
explicit `unmapped_control_reviews` entry with the control ID, `no_framework_match`
status, specific rationale, and closest `reviewed_objective_ids`. Reviewed
unmatched controls remain in the catalog and are disclosed near the bottom of
the framework mapping without increasing coverage. Unexplained omissions fail
merge, state validation, and the final integrity gate.

## Optional supporting inputs

`./input/` contains optional frameworks, requirements, or mitigation reports.
It does not supply the authoritative AWS Threat Model. The default folder may be
absent; an explicitly supplied missing path is an input error. Relative paths
resolve from the working directory, not the YAML file's directory.

User-added content is ignored recursively in `input/`, with explicit exceptions
only for shipped `CCMv4-sample.xlsx` and `sar-slugs.json`. Custom `inputs/`,
`input-*/`, `input_*/`, and `runs/` directories are ignored too. Use paths outside
the repository for other folder names. Do not replace shipped samples with
customer data or force-add downloaded models, user inputs, or derived runtime
state. Tests contain synthetic, hand-authored models only.

Generated alias/UUID mismatches and invalid dispositions remain authoring errors:
repair them against the unambiguous snapshot before final disclosure. P14 rejects
those errors even when listed, while source defects and honest unresolved
coverage remain advisory.
