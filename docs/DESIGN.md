# How it works — accuracy & confidence model

This document explains *how* the Service Approval pipeline produces trustworthy
mappings and controls: the deterministic citation gates, the reference-anchoring
of preventive controls, the source-priority order, and the validation layers. If
you just want to install and run the tool, start with the [README](../README.md);
come back here when you want to understand why a mapping was made or how a control
was justified.

---

## Mapping accuracy: a deterministic, citation-gated layer

Every onboarding run requires a matching published AWS Threat Model. Intake
resolves current `main`, follows AWS's release manifest, verifies artifact hashes,
and saves a pinned snapshot with provenance. Service discovery uses the live
manifest and model metadata. Missing services or retrieval errors halt the run.
At entry/resume, `validate_threat_model_input.py` checks the original snapshot
offline. Only a new run fetches upstream. Source defects are advisory and disclosed
through deterministic source accounting and report blocks (P14).

The shared manifest, pre-write/post-write, phase, and integrity gates check the
saved source and its SHA-256 locally. Readable report citations use verified
headings at the fetched commit. Model claims still pass through Research/Validate.
See [THREAT-MODELS.md](THREAT-MODELS.md).

The framework-mapping phase constrains what each control may claim, so a control
is only mapped to an objective it genuinely satisfies — and every confident
mapping shows its evidence. The controls that drive it:

### Service applicability screen

Before mapping begins, the tool derives the service's capabilities and category
from the AWS Threat Model threat model and screens objectives for applicability:

- **`data/service-capability-rules.json`** — capability flags derived from AWS Threat Model
  mitigation *statements only* (never entity description prose, which describes
  the resource but asserts no customer capability). Each flag is three-valued —
  present / absent / unknown — with a required polarity so "AWS manages patching"
  cannot assert a customer capability.
- **`data/service-category-rules.json`** — the service's category label(s)
  (serverless_compute, storage, database, networking, …) derived from those
  flags; a service may hold several.
- **`data/objective-applicability-rules.json`** — marks an objective N/A only for
  a positive structural reason (an organizational objective, or a category fact
  such as "serverless compute has no customer-managed OS to patch"). An unknown
  capability never forces N/A — it defers to the guidance-KB default.
- **`scripts/compute-applicability-matrix.py`** — takes an AWS Threat Model JSON and writes
  an applicability matrix in which every N/A cites the rule and evidence
  (`derived_from`) that drove it.

Datacenter (DCS), endpoint (UEM), HR (HRS), and patching (TVM) objectives are
automatically N/A for serverless services; backup objectives (BCR-08) are N/A for
serverless unless a backup/replication API is definitively present. No capability
is ever inferred from descriptive prose.

### AWS Threat Model traceability (alias + UUID + statement + MITRE)

**`scripts/threat_model_trace.py`** resolves, per AWS Threat Model mitigation, its alias, UUID,
verbatim statement, and MITRE ATT&CK techniques — walking `mitigation → THREAT
mapping → threat → FRAMEWORK mapping` entirely inside the golden-source file (no
external lookup). map-generate-controls threads these onto each control so the
final mapping can cite the exact AWS Threat Model mitigation and MITRE technique behind
every row. The **control catalog** then prints, under each control, its AWS Threat Model
alias, UUID, and verbatim statement (control IDs are minted by the tool because
AWS Threat Model carries none); a control derived from an assessment gap rather than a
AWS Threat Model mitigation is labelled a recommendation.

### Citation verification against AWS Threat Model

**`tools/validate/validate_threat_model_facts.py`** confirms every AWS Threat Model-cited row is
factual against the provided AWS Threat Model export: the cited alias exists, its governed
operations are consistent with the control's actions, and any quoted mitigation
statement appears **verbatim** (normalized for case/whitespace/punctuation) in
the export's `mitigations[].statement`. It runs `--strict` in the map and
post-generate gates, so a fabricated alias, drifted operation, or invented
statement blocks the phase. `MAPPED` rows are checked; `UNCERTAIN` rows and
assessment-gap citations are exempt.

### Per-domain guidance with coverage ceilings

**`data/domain-mapping-guidance/ccmv4.json`** records, per objective, which
mechanism classes may (`allow_mechanisms`) or must never (`deny_mechanisms`)
satisfy it, plus coverage ceilings. Full Coverage is opt-in: a class that only
partially implements an objective's named mechanism (a detective Config rule, or
CMK-existence for classification-driven encryption) is capped at Partial.
Per-service-category overrides (`by_service_category`) let one objective behave
differently for, say, a serverless vs a storage service.

### Citation-as-gate + UNCERTAIN status

Every confident `MAPPED` row carries a `citation` (the specific objective
sub-requirement satisfied + its source — AWS Threat Model mitigation, reference example, or
AWS doc). A relationship the mapper believes but cannot cite concretely is emitted
as **`UNCERTAIN`** with a `review_reason` — surfaced for review, excluded from
coverage %, never silently asserted or dropped.

**`tools/validate/validate_domain_mapping_accuracy.py`** is the deterministic
backstop: it FAILs (1) a row mapped to a not-applicable objective, (2) a coverage
level over the mechanism-class ceiling, (3) a denied-class mis-map, and (4) a
confident `MAPPED` row with no concrete citation (which must be `UNCERTAIN`).

### Report format

`framework-mapping.md` lists **every** framework objective sequentially by
`ID: Title` under its domain — mapped objectives with their control table, N/A
objectives with their reason, and UNCERTAIN objectives flagged for review — so a
reader can scan top-to-bottom and see each objective's disposition (a render-time
check asserts no objective is dropped). The coverage summary shows only Total /
Mapped / Not Applicable / Uncertain. Controls that could not be cited to an
objective are surfaced as **potential recommendations** with a deterministic
"why not yet cited" rationale (covered by a sibling control, candidate objectives
ruled out, or assessment-gap recommendation) rather than reported as lost.
Mitigation-level rollups (coverage-gap and mitigation-traceability tables) live in
`mapping-results.json` for downstream tooling and are not rendered in the
customer reports.

### Custom / non-CCMv4 frameworks

**`scripts/anchor-custom-framework.py`** anchors a custom framework's objectives to
their nearest CCMv4 objective(s) by description (a deterministic TF-IDF cosine), so
the CCMv4 guidance can be reused. A weak anchor yields an `UNCERTAIN` mapping rather
than a confident wrong one.

### Verify

```bash
# Compute the applicability matrix from an AWS Threat Model JSON
python3 scripts/compute-applicability-matrix.py <threat-model-json> --output /tmp/matrix.json

# Validate a mapping against ceilings + citations + applicability
python3 tools/validate/validate_domain_mapping_accuracy.py <map-framework-mapped.json> \
  --controls <map-controls-generated.json> --matrix <applicability-matrix.json>
```

---

## Preventive controls are reference-anchored

Preventive controls are anchored to existing AWS sample policies and reference
repositories; where no reference covers an objective, the tool does not invent a
preventive control — it points to the reference or recommends a detective/proactive
control instead. Every emitted policy is an example to be verified against the
service authorization guide before deployment.

Concretely, preventive generation runs as a gated sub-pipeline: a recommender
decides each objective's enforcement mechanism (SCP / RCP / IAM, or "not
preventable → detective"), anchors each decision to a published example, the
authors adapt that example to the target service, and a root-cause critic proves
every emitted policy both resolves to a reference and actually enforces its
control (a real condition key gates the action). The reference library is curated
from public AWS repositories, including:

- [`aws-samples/service-control-policy-examples`](https://github.com/aws-samples/service-control-policy-examples)
- [`aws-samples/resource-control-policy-examples`](https://github.com/aws-samples/resource-control-policy-examples)
- [`aws-samples/data-perimeter-policy-examples`](https://github.com/aws-samples/data-perimeter-policy-examples)
- [`aws-samples/example-permissions-boundary`](https://github.com/aws-samples/example-permissions-boundary)
- [`aws-samples/iam-access-analyzer-custom-policy-check-samples`](https://github.com/aws-samples/iam-access-analyzer-custom-policy-check-samples)

The sourcing for each generated preventive policy is recorded in the artifact's
`_metadata.reference` (repo + example id + source URL), so the basis for every
control is visible and auditable.

Some preventive mechanisms are **referred rather than authored** by design,
because no vetted example library exists to anchor them to:

- **Trust policies** are refer-only. A role's trust policy and the cross-service
  confused-deputy prevention it implements (`aws:SourceArn` / `aws:SourceAccount`
  on `sts:AssumeRole`) are documented per-service, so the tool points to that
  documented pattern rather than synthesizing a policy body.
- **Permission boundaries** are refer-by-default. A boundary only takes effect
  when the organization attaches one to its principals, so the tool refers to the
  published boundary scaffold unless the run explicitly opts in.

This is an intentional stance: the tool refers rather than authors wherever a
vetted reference library is absent, instead of inventing a policy that looks
plausible but is unanchored.

---

## Source priority

When the tool needs an external fact or citation, it consults sources in one
fixed priority order and cites the highest-priority source that supports the
claim — the same order everywhere facts are pulled (research, validation,
mapping, and preventive recommendation):

1. **AWS Threat Model** — the published mitigation/threat model retrieved during Intake. It
   is the authoritative source of *what* matters for the service (control intent)
   and the top citation.
2. **AWS Control Catalog API** — the control→objective authority for controls the
   catalog covers.
3. **Service-specific AWS documentation** — the target service's own pages only;
   never general blog posts or third-party write-ups.

The reference-repo library above supplies the *vetted policy body* for a
preventive control, adapted under the AWS Threat Model (or catalog/doc) intent — AWS Threat Model
sets what to enforce and is the top citation; the reference repo supplies how.
Each mapping row and each preventive decision records a typed `citation` whose
`type` (`threat_model` / `reference` / `catalog` / `service-doc`) reflects the
highest-priority source that backs it.

---

## How the tool builds confidence

The pipeline does not issue an approve/deny verdict; instead, every run takes the
same concrete, verifiable steps so a reviewer can see exactly what was checked.
These steps are the same on every run, so they are documented here once rather
than repeated in each Summary Report:

- **Capability verification** — every service capability, API parameter, IAM
  action, and condition key is verified against authoritative AWS sources before
  any control is generated; unverified items are reported, not silently dropped.
- **Validators run** — integrity, reference-anchor, preventability/root-cause, and
  control-mapping cross-checks run at the map and generate review gates and again
  in the Stop hook; their pass/fail is recorded in `pipeline.log`.
- **Reference anchoring** — every preventive control either resolves to a public
  AWS reference example or is explicitly marked not-anchored with a stated reason.

Each Summary Report does **not** repeat this generic list. Instead it carries only
the **run-specific** data a reviewer needs:

- A **Preventive Coverage** accounting: a file-backed
  (`preventive-coverage.json`) count of how many preventive objectives have a
  policy authored from a reference example, how many point to a reference the
  customer applies, and how many are covered by detective controls instead — each
  count traceable to its control id and citation, plus the concrete apply/adapt
  guidance for each authored or referred policy.

---

## Validation efforts

Validation runs at several layers:

- **Two review gates.** A post-map gate checks the mapping is citable and its
  prose stays objective-level (the prose lint scans both the JSON and the
  rendered `.md` files for over-claims and upward re-wording), runs the
  deterministic semantic checks (every referenced control resolves, every mapped
  objective exists, no control claims an unverified action/condition key), and
  the AWS Threat Model-factual check. A post-generate gate proves every preventive artifact
  is reference-anchored and actually enforcing.
- **Root-cause critic.** The last step of preventive generation proves each
  emitted policy both resolves to a reference and enforces its control's root
  cause (a real condition key gates the target action); non-enforcing objectives
  are routed to detective rather than shipped.
- **Reference-anchor enforcement** plus **preventability / enforcement /
  action-scope** checks ensure no policy ships unanchored, no Deny is a silent
  no-op, and no Deny widens beyond the reviewed action set.
- **AWS Threat Model-factual check.** Any control citing an AWS Threat Model mitigation must name a
  mitigation that actually exists in the provided export, with consistent gated
  operations — fabricated or drifted citations are flagged.
- **Conflict detection.** A deterministic pre-filter surfaces control pairs that
  contradict each other (a Deny on an action another control allows, or two
  Denies with incompatible conditions), and a clean reviewer confirms each.
- **Per-domain mapping accuracy (CCMv4).** Framework mapping is specialized by
  domain: each CCMv4 domain is mapped in a focused context loaded with only that
  domain's objectives plus curated guidance on what each objective requires and
  which control mechanisms legitimately satisfy it (and which must never), cutting
  the keyword-driven mis-maps a single 197-objective pass produces. Two
  deterministic validators back the guidance — one screens objectives that are
  not applicable to a managed/serverless service, the other flags any control
  whose mechanism class is denied for the objective it was mapped to.

The **deployability checks** that confirm generated artifacts are syntactically
valid and policy-sound run automatically at session end — see
[README → Validation](../README.md#validation).
