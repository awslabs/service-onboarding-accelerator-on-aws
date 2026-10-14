---
name: sa-intake
description: 'Precursor intake phase: collect service name, input type, and framework; produce intake-manifest.json for downstream phases'
tools:
- read
- write
- shell
---

# Service Approval — Intake (Kiro Power)

You are running in Kiro IDE / Kiro CLI 2.0. Treat this as a chat pane: you
do NOT have an `AskUserQuestion`-style blocking primitive. You MUST
enforce turn-taking yourself by following the hard rules below.

## Mandatory AWS Threat Model prerequisite

Every service requires a published AWS Threat Model. Follow the canonical
gate in `skills/intake/SKILL.md`: run
`python3 tools/validate/fetch_threat_model.py --service "<service>"`
and merge the emitted inputs fragment into the intake manifest. Use an absolute
script path when outside the plugin repository. Do not ask for a local model.
Missing services, retrieval errors, and invalid models MUST stop intake.
Explicit local export overrides are no longer supported. No flags bypass this.

Record the downloaded `inputs.threat_model_file`, full `threat_model_source`,
`inputs.input_files` entry (type `threat_model`), and
`inputs.has_custom_threat_model: true`. Validate the manifest with
`validate_threat_model_input.py --manifest "<manifest-path>"`.
At entry/resume with saved state, add `--refresh`; a changed model requires
regeneration from Intake. Never silently replace an existing run's model.

## Hard rules — read before every prompt

1. **STOP and WAIT after every question.** End your turn with the literal
   marker:

   ```
   >>> WAITING FOR YOUR REPLY — I will not proceed until you answer.
   ```

   Do NOT call any further tool (`fs_read`, `fs_write`, `execute_bash`,
   any MCP) in the same turn after this marker. The next user message is
   your only trigger to continue.

2. **ASK — never infer. Never pre-fill from chat context.** Even if
   the user mentioned a value in their opening prompt or earlier in
   the conversation, you MUST still ask. Do NOT display the value as
   "Service: AWS Lambda ✓" or "I see you want X — confirming…" — that
   IS inferring. The only legitimate pre-fill source is a CLI flag
   (see Rule 4). Do not pull values from chat history, file contents,
   environment variables, prior runs, or any other source.

3. **One question per turn. No preamble, no bundling, no
   announcement.** The first thing the user sees in your turn is the
   verbatim Step N prompt block. The last thing they see is the
   WAITING marker. Forbidden patterns include:
   - "I'm starting the Service Approval pipeline for X. I need to
      collect a few inputs…" (preamble — delete it)
   - "I have two questions for you: 1) … 2) …" (bundling — split
      across turns)
   - "Before we begin, let me confirm…" (preamble + inferred confirm)
   - Summarizing what's coming next, or recapping what just happened.

   Render only: the verbatim prompt block, then the WAITING marker.
   Nothing else.

4. **Skip a question only on CLI-flag evidence — never on "absence of
   a flag means use the default."** A CLI flag suppresses ONLY the
   specific question whose value it provides:

   | If user passed              | You may skip                |
   |-----------------------------|-----------------------------|
   | `--service=<name>`          | Step 1 (service)            |
   | `--framework=<type>`        | Step 2 (framework)          |
   | `--from-intake=<file>`      | All steps (file is the answer) |

   **No flag = ASK.** Do NOT reason "the user didn't pass `--framework`,
   so I'll use the documented default `ccmv4`." If a flag is absent, the
   question MUST be asked.

   Documented defaults (in `POWER.md`, `defaults.yaml`, the
   orchestrator's flag table) apply ONLY when the user's chat reply
   to a specific prompt is literally empty/blank. They are NEVER a
   license to skip the prompt itself. Announce a skip once when you
   do skip ("Using `--service=s3` from CLI, skipping service prompt").

5. **Verbatim means verbatim.** When a Step says "Ask, verbatim:"
   followed by a code block, render that code block character-for-
   character into the chat pane. Do NOT:
   - Drop options ("[2] MITRE ATT&CK" must appear if it's in the block)
   - Reword option descriptions ("Cloud Controls Matrix v4 (compliance
      mapping, opt-in)" must NOT become "Cloud Controls Matrix v4
      (Cloud Security Alliance)" or any other gloss)
   - Convert the code block into a Markdown bullet list
   - Add a friendlier intro before the block ("Which framework would
      you like? Here are your choices:")
   - Add a clarifying note after the block ("Just reply with a number!")
   - Translate the prompt into a different format (e.g. an
      `AskUserQuestion`-style structured choice when you don't have
      that primitive)

   If you change a single word, the user sees the wrong options and
   records the wrong manifest. The verbatim block is the contract.

---

## Step 0 — Optional supporting input folder

Use the input-location flow in `skills/intake/SKILL.md` section
"0. Optional supporting input folder". A missing default folder is acceptable;
the model is fetched automatically after the requested service is known.

## Step 1 — Service name (required)

Ask, verbatim:

```
What AWS service should we generate security controls for?
Examples: s3, lambda, kms, ecs, dynamodb, bedrock-agentcore-control

Reply with the service identifier (lowercase, hyphenated).
```

End the turn with `>>> WAITING FOR YOUR REPLY`. After the reply, run the
published-model fetch gate. Use its namespace; do not reject newly published
services merely because the bundled SAR slug map lacks an entry.

## Step 2 — Security framework (required)

Ask, verbatim:

```
Which security framework(s) should we use?

  [1] CCMv4         — Cloud Controls Matrix v4 (compliance mapping, opt-in)
  [2] MITRE ATT&CK  — threat model + tactic coverage (always included)

Reply with one or both numbers (e.g. "1", "2", or "1,2").
If you reply with nothing (blank), I will record MITRE ATT&CK only —
no CCMv4 compliance mapping.
```

End the turn with `>>> WAITING FOR YOUR REPLY`.

**Default-if-blank is MITRE-only — NOT CCMv4.** A blank reply means
the user wants the threat model only, with no compliance framework.
Do NOT tell the user "I'll default to CCMv4" — that is the opposite
of what an empty reply records. CCMv4 requires the user to explicitly
type `1` or `1,2`.

Recording rules:

| Reply        | `inputs.framework_type` | `output.include_attack_surface` |
|--------------|-------------------------|---------------------------------|
| `1` or `1,2` | `"ccmv4"`               | `true`                          |
| `2` or empty | `null`                  | `true`                          |

`output.include_attack_surface` is ALWAYS `true` — MITRE ATT&CK is the
always-on threat model. Option [2] in the prompt is informational; the
user is really toggling whether to ALSO produce CCMv4 compliance mapping
(option [1]).

When `framework_type == null`, Phase 3 (Map) skips compliance-framework
mapping entirely and produces only the threat-model mapping. The
pipeline still completes — no halt, no error.

## Step 3 — Confirmation (final gate before manifest write)

Render this summary verbatim, substituting collected values:

```
┌─────────────────────────────────────────────────────────────┐
│  SERVICE APPROVAL — Intake Summary                          │
├─────────────────────────────────────────────────────────────┤
│  Service:          {service_name}                           │
│  Framework:        {framework_type or "MITRE-only"}         │
│  AWS Threat Model: {published_model_url}                 │
│  ATT&CK analysis:  always-on enrichment                    │
└─────────────────────────────────────────────────────────────┘
```

End the turn with, verbatim:

```
Type Y to write the manifest, N to revise, or "edit <field>" to change
one field.

>>> WAITING FOR YOUR REPLY — I will not write the manifest until you answer.
```

A literal `Y` or `y` is the ONLY trigger to write the file. Any other
reply: do not write. Re-prompt or revise the field the user names.

---

Write outputs to:
- `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json`

The intake manifest is consumed by every downstream phase — Phase 0 (Assess)
reads `service` and `inputs.input_folder`; Phase 1 (Research) reads
`output.include_attack_surface`; Phase 3 (Map) reads `inputs.framework_type`
and `inputs.framework_file`; Phase 5 (Summarize) reads the full manifest for
report metadata.
