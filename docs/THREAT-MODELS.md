# Published AWS Threat Models

Every run requires a matching model published in
[aws/threat-models-for-aws-services](https://github.com/aws/threat-models-for-aws-services).
Intake downloads it automatically. Customers supply a service name and any optional
supporting documents or framework; they no longer supply a threat-model JSON file.
A service that AWS has not published is blocked, even if a local model exists.

## Retrieval and provenance

`tools/validate/fetch_threat_model.py --service dsql` resolves the latest `main`
commit through GitHub's public API, reads the release's `manifest.json`, and follows
its service data and readable report references at that immutable commit. It
checks the manifest's SHA-256 hashes and the pipeline's model shape and identity
requirements. Service namespaces come from the manifest; friendly names and IAM
identifiers come from model metadata. New models and updates require no tooling
or bundled service-list change as long as the published format remains compatible.

The helper writes the validated model to the ignored workspace path
`.service-approval/_sources/<commit>/<namespace>.json` and emits an intake inputs
fragment. Merge it into `inputs`, preserving `threat_model_file` and the complete
`threat_model_source` object. The source records the repository, commit, namespace,
release version, retrieval time, artifact paths, hashes, and pinned report links.
The snapshot path survives staging-to-service promotion.

Run the helper from the user's workspace, using an absolute script path if the
plugin is installed elsewhere. Its optional `--output` writes the inputs fragment
under `.service-approval/`; it is not a complete intake manifest.

```bash
python3 tools/validate/fetch_threat_model.py --service dsql \
  --output .service-approval/_sources/selected-inputs.json
python3 tools/validate/validate_threat_model_input.py --manifest <intake-manifest-path>
```

Downloaded models and model-derived state remain runtime data. Do not commit them
or bundle them with the plugin. Repository tests use synthetic, hand-authored models.

## Resume and failures

At every pipeline entry/resume with saved state, run:

```bash
python3 tools/validate/validate_threat_model_input.py --slug <slug> --refresh
```

This checks the latest upstream release. If the service is missing, retrieval fails,
or its model bytes changed, the run stops. A changed model requires a fresh Intake
and regeneration of all downstream output. Existing snapshots and results are not
overwritten. Changes to unrelated services do not invalidate an unchanged model.
The original pinned report remains the citation source for an unchanged run.

Within one active run, per-phase checks and hooks validate the saved source and
content hash locally. They do not repeatedly fetch GitHub during individual file
writes. A `--clean` run retrieves first, then clears only the selected service's old
phase output, preserving `_sources` and other services. No flags bypass this gate.

Network access to `api.github.com/repos/aws/threat-models-for-aws-services/` and
`raw.githubusercontent.com/aws/threat-models-for-aws-services/` is required in both
MCP and No-MCP modes. Requests have a 30-second timeout and a 32 MiB artifact limit.
GitHub errors and rate limits are surfaced; retry after access is restored. There
is no stale-cache or local-file fallback. Legacy `--threat-model-file` and YAML
`input.threat_model_file` overrides are rejected by Intake; recreate old manifests
with published provenance before resuming. The standalone local validator can
still inspect an export, but an export without published provenance cannot pass
the manifest, phase, or integrity gates.

## Readable citations

The normalized index includes `threat_model_url` for mitigation/implementation
aliases whose headings exist in the hash-verified report. Map assembly derives
clickable source aliases in `controls-catalog.md` and `framework-mapping.md` from
the selected model and provenance. Links use the fetched commit, keeping the
cited evidence stable after upstream updates. For example, a heading named
`Mitigation.DSQL.Cluster.4` uses `#mitigationdsqlcluster4`.

Readable model links supplement existing AWS documentation and reference-policy
citations. Research/Validate must still verify AWS capability claims and policy
feasibility; publication alone does not prove those claims. Preventive reference
anchors and existing citation validators remain required.
