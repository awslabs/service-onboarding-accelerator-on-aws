# Shared CAF domain research checklist

Use this checklist with the Assess skill's Assessment Depth Requirements,
Factual Checkpoint Verification, and domain synthesis/validation rules. It is
part of the installed skill; no local client-specific instruction file is needed.

Discover the target service's documentation through `awsknowledge` or
`aws-documentation`. Search using the actual service name and the topics below,
then read the relevant official pages. Reuse already retrieved evidence where
it covers an item, and continue truncated tables when needed for a complete
enumeration. In No-MCP mode, follow the skill's documented web fallback.

| Domain | Required discovery topics | Required reads and evidence |
|--------|---------------------------|-----------------------------|
| IAM | IAM integration, identity/resource policies, condition keys, ABAC, managed policies, service-linked roles | The service SAR page and IAM/security guide; supported actions/resources/conditions, policy types, tag authorization by resource, managed policies and service-linked role permissions |
| LOGGING | CloudTrail, data and network events, CloudWatch metrics, AWS Config | Service logging/monitoring pages and the three LOGGING checkpoint pages; event types/selectors, complete metric namespaces/names, Config resource types and relationships |
| INFRA | VPC endpoints, network access, Console Private Access, CloudFormation, quotas, SCP/RCP, declarative policies, RAM | Service networking and quota documentation, CloudFormation resource reference, and the INFRA checkpoint pages; resource/API scope and documented support limitations |
| DATA | Encryption at rest and in transit, KMS key options, FIPS, compliance scope, backup/recovery, replication | Service data-protection and recovery documentation and the DATA checkpoint pages; per-resource encryption/key types, TLS behavior, exact FIPS endpoints and program scope |
| INCIDENT | Incident response, service-specific security integrations, access revocation, recovery and operational tagging | Service-specific response/recovery guidance and relevant API/SAR evidence; supported response operations, their limits, and any explicit integration evidence |

For every topic, record the source and finding, or the attempted search and the
unresolved evidence gap. A failed search or unavailable tool does not establish
that a feature is unsupported. Use definitive negative answers only where an
authoritative exhaustive source supports them, as specified by the checkpoint
rules. Additional knowledge-base results may aid discovery but do not replace
the public AWS evidence required by the skill.

Each domain must attempt every listed topic before synthesis, include its depth
markers, and cite the evidence in `domains/{DOMAIN}-research.md`. The shared
checkpoint pass may supply evidence to several domains; do not repeat calls just
to produce separate logs. Observe the Assess skill's call caps and deduplication
rules.
