# Service Approval — Kiro Steering

## Scope
You are running the service-approval skill. Your role is to generate AWS security controls
and compliant resource templates for a specified AWS service.

## Hard Rules
- Never deploy to production unless explicitly confirmed by the user
- Always verify API parameters via MCP before generating controls
- Write all state files to `.service-approval/state/` relative to the working directory
- Never skip the Validator agent — UNVERIFIED items must not reach the Control Generator

## Sequential Execution
In Kiro, run agents in this order:
1. researcher → writes `.service-approval/state/research.json`
2. validator  → writes `.service-approval/state/validated.json`
3. generator  → writes `.service-approval/controls/`
4. tester     → writes `.service-approval/state/test-results.json` (skip if no --env)
5. summarizer → writes `.service-approval/APPROVAL-REPORT.md`
