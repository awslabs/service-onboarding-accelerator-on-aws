#!/usr/bin/env python3
"""
Cloud Party Facilitator Agent (CLI)

Records approval evidence, captures feedback, and guides the approval workflow
during a Service Onboarding Cloud Party session.

Usage:
    python facilitate.py                    # Interactive mode — walks through all stages
    python facilitate.py --stage session-2  # Jump to a specific stage
    python facilitate.py --summary          # Generate summary from existing evidence
    python facilitate.py --list             # List all recorded evidence

Outputs saved to: .service-approval/approval-evidence/
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

EVIDENCE_DIR = ".service-approval/approval-evidence"

# Stage definitions with pre-configured questions
STAGES = {
    "session-2-gate-1": {
        "title": "Session 2 — Gate 1: MITRE Threats & Mitigating Controls",
        "team": "Security",
        "file": "session-2-gate-1-approval-evidence.md",
        "questions": [
            "Do these MITRE threats accurately represent the risk surface for this service?",
            "Are the mitigating controls sufficient for each threat?",
            "Are controls categorized correctly (proactive/preventative/detective/corrective)?",
            "Are platform/account/resource levels appropriate for each control?",
            "Which controls require manual review or additional context?",
        ],
    },
    "session-2-gate-2": {
        "title": "Session 2 — Gate 2: Controls Mapped to Compliance Objectives",
        "team": "Security",
        "file": "session-2-gate-2-approval-evidence.md",
        "questions": [
            "Do the control-to-objective mappings make sense from a security standpoint?",
            "Are any control objectives missing coverage?",
            "Which mappings need security team input before risk review?",
        ],
    },
    "session-2b": {
        "title": "Session 2b — Risk Team: Compliance Mapping Review",
        "team": "Risk/Compliance",
        "file": "session-2b-approval-evidence.md",
        "questions": [
            "Does the CCMv4 mapping align with your compliance framework and interpretation?",
            "Are control objectives covered comprehensively per your audit requirements?",
            "Which mappings need adjustment for your specific regulatory context?",
            "Are there additional control objectives your framework requires that aren't covered?",
        ],
    },
    "session-3": {
        "title": "Session 3 — Platform Team: Terraform Modules",
        "team": "Platform",
        "file": "session-3-approval-evidence.md",
        "questions": [
            "Do these patterns match your architectural standards?",
            "Are security baselines sufficient?",
            "Which variables need customization?",
            "How do these integrate with existing Artifactory patterns?",
            "Platform team: Do you approve these Terraform modules for testing?",
        ],
    },
    "session-4": {
        "title": "Session 4 — Platform Team: Validation & Testing",
        "team": "Platform",
        "file": "session-4-approval-evidence.md",
        "questions": [
            "Do failures indicate real issues or false positives?",
            "Which controls need refinement?",
            "Platform team: Do you approve the validated Terraform modules?",
        ],
    },
}


def ensure_evidence_dir():
    """Create the evidence directory if it doesn't exist."""
    Path(EVIDENCE_DIR).mkdir(parents=True, exist_ok=True)


def timestamp():
    """Return a formatted timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def prompt_decision():
    """Prompt the user for a decision."""
    print("\n  Decision:")
    print("    [1] Approve")
    print("    [2] Request Changes")
    print("    [3] Iterate (re-run agent with adjustments)")
    print("    [q] Skip this stage")
    while True:
        choice = input("\n  Enter choice (1/2/3/q): ").strip().lower()
        if choice == "1":
            return "APPROVED"
        elif choice == "2":
            return "CHANGES_REQUESTED"
        elif choice == "3":
            return "ITERATE"
        elif choice == "q":
            return None
        print("  Invalid choice. Enter 1, 2, 3, or q.")


def prompt_comments():
    """Prompt for free-text comments."""
    print("\n  Comments (press Enter twice to finish):")
    lines = []
    while True:
        line = input("  > ")
        if line == "" and (len(lines) == 0 or lines[-1] == ""):
            break
        lines.append(line)
    return "\n".join(lines).strip()


def run_stage(stage_key):
    """Run a single approval stage interactively."""
    stage = STAGES[stage_key]
    ts = timestamp()

    print(f"\n{'='*60}")
    print(f"  {stage['title']}")
    print(f"  Team: {stage['team']}")
    print(f"  Time: {ts}")
    print(f"{'='*60}")

    # Present questions
    print("\n  Review Questions:")
    responses = {}
    for i, q in enumerate(stage["questions"], 1):
        print(f"\n  Q{i}: {q}")
        answer = input("  Response (or Enter to skip): ").strip()
        if answer:
            responses[q] = answer

    # Get decision
    decision = prompt_decision()
    if decision is None:
        print(f"\n  Skipped {stage['title']}")
        return None

    # Get comments
    comments = prompt_comments()

    # Build the decision record
    record = {
        "stage": stage_key,
        "title": stage["title"],
        "team": stage["team"],
        "timestamp": ts,
        "decision": decision,
        "responses": responses,
        "comments": comments,
    }

    # Write to markdown file
    write_evidence_md(stage, record)

    # Print confirmation
    status_icon = {"APPROVED": "✅", "CHANGES_REQUESTED": "🔄", "ITERATE": "🔁"}
    print(f"\n  {status_icon.get(decision, '📝')} Decision recorded: {decision}")
    print(f"  Saved to: {EVIDENCE_DIR}/{stage['file']}")

    return record


def write_evidence_md(stage, record):
    """Write an evidence record as a markdown file."""
    ensure_evidence_dir()
    filepath = os.path.join(EVIDENCE_DIR, stage["file"])

    # If file exists, append (supports multiple iterations)
    mode = "a" if os.path.exists(filepath) else "w"
    is_append = mode == "a"

    with open(filepath, mode) as f:
        if not is_append:
            f.write(f"# {stage['title']}\n\n")

        if is_append:
            f.write(f"\n---\n\n## Iteration — {record['timestamp']}\n\n")
        else:
            f.write(f"**Team:** {record['team']}  \n")
            f.write(f"**Timestamp:** {record['timestamp']}  \n")
            f.write(f"**Decision:** {record['decision']}\n\n")

        if is_append:
            f.write(f"**Decision:** {record['decision']}  \n")
            f.write(f"**Timestamp:** {record['timestamp']}\n\n")

        if record["responses"]:
            f.write("### Responses\n\n")
            for q, a in record["responses"].items():
                f.write(f"**Q:** {q}  \n")
                f.write(f"**A:** {a}\n\n")

        if record["comments"]:
            f.write("### Comments\n\n")
            f.write(f"{record['comments']}\n\n")


def generate_summary():
    """Generate a summary.md from all existing evidence files."""
    ensure_evidence_dir()
    evidence_path = Path(EVIDENCE_DIR)
    evidence_files = sorted(evidence_path.glob("session-*.md"))

    if not evidence_files:
        print("\n  No approval evidence recorded yet.")
        return

    summary_lines = [
        "# Cloud Party — Approval Evidence Summary\n",
        f"**Generated:** {timestamp()}\n",
        "---\n",
    ]

    approved = 0
    changes = 0
    iterated = 0

    for df in evidence_files:
        content = df.read_text()
        summary_lines.append(f"\n## {df.stem.replace('-', ' ').title()}\n")

        # Extract decision status from content
        for line in content.split("\n"):
            if line.startswith("**Decision:**"):
                status = line.replace("**Decision:**", "").strip()
                if "APPROVED" in status:
                    approved += 1
                elif "CHANGES_REQUESTED" in status:
                    changes += 1
                elif "ITERATE" in status:
                    iterated += 1
                summary_lines.append(f"- Status: {status}\n")
            elif line.startswith("**Team:**"):
                team = line.replace("**Team:**", "").strip()
                summary_lines.append(f"- Team: {team}\n")
            elif line.startswith("**Timestamp:**"):
                ts = line.replace("**Timestamp:**", "").strip()
                summary_lines.append(f"- Timestamp: {ts}\n")

    summary_lines.append("\n---\n")
    summary_lines.append(f"\n## Totals\n")
    summary_lines.append(f"- ✅ Approved: {approved}\n")
    summary_lines.append(f"- 🔄 Changes Requested: {changes}\n")
    summary_lines.append(f"- 🔁 Iterated: {iterated}\n")
    summary_lines.append(f"- Total evidence records: {approved + changes + iterated}\n")

    summary_path = os.path.join(EVIDENCE_DIR, "summary.md")
    with open(summary_path, "w") as f:
        f.writelines(summary_lines)

    print(f"\n  Summary generated: {summary_path}")
    print(f"  ✅ Approved: {approved} | 🔄 Changes: {changes} | 🔁 Iterated: {iterated}")


def list_evidence():
    """List all recorded approval evidence."""
    evidence_path = Path(EVIDENCE_DIR)
    if not evidence_path.exists():
        print("\n  No evidence directory found.")
        return

    evidence_files = sorted(evidence_path.glob("*.md"))
    if not evidence_files:
        print("\n  No approval evidence recorded yet.")
        return

    print(f"\n  Recorded approval evidence in {EVIDENCE_DIR}/:")
    for df in evidence_files:
        size = df.stat().st_size
        print(f"    {df.name} ({size} bytes)")


def interactive_mode(start_stage=None):
    """Walk through all stages interactively."""
    stage_order = [
        "session-2-gate-1",
        "session-2-gate-2",
        "session-2b",
        "session-3",
        "session-4",
    ]

    # If a start stage is specified, find it
    start_idx = 0
    if start_stage:
        for key in STAGES:
            if start_stage in key:
                start_idx = stage_order.index(key)
                break

    print("\n" + "=" * 60)
    print("  Cloud Party — Facilitator Agent")
    print("  Evidence saved to: .service-approval/approval-evidence/")
    print("=" * 60)

    records = []
    for stage_key in stage_order[start_idx:]:
        record = run_stage(stage_key)
        if record:
            records.append(record)

        # Ask if they want to continue to next stage
        if stage_key != stage_order[-1]:
            cont = input("\n  Continue to next stage? (y/n): ").strip().lower()
            if cont != "y":
                break

    # Generate summary
    if records:
        print("\n  Generating summary...")
        generate_summary()

    print("\n  Cloud Party facilitation session complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Cloud Party Facilitator Agent"
    )
    parser.add_argument(
        "--stage",
        help="Jump to a specific stage (e.g., session-2, session-3)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Generate summary from existing evidence",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all recorded evidence",
    )
    args = parser.parse_args()

    if args.summary:
        generate_summary()
    elif args.list:
        list_evidence()
    else:
        interactive_mode(start_stage=args.stage)


if __name__ == "__main__":
    main()
