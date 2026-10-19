"""Shared Rule 7 contract: every control has a mapping, candidate, or review.

A source mitigation and a framework objective answer different questions.
Retain useful controls outside the selected framework, with a specific review,
without silently accepting omissions or claiming framework coverage.
"""
from urllib.parse import urlparse

DIRECT_EVIDENCE_METHOD = "direct_objective_evidence"


def direct_evidence_errors(document, controls):
    """Check source attribution for the direct custom-mapping contract.

    Semantic sufficiency still requires review. CCM scores deliberately have no
    role here. Legacy artifacts retain their existing validation behavior.
    """
    if document.get("_metadata", {}).get("framework_mapping_method") != DIRECT_EVIDENCE_METHOD:
        return []
    errors = []
    inventory = {c.get("id"): c for c in controls}
    for row in document.get("framework_mapping", []):
        oid = row.get("objective_id", "<unknown>")
        status = row.get("status")
        if not str(row.get("reason") or "").strip():
            errors.append(f"Evidence: {oid} needs an objective-specific decision reason.")
        if status == "UNCERTAIN" and not str(row.get("review_reason") or "").strip():
            errors.append(f"Evidence: {oid} needs the missing evidence in review_reason.")
        if status != "MAPPED":
            continue
        if not row.get("controls"):
            errors.append(f"Evidence: {oid} is MAPPED without a supporting control.")
        for mapped in row.get("controls", []):
            cid = mapped.get("control_id")
            control = inventory.get(cid)
            if control is None:
                errors.append(f"Evidence: {oid} names unknown control {cid}.")
                continue
            citation = mapped.get("citation")
            if not isinstance(citation, dict) or not str(citation.get("objective_requirement") or "").strip():
                errors.append(f"Evidence: {oid}/{cid} needs a citation naming the supported requirement.")
                continue
            source = citation.get("source")
            if control.get("trace_source") == "threat_model" and source != "threat_model":
                errors.append(f"Evidence: {oid}/{cid} must retain its primary AWS Threat Model citation.")
            if source == "threat_model":
                pairs = {
                    (r.get("alias"), r.get("uuid"))
                    for r in control.get("mitigation_references", [])
                    if isinstance(r, dict) and r.get("alias") and r.get("uuid")
                }
                if control.get("mitigation_alias") and control.get("mitigation_uuid"):
                    pairs.add((control["mitigation_alias"], control["mitigation_uuid"]))
                pair = (citation.get("mitigation_alias"), citation.get("mitigation_uuid"))
                if pair not in pairs:
                    errors.append(f"Evidence: {oid}/{cid} citation must match a source alias/UUID pair on the control.")
            elif source in {"assessment_gap", "aws_doc"}:
                url = citation.get("reference_url", "")
                try:
                    parsed = urlparse(url) if isinstance(url, str) else None
                    valid = parsed and parsed.scheme == "https" and parsed.hostname in {
                        "docs.aws.amazon.com", "aws.amazon.com", "repost.aws"
                    }
                except ValueError:
                    valid = False
                if not valid:
                    errors.append(f"Evidence: {oid}/{cid} supplemental citation needs an AWS reference_url.")
            else:
                errors.append(f"Evidence: {oid}/{cid} needs threat_model, assessment_gap, or aws_doc evidence.")
    return errors


def referenced_controls(mappings):
    return {
        c["control_id"] for row in mappings
        if row.get("status") in ("MAPPED", "UNCERTAIN")
        for c in row.get("controls", []) if c.get("control_id")
    }


def review_errors(mappings, control_ids, reviews):
    """Validate reviews against the actual control/objective inventory."""
    errors = []
    unmatched = set(control_ids) - referenced_controls(mappings)
    objectives = {row.get("objective_id") for row in mappings}
    if not isinstance(reviews, list):
        return ["Rule7: unmapped_control_reviews must be an array."]
    seen = set()
    for review in reviews:
        if not isinstance(review, dict):
            errors.append("Rule7: each unmapped control review must be an object.")
            continue
        cid = review.get("control_id")
        if not isinstance(cid, str) or cid not in unmatched:
            errors.append(f"Rule7: review for {cid!r} is unknown or already referenced by an objective.")
            continue
        if cid in seen:
            errors.append(f"Rule7: duplicate review for {cid}.")
        seen.add(cid)
        candidates = review.get("reviewed_objective_ids")
        reason = review.get("rationale")
        if (review.get("status") != "no_framework_match"
                or not isinstance(reason, str) or not reason.strip()
                or not isinstance(candidates, list) or not candidates
                or any(not isinstance(oid, str) or oid not in objectives for oid in candidates)):
            errors.append(
                f"Rule7: {cid} needs status=no_framework_match, a specific rationale, "
                "and reviewed_objective_ids from this framework."
            )
    missing = sorted(unmatched - seen)
    if missing:
        errors.append(f"Rule7: {len(missing)} controls lack a mapping or documented review: {missing}")
    return errors


def document_review_errors(document, controls):
    return review_errors(
        document.get("framework_mapping", []),
        {c["id"] for c in controls if c.get("id")},
        document.get("unmapped_control_reviews", []),
    ) + direct_evidence_errors(document, controls)
