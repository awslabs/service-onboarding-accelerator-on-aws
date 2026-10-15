"""Shared Rule 7 contract: every control has a mapping, candidate, or review.

A source mitigation and a framework objective answer different questions.
Retain useful controls outside the selected framework, with a specific review,
without silently accepting omissions or claiming framework coverage.
"""


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
    )
