"""Shared readers for the current and legacy rule artifact containers."""


def iter_rules(data):
    """Yield (name, rule) for rules[], rules{}, or legacy top-level rules."""
    if not isinstance(data, dict):
        return
    rules = data.get("rules", data)
    if isinstance(rules, list):
        entries = ((f"rule[{i}]", rule) for i, rule in enumerate(rules))
    elif isinstance(rules, dict):
        entries = rules.items()
    else:
        return
    for key, rule in entries:
        if key.startswith("_") or not isinstance(rule, dict):
            continue
        yield rule.get("rule_name") or rule.get("Name") or key, rule


def resource_types(rule):
    """Yield explicitly scoped Config resource types in either field form."""
    plural = rule.get("resource_types") or []
    if isinstance(plural, str):
        plural = [plural]
    if not isinstance(plural, list):
        plural = []
    values = [rule.get("resource_type")] + plural
    for value in dict.fromkeys(v for v in values if isinstance(v, str) and v.strip()):
        yield value.strip()
