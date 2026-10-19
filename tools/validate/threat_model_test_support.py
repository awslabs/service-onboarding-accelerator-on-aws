"""Synthetic source receipts for tests; contains no real AWS model content."""
import hashlib
from threat_model_source import REPOSITORY, artifact_url


def source_receipt(path, namespace="dsql", **overrides):
    commit = "a" * 40
    data_path = f"data/services/{namespace}.json"
    report_path = f"reports/services/{namespace}.md"
    source = {
        "repository": REPOSITORY, "ref": "main", "commit": commit,
        "namespace": namespace,
        "data": {"path": data_path, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
        "report": {"path": report_path, "sha256": "b" * 64},
        "data_url": artifact_url(commit, data_path),
        "report_url": artifact_url(commit, report_path),
        "report_aliases": [],
    }
    source.update(overrides)
    # Synthetic fixtures simulate the already-verified intake boundary. Real
    # publication tests exercise save_latest through a mocked AWS transport.
    from source_verification import seal_verified_intake
    seal_verified_intake(source, path)
    return source
