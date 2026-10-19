"""Keep local intake attestation keys isolated from the developer's installation."""
import pytest


@pytest.fixture(autouse=True)
def isolated_intake_trust(tmp_path, monkeypatch):
    monkeypatch.setenv("SERVICE_APPROVAL_TRUST_DIR", str(tmp_path / "intake-trust"))
