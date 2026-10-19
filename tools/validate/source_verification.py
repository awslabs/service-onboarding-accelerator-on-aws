"""Local attestation of intake's successful upstream publication verification.

The seal is issued only after the fetcher verifies AWS's pinned release. Its key
is outside generated run state so a caller-supplied manifest cannot attest itself.
This protects the intake contract, not against someone controlling the OS user,
the installed Python code, or the private key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile


def _key_path() -> Path:
    # Override supports isolated installations/tests; never read a key path
    # from an intake manifest or source receipt.
    state = os.environ.get("SERVICE_APPROVAL_TRUST_DIR")
    root = Path(state).expanduser() if state else Path.home() / ".local/state/service-approval"
    return root / "intake-verification.key"


def _key(*, create: bool = False) -> bytes:
    path = _key_path()
    if create:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Publish a fully written key without replacing an existing one.
        # Concurrent new runs must neither rotate the key nor read a partial key.
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(secrets.token_bytes(32))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid local intake verification key")
    return key


def _message(source: dict, path: Path) -> bytes:
    return json.dumps({
        "version": 1,
        "snapshot": str(path.resolve()),
        "source": {k: v for k, v in source.items() if k != "intake_verification"},
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def seal_verified_intake(source: dict, path: Path) -> None:
    """Called by save_latest after upstream verification, never by validators."""
    source["intake_verification"] = {
        "version": 1,
        "signature": hmac.new(_key(create=True), _message(source, path), hashlib.sha256).hexdigest(),
    }


def has_verified_intake(source: dict, path: Path) -> bool:
    """Verify the local seal offline; do not create keys or trust new receipts."""
    proof = source.get("intake_verification")
    if not isinstance(proof, dict) or proof.get("version") != 1:
        return False
    signature = proof.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        expected = hmac.new(_key(), _message(source, path), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)
    except (OSError, ValueError, TypeError):
        return False
