"""Doc-assertion + behavioral test for the summarize artifact manifest.

The manifest must exclude vendored/build directories so an IaC format that
vendors its dependencies (e.g. cdktf's node_modules) cannot balloon the
customer-facing report. This test asserts (1) the summarize SKILL declares the
exclusions, and (2) the documented find command actually drops a planted
node_modules path while keeping a real artifact.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SUMMARIZE = REPO / "skills" / "summarize" / "SKILL.md"

# The find command as documented in the SKILL (kept in sync via test 1).
_MANIFEST_FIND = r"""
find {root} \
  \( -type d \( -name node_modules -o -name .terraform -o -name cdk.out \
       -o -name __pycache__ -o -name .git \) -prune \) -o \
  \( -type f \
     ! -name 'package-lock.json' ! -name 'yarn.lock' ! -name '*.tfstate' \
     ! -name '*.tfstate.backup' ! -name '*.pyc' \
     -print \) | sort
"""


def test_summarize_declares_vendored_exclusions():
    text = SUMMARIZE.read_text()
    for token in ("node_modules", ".terraform", "cdk.out", "__pycache__",
                  "package-lock.json"):
        assert token in text, f"summarize manifest must exclude {token}"


def test_manifest_find_excludes_vendored_keeps_real(tmp_path: Path):
    gen = tmp_path / "05-recommended-guidance"
    # real artifacts
    (gen / "preventive").mkdir(parents=True)
    (gen / "preventive" / "scp-policy.json").write_text("{}")
    (gen / "iac").mkdir()
    (gen / "iac" / "compliant-resource.cfn.yaml").write_text("x")
    # vendored / build noise
    nm = gen / "iac" / "cdktf" / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("junk")
    (gen / "iac" / "cdktf" / "package-lock.json").write_text("{}")
    tf = gen / "iac" / "terraform" / ".terraform" / "providers"
    tf.mkdir(parents=True)
    (tf / "cache.bin").write_text("x")

    cmd = _MANIFEST_FIND.format(root=str(gen))
    out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True).stdout

    assert "scp-policy.json" in out
    assert "compliant-resource.cfn.yaml" in out
    assert "node_modules" not in out
    assert ".terraform" not in out
    assert "package-lock.json" not in out
