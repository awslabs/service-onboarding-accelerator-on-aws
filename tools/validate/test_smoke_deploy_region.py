"""Region-precedence tests for scripts/smoke-deploy-test.sh.

The Phase 5 deploy script must pin the region from an explicit precedence
chain (--region flag > intake config > ambient env > hardcoded default) so
a stale AWS_REGION exported by the harness cannot redirect a deploy to the
wrong region. These tests run the script in a controlled subdir + env
combination and parse the printed
    Region: <value>  (source: <source-label>)
banner that the script emits before any aws CLI call.

We deliberately stop the script before it tries to deploy by giving it an
empty IaC directory — the slug/region preflight banner still fires, which
is all we need to assert resolution behaviour.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "smoke-deploy-test.sh"


# The source label can itself contain parens (e.g.,
# "intake.json (.testing.region)"), so we anchor the match on the trailing
# `)` at end-of-line rather than greedily refusing parens inside.
_REGION_LINE_RE = re.compile(
    r"^\s*Region:\s+(?P<region>\S+)\s+\(source:\s+(?P<source>.+)\)\s*$",
    re.MULTILINE,
)


def _make_workspace(tmp_path: Path, slug: str, intake_region: str | None) -> Path:
    """Create a minimal .service-approval/<slug>/ tree the script accepts.

    The 05-generate/iac/ subdir must exist so slug auto-discovery works,
    but we leave it without templates so neither terraform nor
    cloudformation actually run — the script falls through to "no
    smoke-test.tfvars" / "no smoke-test-params.json" SKIP branches.
    """
    iac = tmp_path / ".service-approval" / slug / "05-generate" / "iac"
    iac.mkdir(parents=True)
    (iac / "cloudformation").mkdir()
    (iac / "terraform").mkdir()

    if intake_region is not None:
        intake_dir = tmp_path / ".service-approval" / slug / "00-intake"
        intake_dir.mkdir(parents=True)
        (intake_dir / "intake.json").write_text(
            '{"testing": {"region": "' + intake_region + '"}}'
        )
    return tmp_path


def _run_script(
    cwd: Path, args: list[str], env_overrides: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run smoke-deploy-test.sh with a stripped env so only the explicit
    overrides influence resolution. AWS_PROFILE is explicitly cleared so
    `aws sts get-caller-identity` falls through quickly to the slug
    preflight (we don't actually want a successful AWS call here)."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(cwd)),
        # Force a non-routable AWS_PROFILE so sts fails fast — the script
        # exits before doing any real work, but only AFTER printing the
        # resolved region banner.
        "AWS_PROFILE": "no-such-profile-for-region-test",
    }
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _extract_region(stdout: str) -> tuple[str, str]:
    m = _REGION_LINE_RE.search(stdout)
    if not m:
        raise AssertionError(
            f"Region banner not found in script stdout:\n---\n{stdout}\n---"
        )
    return m.group("region"), m.group("source")


@pytest.mark.skipif(not SCRIPT.exists(), reason="smoke-deploy-test.sh not present")
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
class TestRegionResolution:
    def test_explicit_flag_wins_over_intake_and_env(self, tmp_path: Path):
        """--region=<r> overrides intake.json AND ambient AWS_REGION."""
        ws = _make_workspace(tmp_path, "test-svc", intake_region="eu-west-1")
        result = _run_script(
            ws,
            ["--region=us-east-1", "--slug=test-svc"],
            {"AWS_REGION": "ap-southeast-2"},
        )
        region, source = _extract_region(result.stdout)
        assert region == "us-east-1", (
            f"Expected --region flag to win; got {region} (source={source})"
        )
        assert "--region flag" in source

    def test_intake_wins_over_env(self, tmp_path: Path):
        """When --region is absent, intake.testing.region beats AWS_REGION."""
        ws = _make_workspace(tmp_path, "test-svc", intake_region="eu-west-1")
        result = _run_script(
            ws,
            ["--slug=test-svc"],
            {"AWS_REGION": "ap-southeast-2"},
        )
        region, source = _extract_region(result.stdout)
        assert region == "eu-west-1", (
            f"Expected intake.region to win over AWS_REGION; got {region}"
        )
        assert "intake.json" in source

    def test_env_used_when_no_intake_or_flag(self, tmp_path: Path):
        """Ambient AWS_REGION is the fallback when intake has no region."""
        ws = _make_workspace(tmp_path, "test-svc", intake_region=None)
        result = _run_script(
            ws,
            ["--slug=test-svc"],
            {"AWS_REGION": "ap-southeast-2"},
        )
        region, source = _extract_region(result.stdout)
        assert region == "ap-southeast-2"
        assert "ambient" in source.lower()

    def test_default_us_east_1_when_nothing_set(self, tmp_path: Path):
        """With no flag, no intake, no env — falls through to us-east-1."""
        ws = _make_workspace(tmp_path, "test-svc", intake_region=None)
        # Note: we deliberately do NOT set AWS_REGION/AWS_DEFAULT_REGION.
        result = _run_script(ws, ["--slug=test-svc"], {})
        region, source = _extract_region(result.stdout)
        assert region == "us-east-1"
        assert "default" in source.lower()

    def test_aws_default_region_used_if_aws_region_unset(self, tmp_path: Path):
        """AWS_DEFAULT_REGION is also consulted (slot 3b) when AWS_REGION
        is empty — boto3 honours both, and the script must too."""
        ws = _make_workspace(tmp_path, "test-svc", intake_region=None)
        result = _run_script(
            ws,
            ["--slug=test-svc"],
            {"AWS_DEFAULT_REGION": "sa-east-1"},
        )
        region, source = _extract_region(result.stdout)
        assert region == "sa-east-1"
        assert "AWS_DEFAULT_REGION" in source
