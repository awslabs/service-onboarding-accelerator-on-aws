"""The canonical and generated public license must agree with LICENSE."""
import json
import importlib.util
from pathlib import Path

import yaml


def test_shipped_license_metadata_matches_approved_license():
    root = Path(__file__).parents[2]
    license_name = (root / "LICENSE").read_text().splitlines()[0].strip()
    manifest = yaml.safe_load((root / "manifest.yaml").read_text())
    assert manifest["license"] == license_name
    for relative in (
        ".claude-plugin/plugin.json",
        ".github/plugins/service-approval/.github/plugin/plugin.json",
    ):
        assert json.loads((root / relative).read_text())["license"] == license_name
    assert f"licensed under the {license_name}" in (root / "README.md").read_text()
    for relative in (
        "powers/service-approval/README.md",
        ".github/plugins/service-approval/README.md",
    ):
        assert f"## License\n\n{license_name}" in (root / relative).read_text()
    assert f"**License:** {license_name}" in (root / "powers/service-approval/POWER.md").read_text()


def test_sync_detects_and_repairs_stale_client_license_notice(tmp_path):
    root = Path(__file__).parents[2]
    spec = importlib.util.spec_from_file_location("license_sync", root / "tools/sync-ide-configs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REPO = tmp_path
    path = tmp_path / "README.md"
    path.write_text("# Client\n\n## License\n\nApache-2.0\n")
    assert module._sync_license_notice(path, "Amazon Software License 1.0", check=True)
    assert "Apache-2.0" in path.read_text()
    assert module._sync_license_notice(path, "Amazon Software License 1.0", check=False)
    assert not module._sync_license_notice(path, "Amazon Software License 1.0", check=True)
