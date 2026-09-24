import json
from pathlib import Path
import subprocess
import sys


def test_manifest_fails_closed_for_unknown_active(tmp_path: Path):
    export = tmp_path / "export.json"
    output = tmp_path / "manifest.json"
    export.write_text(json.dumps([{"id": "1", "name": "Unknown", "active": True, "versionId": "v1"}]))
    result = subprocess.run([sys.executable, "scripts/reconcile_n8n_staging.py", str(export), str(output)], capture_output=True)
    assert result.returncode != 0
    assert json.loads(output.read_text())["unclassified_active_ids"] == ["1"]
