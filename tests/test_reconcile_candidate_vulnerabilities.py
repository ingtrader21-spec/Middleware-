import csv
import json
import subprocess
import sys


def test_reconciles_without_suppressing(tmp_path):
    trivy = tmp_path / "trivy.json"
    grype = tmp_path / "grype.json"
    output = tmp_path / "matrix.csv"
    summary = tmp_path / "summary.json"
    trivy.write_text(json.dumps({"Results": [{"Target": "/x", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}]}]}))
    grype.write_text(json.dumps({"matches": [{"vulnerability": {"id": "CVE-2", "severity": "Critical", "fix": {"versions": []}}, "artifact": {"name": "q", "version": "3", "locations": [{"path": "/q"}]}}]}))
    subprocess.run([sys.executable, "scripts/reconcile_candidate_vulnerabilities.py", "--trivy", str(trivy), "--grype", str(grype), "--output", str(output), "--summary", str(summary)], check=True)
    assert len(list(csv.DictReader(output.open()))) == 2
    assert json.loads(summary.read_text()) == {"critical_count": 1, "deduplicated_finding_count": 2, "finding_suppression_count": 0, "high_count": 1}
