"""Offline regressions for the candidate publisher and reviewer workflow.

Use only the standard library: these tests also run before dependencies are
installed on the GitHub-hosted policy runner. The gh command is a local shell
function in rendering tests; no network, credentials, or repository writes occur.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CANDIDATE = WORKFLOWS / "source-lock-candidate-build.yml"
REVIEWER = WORKFLOWS / "production-reviewer-access.yml"


def bash_executable() -> str:
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"), "Programs", "Git", "bin", "bash.exe"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return "bash"


def run_block(text: str, step_name: str) -> str:
    """Extract one fixed-indentation run block, rejecting escaped YAML content."""
    step = text.split(f"      - name: {step_name}\n", 1)[1]
    body = step.split("        run: |\n", 1)[1]
    lines: list[str] = []
    for line in body.splitlines():
        if line.startswith("      - "):
            break
        if line and not line.startswith("          "):
            raise ValueError("run content escaped the YAML block indentation")
        lines.append(line[10:] if line else "")
    return "\n".join(lines) + "\n"


class ReleaseWorkflowRegressions(unittest.TestCase):
    def test_candidate_publish_scan_and_evidence_share_canonical_owner(self) -> None:
        text = CANDIDATE.read_text(encoding="utf-8")
        prefix = "ghcr.io/appolon1908-hue/${{ matrix.component }}"
        self.assertEqual(text.count(prefix), 3)
        self.assertNotIn("ghcr.io/codestra-srl/", text)
        self.assertIn(f"tags: {prefix}:${{{{ github.sha }}}}", text)
        self.assertIn(f"image-ref: {prefix}:${{{{ github.sha }}}}", text)
        self.assertIn(f"IMAGE: {prefix}@${{{{ steps.build.outputs.digest }}}}", text)

    def test_candidate_publish_is_disabled_on_the_canonical_main_trigger(self) -> None:
        text = CANDIDATE.read_text(encoding="utf-8")
        condition = text.split("  build:\n", 1)[1].split("    runs-on:", 1)[0]
        self.assertIn("RUNTIME_MUTATION_DISABLED=true", condition)
        self.assertIn("if: ${{ false }}", condition)
        self.assertIn("push:\n    branches: [main]", text)
        self.assertIn("push: ${{ github.event_name == 'push' }}", text)
        self.assertIn("load: ${{ github.event_name == 'pull_request' }}", text)

    def test_security_and_immutable_evidence_gates_remain_blocking(self) -> None:
        text = CANDIDATE.read_text(encoding="utf-8")
        self.assertIn("severity: CRITICAL,HIGH", text)
        self.assertIn("exit-code: '1'", text)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("'mode=max'", text)
        self.assertIn("sbom: ${{ github.event_name == 'push' }}", text)
        self.assertIn('imagetools inspect "$IMAGE"', text)
        self.assertIn("jq -e", text)

    def test_both_workflows_execute_these_offline_regressions(self) -> None:
        for path in (CANDIDATE, REVIEWER):
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("python3 -m unittest -v tests.test_release_workflow_regressions", text)
                self.assertIn("tests/test_release_workflow_regressions.py", text)

    def test_reviewer_publish_shell_is_syntactically_valid(self) -> None:
        script = run_block(REVIEWER.read_text(encoding="utf-8"), "Publish issue result")
        result = subprocess.run([bash_executable(), "-n"], input=script, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_historical_unindented_comment_is_rejected(self) -> None:
        text = REVIEWER.read_text(encoding="utf-8")
        broken = text.replace("          \\`SOURCE_SHA=", "\\`SOURCE_SHA=", 1)
        self.assertNotEqual(text, broken)
        with self.assertRaisesRegex(ValueError, "escaped the YAML block"):
            run_block(broken, "Publish issue result")

    def test_reviewer_publish_renders_pass_and_blocked_without_network(self) -> None:
        script = run_block(REVIEWER.read_text(encoding="utf-8"), "Publish issue result")
        mock = 'gh() { printf \'%s\\0\' "$@" > "$CAPTURE_PATH"; }\n'
        for outcome, expected in (("success", "PASS"), ("failure", "BLOCKED"), ("skipped", "BLOCKED")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                capture = Path(directory) / "arguments"
                environment = {
                    "PATH": os.defpath,
                    "GITHUB_REPOSITORY": "ingtrader21-spec/Middleware-",
                    "GITHUB_SHA": "a" * 40,
                    "ROLLOUT_OUTCOME": outcome,
                    "CAPTURE_PATH": str(capture),
                }
                result = subprocess.run([bash_executable()], input=mock + script, text=True, capture_output=True, env=environment, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = capture.read_bytes().decode().split("\0")[:-1]
                self.assertEqual(arguments[:6], ["issue", "comment", "130", "--repo", environment["GITHUB_REPOSITORY"], "--body"])
                self.assertEqual(len(arguments), 7)
                body = arguments[6]
                self.assertTrue(body.startswith(f"## Production reviewer access — {expected}\n\n"))
                self.assertIn(f"`SOURCE_SHA={environment['GITHUB_SHA']}`", body)
                self.assertNotIn("\n          ", body)
                self.assertIn("No runtime, deployment, credential value", body)

    def test_reviewer_mutation_stays_owner_command_and_environment_gated(self) -> None:
        text = REVIEWER.read_text(encoding="utf-8")
        apply = text.split("\n  apply:\n", 1)[1]
        condition = apply.split("\n    permissions:\n", 1)[0]
        for expected in (
            "CONTROL_PLANE_MUTATION=repository-administration",
            "github.event_name == 'issue_comment'",
            "github.event.issue.number == 130",
            "github.event.repository.id == 1347559071",
            "github.event.sender.id == 275410064",
            "github.event.comment.user.id == 275410064",
            "'/apply-production-reviewer-access v1'",
        ):
            self.assertIn(expected, condition)
        self.assertNotIn("github.event_name == 'push'", condition)
        self.assertNotIn("if: ${{ false }}", condition)
        self.assertIn("name: repository-administration", apply)
        self.assertIn('test "$current_main" = "$GITHUB_SHA"', apply)
        self.assertIn("if: steps.rollout.outcome != 'success'", apply)


if __name__ == "__main__":
    unittest.main()
