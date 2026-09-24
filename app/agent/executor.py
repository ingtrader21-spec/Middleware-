"""Fixed-operation executor for the development-only Server A agent."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.automation import redact
from app.core.controller import (
    ALLOWED_TOOLS,
    ControllerError,
    _reject_forbidden,
    validate_workspace,
)


MAX_OUTPUT = 256 * 1024
MAX_FILES = 2000
ALLOWED_SERVICES = frozenset({"codestra-middleware-development"})


class AgentExecutor:
    def __init__(self, workspaces: tuple[Path, ...]):
        self.workspaces = tuple(path.resolve() for path in workspaces)
        self.executions: dict[str, dict[str, Any]] = {}
        self.cancelled: set[str] = set()
        self._lock = asyncio.Lock()

    def _workspace(self, value: str) -> Path:
        validated = validate_workspace(value, self.workspaces)
        # Return an existing trusted Path object so request text never becomes
        # the filesystem root used by the dispatcher.
        for root in self.workspaces:
            if validated == str(root):
                return root
        raise ControllerError("workspace must name an allowed root")

    @staticmethod
    def _path(root: Path, value: str) -> Path:
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ControllerError("path traversal denied")
        requested = relative.as_posix()
        for current, directories, names in os.walk(root):
            directories[:] = [item for item in directories if item not in {".git", ".venv", "node_modules"}]
            for name in names:
                candidate = Path(current) / name
                if candidate.relative_to(root).as_posix() == requested:
                    return candidate
        raise ControllerError("file not found")

    async def _fixed_process(self, argv: tuple[str, ...], cwd: Path) -> dict[str, Any]:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent"},
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=600)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise ControllerError("bounded tool timeout") from None
        text = output[:MAX_OUTPUT].decode("utf-8", "replace")
        return {"exit_code": process.returncode, "output": redact(text),
                "truncated": len(output) > MAX_OUTPUT}

    async def _dispatch(self, tool: str, root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "inspect_workspace":
            # root is rebound to an object from self.workspaces in _workspace.
            return {"workspace": str(root), "exists": root.is_dir(),
                    "git": (root / ".git").exists() or (root / ".git").is_file()}  # lgtm[py/path-injection]
        if tool == "list_files":
            files: list[str] = []
            for current, directories, names in os.walk(root):  # lgtm[py/path-injection]
                directories[:] = sorted(item for item in directories if item not in {".git", ".venv", "node_modules"})
                for name in sorted(names):
                    files.append(str((Path(current) / name).relative_to(root)))
                    if len(files) >= MAX_FILES:
                        return {"files": files, "truncated": True}
            return {"files": files, "truncated": False}
        if tool == "read_file":
            target = self._path(root, str(arguments.get("path", "")))
            data = target.read_bytes()
            if len(data) > MAX_OUTPUT:
                raise ControllerError("file exceeds read limit")
            return {"path": str(target.relative_to(root)), "content": redact(data.decode("utf-8", "replace"))}
        if tool == "search_code":
            needle = str(arguments.get("query", ""))
            if not needle or len(needle) > 256:
                raise ControllerError("search query denied")
            matches: list[dict[str, Any]] = []
            for current, directories, names in os.walk(root):  # lgtm[py/path-injection]
                directories[:] = [item for item in directories if item not in {".git", ".venv", "node_modules"}]
                for name in names:
                    path = Path(current) / name
                    try:
                        for line_number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):  # lgtm[py/path-injection]
                            if needle in line:
                                matches.append({"path": str(path.relative_to(root)), "line": line_number})
                                if len(matches) >= 500:
                                    return {"matches": matches, "truncated": True}
                    except OSError:
                        continue
            return {"matches": matches, "truncated": False}
        fixed: dict[str, tuple[str, ...]] = {
            "git_status": ("git", "status", "--short", "--branch"),
            "git_diff": ("git", "diff", "--check"),
            "run_formatter": ("ruff", "format", "--check", "."),
            "run_linter": ("ruff", "check", "."),
            "run_typecheck": ("mypy", "--ignore-missing-imports", "app", "tests"),
            "run_unit_tests": ("pytest", "-q", "tests", "--ignore=tests/integration"),
            "run_integration_tests": ("pytest", "-q", "tests/integration"),
            "run_security_scan": ("semgrep", "scan", "--config", "auto", "--error", "."),
            "run_secret_scan": ("gitleaks", "dir", "--no-banner", "--redact", "."),
            "build_project": ("python", "-m", "build"),
        }
        if tool in fixed:
            return await self._fixed_process(fixed[tool], root)
        if tool == "apply_patch":
            patch = str(arguments.get("patch", ""))
            if not patch or len(patch.encode()) > MAX_OUTPUT or "../" in patch:
                raise ControllerError("patch denied")
            process = await asyncio.create_subprocess_exec(
                "git", "apply", "--check", "--whitespace=error-all", "-",
                cwd=root, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            )
            checked, _ = await process.communicate(patch.encode())
            if process.returncode:
                return {"exit_code": process.returncode, "output": checked[:MAX_OUTPUT].decode(errors="replace")}
            apply_process = await asyncio.create_subprocess_exec(
                "git", "apply", "--whitespace=error-all", "-", cwd=root,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            )
            applied, _ = await apply_process.communicate(patch.encode())
            return {"exit_code": apply_process.returncode, "output": applied[:MAX_OUTPUT].decode(errors="replace")}
        if tool in {"check_service", "read_sanitized_logs", "restart_development_service"}:
            service = str(arguments.get("service", ""))
            if service not in ALLOWED_SERVICES:
                raise ControllerError("service denied")
            if tool == "check_service":
                command: tuple[str, ...] = ("systemctl", "is-active", service)
            elif tool == "read_sanitized_logs":
                command = ("journalctl", "-u", service, "-n", "200", "--no-pager", "--output=short-iso")
            else:
                command = ("systemctl", "restart", service)
            return await self._fixed_process(command, root)
        raise ControllerError("unknown tool")

    async def execute(self, tool: str, workspace: str, arguments: dict[str, Any],
                      context: dict[str, Any]) -> dict[str, Any]:
        if tool not in ALLOWED_TOOLS:
            raise ControllerError("unknown tool")
        _reject_forbidden(arguments)
        root = self._workspace(workspace)
        execution_id = str(uuid4())
        async with self._lock:
            self.executions[execution_id] = {
                "execution_id": execution_id, "state": "RUNNING", "tool": tool,
                "workspace": str(root), "tenant_id": context["tenant_id"],
                "request_id": context["request_id"],
                "correlation_id": context["correlation_id"],
            }
        try:
            result = await self._dispatch(tool, root, arguments)
            state = "CANCELLED" if execution_id in self.cancelled else "COMPLETED"
        except (OSError, ControllerError) as exc:
            result = {"error": str(exc)}
            state = "FAILED"
        self.executions[execution_id].update({"state": state, "result": redact(result)})
        return self.executions[execution_id]
