"""Private, inactive-by-default Server A restricted agent."""

from functools import lru_cache
from pathlib import Path
from typing import Any, Annotated

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.agent.executor import ALLOWED_SERVICES, AgentExecutor
from app.agent.security import authorize_agent_request, certificate_identity
from app.core.config import settings


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolRequest(StrictModel):
    task_id: str
    workspace: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_token: str


class CancelRequest(StrictModel):
    execution_id: str


@lru_cache
def executor() -> AgentExecutor:
    roots = tuple(
        Path(item.strip()) for item in settings.controller_workspace_allowlist.split(",")
        if item.strip()
    )
    return AgentExecutor(roots)


app = FastAPI(title="Codestra Server A Restricted Agent", version="1.0.0")


@app.post("/api/v1/tools/execute", status_code=202)
async def execute_tool(
    request: Request,
    body: ToolRequest,
    tenant_id: Annotated[str, Header(alias="X-Tenant-ID")],
    request_id: Annotated[str, Header(alias="X-Request-ID")],
    correlation_id: Annotated[str, Header(alias="X-Correlation-ID")],
):
    if not all((tenant_id, request_id, correlation_id)):
        raise HTTPException(422, "tenant_id, request_id and correlation_id required")
    authorize_agent_request(
        request, token=body.approval_token, task_id=body.task_id,
        tenant_id=tenant_id, workspace=body.workspace, tool=body.tool,
    )
    return await executor().execute(
        body.tool, body.workspace, body.arguments,
        {"tenant_id": tenant_id, "request_id": request_id,
         "correlation_id": correlation_id},
    )


@app.post("/api/v1/tools/cancel", status_code=202)
async def cancel_tool(request: Request, body: CancelRequest):
    certificate_identity(request.scope)
    record = executor().executions.get(body.execution_id)
    if record is None:
        raise HTTPException(404, "execution not found")
    executor().cancelled.add(body.execution_id)
    return {"execution_id": body.execution_id, "cancellation_requested": True}


@app.get("/api/v1/executions/{execution_id}")
async def execution_status(request: Request, execution_id: str,
                           tenant_id: Annotated[str, Header(alias="X-Tenant-ID")]):
    certificate_identity(request.scope)
    record = executor().executions.get(execution_id)
    if record is None or record["tenant_id"] != tenant_id:
        raise HTTPException(404, "execution not found")
    return record


@app.get("/api/v1/services/{service}/status")
async def service_status(request: Request, service: str):
    certificate_identity(request.scope)
    if service not in ALLOWED_SERVICES:
        raise HTTPException(404, "service not found")
    return {"service": service, "status": "query-via-authorized-tool"}


@app.get("/api/v1/workspaces")
async def workspaces(request: Request):
    certificate_identity(request.scope)
    return {"workspaces": [str(path) for path in executor().workspaces]}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "server_id": "middleware", "profile": "development"}


@app.get("/readyz", response_model=None)
async def readyz() -> dict[str, str] | JSONResponse:
    if not settings.server_a_agent_enabled:
        return JSONResponse({"status": "not-ready", "reason": "disabled"}, status_code=503)
    if settings.server_a_agent_bind != "10.40.0.1:9443":
        return JSONResponse({"status": "not-ready", "reason": "private-bind-required"}, status_code=503)
    return {"status": "ready", "exposure": "private-vlan-only"}
