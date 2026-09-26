"""Command-kernel DLQ persistence/readback and guarded redrive."""
from __future__ import annotations
from typing import Any
from uuid import UUID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.command_reliability import redrive_eligible

LIST_COMMAND_DLQ_SQL=text("""
SELECT d.id,d.tenant_id,d.command_id,d.attempt_number,d.error_code,d.reason,
 d.safe_error_detail,d.request_sha256,d.dead_lettered_at,d.resolved_at,d.redriven_command_id,
 c.redrive_count,c.redrive_blocked,c.state
FROM middleware_command_dead_letters d
JOIN middleware_commands c ON c.tenant_id=d.tenant_id AND c.command_id=d.command_id
WHERE d.tenant_id=:tenant_id
ORDER BY d.dead_lettered_at DESC,d.id DESC LIMIT :limit
""")
GET_COMMAND_DLQ_SQL=text("""
SELECT d.id,d.tenant_id,d.command_id,d.attempt_number,d.error_code,d.reason,
 d.safe_error_detail,d.request_sha256,d.dead_lettered_at,d.resolved_at,d.redriven_command_id,
 c.redrive_count,c.redrive_blocked,c.state
FROM middleware_command_dead_letters d
JOIN middleware_commands c ON c.tenant_id=d.tenant_id AND c.command_id=d.command_id
WHERE d.tenant_id=:tenant_id AND d.command_id=:command_id
""")
REDRIVE_SQL=text("""
UPDATE middleware_commands SET state='queued',next_attempt_at=now(),last_error=NULL,
 dead_lettered_at=NULL,dead_letter_reason=NULL,redrive_count=redrive_count+1,updated_at=now()
WHERE tenant_id=:tenant_id AND command_id=:command_id AND state='dead_lettered'
 AND redrive_blocked=false
""")
RESOLVE_SQL=text("""
UPDATE middleware_command_dead_letters SET resolved_at=now(),redriven_command_id=:command_id
WHERE tenant_id=:tenant_id AND command_id=:command_id AND resolved_at IS NULL
""")

async def list_command_dead_letters(session:AsyncSession,tenant_id:str,limit:int=100)->list[dict[str,Any]]:
    if not 1<=limit<=100: raise ValueError("dead-letter limit must be between 1 and 100")
    rows=await session.execute(LIST_COMMAND_DLQ_SQL,{"tenant_id":tenant_id,"limit":limit})
    return [dict(x) for x in rows.mappings()]

async def get_command_dead_letter(session:AsyncSession,tenant_id:str,command_id:UUID)->dict[str,Any]|None:
    row=(await session.execute(GET_COMMAND_DLQ_SQL,{"tenant_id":tenant_id,"command_id":str(command_id)})).mappings().first()
    return dict(row) if row else None

async def redrive_command(session:AsyncSession,tenant_id:str,command_id:UUID)->bool:
    row=await get_command_dead_letter(session,tenant_id,command_id)
    if row is None or not redrive_eligible(row): return False
    result=await session.execute(REDRIVE_SQL,{"tenant_id":tenant_id,"command_id":str(command_id)})
    if getattr(result,"rowcount",0)!=1:
        await session.rollback(); return False
    await session.execute(RESOLVE_SQL,{"tenant_id":tenant_id,"command_id":str(command_id)})
    await session.commit(); return True
