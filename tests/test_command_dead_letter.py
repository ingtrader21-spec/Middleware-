from pathlib import Path
from app.core.command_reliability import redrive_eligible

def test_command_dlq_module_has_tenant_scoped_readback_and_atomic_guard():
 source=(Path(__file__).resolve().parents[1]/"app/workers/command_dead_letter.py").read_text()
 assert "WHERE d.tenant_id=:tenant_id" in source
 assert "state='dead_lettered'" in source and "redrive_blocked=false" in source
 assert "await session.rollback()" in source and "await session.commit()" in source

def test_redrive_policy_rejects_blocked_or_resolved_entries():
 assert redrive_eligible({"state":"dead_lettered","resolved_at":None,"redrive_blocked":False})
 assert not redrive_eligible({"state":"dead_lettered","resolved_at":None,"redrive_blocked":True})
 assert not redrive_eligible({"state":"dead_lettered","resolved_at":"done","redrive_blocked":False})
