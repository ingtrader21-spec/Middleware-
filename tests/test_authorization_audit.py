import pytest
from app.platform.persistence import record_authorization_decision
class Conn:
    def __init__(self): self.args=None
    async def execute(self, sql,*args): self.args=(sql,args)
class Ctx:
    def __init__(self,c): self.c=c
    async def __aenter__(self): return self.c
    async def __aexit__(self,*a): pass
class Pool:
    def __init__(self): self.c=Conn()
    def acquire(self): return Ctx(self.c)
@pytest.mark.asyncio
async def test_authorization_audit_is_bounded_and_secret_free():
    p=Pool(); await record_authorization_decision(p,tenant_id='t1',resource='connector:test',action='connector.read',principal_id='svc',decision_code='ALLOW',allowed=True,correlation_id='corr',matched_policy='role_scope_policy')
    sql,args=p.c.args
    assert 'middleware_control_audit' in sql and 'authorization_decision' in sql
    assert args[0]=='t1' and args[4]=='ALLOW' and args[5]=='allowed'
    assert 'Authorization' not in args[6] and 'Bearer' not in args[6]
