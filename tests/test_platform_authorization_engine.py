from app.platform.principal import PrincipalType, authorize, principal_from_claims
from app.control_plane_auth import ControlPlaneCaller

def caller():
    return ControlPlaneCaller(client_id='middleware-api', command_scope='platform.command', status_scope='platform.command.read', allowed_command_prefixes=(), allowed_targets=frozenset(), connector_commands_allowed=False, compatibility_only=False)

def principal(**extra):
    claims={'sub':'u1','azp':'middleware-api','tenant_id':'t1','scope':'platform.command platform.command.read','roles':['agent'],**extra}
    return principal_from_claims(claims,caller(),environment='test')

def test_human_principal_and_default_deny():
    p=principal(); assert p.principal_type is PrincipalType.HUMAN and p.actor_id=='u1'
    assert authorize(p,action='command.read',resource='command:1',tenant_id='t1').allowed
    assert not authorize(p,action='provisioning.disable',resource='agent:1',tenant_id='t1').allowed

def test_tenant_campaign_and_production_effect_fail_closed():
    p=principal(campaigns=['c1'])
    assert authorize(p,action='command.read',resource='command:1',tenant_id='t2').decision_code=='TENANT_MISMATCH'
    assert authorize(p,action='command.read',resource='command:1',tenant_id='t1',campaign_id='c2').decision_code=='CAMPAIGN_FORBIDDEN'
    assert authorize(p,action='command.create',resource='connector:x',tenant_id='t1',effect_class='EXTERNAL_MUTATION',environment='production').decision_code=='ENVIRONMENT_NOT_AUTHORIZED'
