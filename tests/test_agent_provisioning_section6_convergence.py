from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "app/api/v1/agent_provisioning.py").read_text()
LIFECYCLE = (ROOT / "app/api/v1/agent_provisioning_lifecycle.py").read_text()
MIGRATION = (ROOT / "migrations/versions/0070_agent_provisioning_lifecycle.py").read_text()


def test_section6_uses_governed_0070_successor() -> None:
    assert 'revision = "0070_agent_provisioning_lifecycle"' in MIGRATION
    assert 'down_revision = "0069_progressive_tenant_rls"' in MIGRATION
    assert "app.tenant_ids" not in MIGRATION
    assert "current_setting('app.tenant_id', true)" in MIGRATION


def test_readback_is_read_only() -> None:
    section = LIFECYCLE.split('@router.get("/{request_id}/readback")', 1)[1].split(
        '@router.post("/{request_id}/repair-intents"', 1
    )[0]
    assert "session.commit()" not in section
    assert "session.add(" not in section
    assert "AgentProvisioningRepairIntent(" not in section


def test_repair_intent_has_explicit_mutation_route() -> None:
    assert '@router.post("/{request_id}/repair-intents", status_code=201)' in LIFECYCLE
    assert "tenant_id=request.tenant_id" in LIFECYCLE


def test_extension_reservation_requires_authoritative_evidence() -> None:
    reserve = LIFECYCLE.split('@router.post("/reserve-extension")', 1)[1].split(
        "class WebRtcTicketRequest", 1
    )[0]
    assert "authoritative extension evidence is required" in reserve
    assert "evidence_by_extension=body.evidence_by_extension" in reserve


def test_adopt_and_webrtc_require_exact_reservation_binding() -> None:
    assert LIFECYCLE.count("EXTENSION_RESERVATION_MISMATCH") >= 2
    assert "TelephonyExtensionReservation.extension == int(body.extension)" in LIFECYCLE
    assert "AgentProvisioningRequest.id == body.provisioning_request_id" in LIFECYCLE
    assert 'reservation.state = "DISABLED_READY"' in LIFECYCLE


def test_single_tenant_tokens_remain_backward_compatible() -> None:
    assert "len(principal.tenant_ids) != 1" in API
    assert "tenant_id is required for multi-tenant authority" in API
