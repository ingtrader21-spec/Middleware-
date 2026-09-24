"""Pure contract regressions; fixtures are synthetic and never dialed."""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.calling_contract import (
    CallLifecycleEvidence, CallPrincipal, CallingContractError, CallingGrant, OriginateRequest,
    load_grant, operation_identity, validate_call_evidence,
)

SOURCE_SHA = "a" * 40
GETUID = getattr(os, "getuid", None)


def principal(**changes):
    value = dict(tenant_id="TEST_TENANT", subject="test-user-subject", employee_id="TEST_AGENT",
                 campaign_id="TEST_UNIT", business_unit="TEST_BU", extension="6998")
    return CallPrincipal(**(value | changes))


def originate(**changes):
    value = dict(employee_id="TEST_AGENT", campaign="TEST_UNIT", business_unit="TEST_BU",
                 destination="internal:TEST_ECHO", destination_class="internal_test",
                 destination_country="ZZ", destination_timezone="UTC", caller_id="+12025550123",
                 lead_model="crm.lead", lead_id=17, recording_requested=False,
                 idempotency_key="test-originate-0001")
    return OriginateRequest(**(value | changes))


def grant(**changes):
    now = datetime.now(UTC)
    value = dict(authorization_reference="TEST-AUTH-0001", principal=principal(),
                 destination="internal:TEST_ECHO", caller_id="+12025550123", lead_id=17,
                 not_before=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10),
                 source_sha=SOURCE_SHA)
    return CallingGrant(**(value | changes))


class CallingContractTests(unittest.TestCase):
    def lifecycle(self, **changes):
        created = datetime(2026, 9, 5, 20, 0, tzinfo=UTC)
        value = dict(operation_id="op", correlation_id="corr", dispatch_state="accepted",
                     asterisk_uniqueid="unique", linkedid="linked", call_id="call",
                     call_state="completed", answered_at=created + timedelta(seconds=2),
                     ended_at=created + timedelta(seconds=7), terminal=True, evidence={"sequence": 3},
                     tenant_id="tenant", subject="subject", employee_id="employee",
                     username="appolon", extension="6901", campaign="TEST_SYN",
                     authorization_reference="auth", created_at=created,
                     duration_seconds=7, talk_duration_seconds=5, hangup_cause="normal",
                     hangup_cause_code=16, internal_only=True, external_dialing=False, recording=False)
        return value | changes

    def test_lifecycle_timestamps_and_strict_values(self):
        CallLifecycleEvidence.model_validate(self.lifecycle())
        invalid = [
            {"ended_at": "invalid"}, {"ended_at": datetime(2026,9,5,19,0,tzinfo=UTC)},
            {"duration_seconds": 6}, {"talk_duration_seconds": 4}, {"terminal": "true"},
            {"duration_seconds": True},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                CallLifecycleEvidence.model_validate(self.lifecycle(**changes))

    def test_nonterminal_lifecycle_rejects_terminal_unknown_and_end_time(self):
        bindings = dict(operation_id="op", correlation_id="corr", tenant_id="tenant",
                        actor={"subject":"subject","employee_id":"employee","extension":"6901","campaign_id":"TEST_SYN"},
                        authorization_reference="auth", require_terminal=False)
        created=datetime(2026,9,5,20,0,tzinfo=UTC)
        base=self.lifecycle(call_state="ringing", terminal=False, answered_at=None,
                            ended_at=None, duration_seconds=None, talk_duration_seconds=None,
                            linkedid=None, evidence=None, created_at=created)
        validate_call_evidence(base, **bindings)
        for changes in ({"call_state":"completed"},{"call_state":"mystery"},{"ended_at":created}):
            with self.subTest(changes=changes), self.assertRaises((CallingContractError,ValidationError)):
                validate_call_evidence(base|changes, **bindings)

    def test_lifecycle_evidence_must_match_accepted_provider_identity(self):
        bindings = dict(
            operation_id="op", correlation_id="corr", tenant_id="tenant",
            actor={"subject":"subject","employee_id":"employee",
                   "extension":"6901","campaign_id":"TEST_SYN"},
            authorization_reference="auth", require_terminal=True,
            provider_operation_id="unique",
        )
        validate_call_evidence(self.lifecycle(), **bindings)
        with self.assertRaises(CallingContractError):
            validate_call_evidence(
                self.lifecycle(asterisk_uniqueid="different"), **bindings,
            )
    def test_internal_shape_and_grant(self):
        grant().authorize(principal(), originate(), source_sha=SOURCE_SHA)

    def test_external_shape_remains_e164(self):
        self.assertEqual(originate(destination_class="mobile", destination="+12025550124").destination,
                         "+12025550124")
        with self.assertRaises(ValidationError):
            originate(destination_class="mobile", destination="6998")

    def test_internal_cannot_supply_sip_or_dialplan(self):
        for target in ["sip:6998@example.test", "SIP/trunk/123", "internal:../trunk", "internal:*"]:
            with self.subTest(target=target), self.assertRaises(ValidationError):
                originate(destination=target)

    def test_no_extra_fields_or_inline_credentials(self):
        for key in ["password", "token", "context", "trunk", "actor"]:
            with self.subTest(key=key), self.assertRaises(ValidationError):
                originate(**{key: "untrusted"})

    def test_strict_lead_and_recording_types(self):
        for value in [True, "17", 17.0, -1, 0]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                originate(lead_id=value)
        for value in [True, 1, "false"]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                originate(recording_requested=value)

    def test_timezone_is_validated(self):
        with self.assertRaises(ValidationError):
            originate(destination_timezone="not/a/timezone")

    def test_wildcard_identity_is_rejected(self):
        for field in ["tenant_id", "subject", "employee_id", "campaign_id", "business_unit"]:
            with self.subTest(field=field), self.assertRaises(ValidationError):
                principal(**{field: "*"})

    def test_body_identity_does_not_override_verified_principal(self):
        for changes in [dict(employee_id="OTHER"), dict(campaign="OTHER"), dict(business_unit="OTHER")]:
            with self.subTest(changes=changes), self.assertRaises(CallingContractError):
                originate(**changes).assert_principal(principal())

    def test_expired_and_future_policy(self):
        now = datetime.now(UTC)
        for before, after in [(now-timedelta(minutes=20), now-timedelta(minutes=1)),
                              (now+timedelta(minutes=1), now+timedelta(minutes=20))]:
            with self.subTest(before=before), self.assertRaises(CallingContractError):
                grant(not_before=before, expires_at=after).authorize(principal(), originate(), source_sha=SOURCE_SHA)

    def test_policy_maximum_duration(self):
        with self.assertRaises(ValidationError):
            grant(expires_at=datetime.now(UTC) + timedelta(hours=2))

    def test_policy_release_and_exact_bindings(self):
        with self.assertRaises(CallingContractError):
            grant().authorize(principal(), originate(), source_sha="b"*40)
        for changes in [dict(lead_id=18), dict(destination="internal:OTHER"),
                        dict(caller_id="+12025550124")]:
            with self.subTest(changes=changes), self.assertRaises(CallingContractError):
                grant().authorize(principal(), originate(**changes), source_sha=SOURCE_SHA)

    def test_policy_cannot_authorize_public_dial(self):
        with self.assertRaises(CallingContractError):
            grant().authorize(principal(), originate(destination_class="mobile", destination="+12025550124"), source_sha=SOURCE_SHA)

    def test_policy_never_enables_recording_or_public_delivery(self):
        for changes in [dict(external_dialing=True), dict(internal_only=False), dict(max_calls=2),
                        dict(external_dialing=0), dict(internal_only=1), dict(max_calls=True)]:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                grant(**changes)

    def test_stable_request_identity_and_distinct_subject(self):
        key = originate().idempotency_key
        self.assertEqual(operation_identity(principal(), key), operation_identity(principal(), key))
        self.assertNotEqual(operation_identity(principal(), key), operation_identity(principal(subject="other"), key))

    def test_absent_policy_is_disabled(self):
        self.assertIsNone(load_grant({}))

    def test_relative_policy_path_denied(self):
        with self.assertRaises(CallingContractError):
            load_grant({"CODESTRA_INTERNAL_CALL_POLICY_FILE": "relative.json"})

    def test_policy_symlink_denied(self):
        try:
            link = Path(tempfile.mkdtemp()) / "alias.json"
            link.parent.mkdir(exist_ok=True)
            source = link.parent / "policy.json"
            source.write_text(grant().model_dump_json())
            source.chmod(0o600)
            link.symlink_to(source)
        except (AttributeError, NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(CallingContractError):
            load_grant({"CODESTRA_INTERNAL_CALL_POLICY_FILE": str(link)})

    def test_world_readable_policy_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "policy.json"
            source.write_text(grant().model_dump_json())
            source.chmod(0o644)
            with self.assertRaises(CallingContractError):
                load_grant({"CODESTRA_INTERNAL_CALL_POLICY_FILE": str(source)})

    def test_unowned_policy_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "policy.json"
            source.write_text(grant().model_dump_json())
            source.chmod(0o600)
            actual = source.stat()
            unowned = type("Metadata", (), {"st_mode": actual.st_mode, "st_uid": 12345, "st_size": actual.st_size})()
            with patch("app.calling_contract.os.fstat", return_value=unowned), self.assertRaises(CallingContractError):
                load_grant({"CODESTRA_INTERNAL_CALL_POLICY_FILE": str(source)})

    @unittest.skipUnless(GETUID is not None and GETUID() == 0, "root-owned policy acceptance requires root test process")
    def test_private_root_owned_policy_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "policy.json"
            expected = grant()
            source.write_text(expected.model_dump_json())
            source.chmod(0o640)
            self.assertEqual(load_grant({"CODESTRA_INTERNAL_CALL_POLICY_FILE": str(source)}), expected)


if __name__ == "__main__":
    unittest.main()
