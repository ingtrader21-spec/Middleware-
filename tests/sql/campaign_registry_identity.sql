\set ON_ERROR_STOP on

INSERT INTO campaign_extension_allocation
  (id,campaign_id,campaign_number,allocation_public_id,extension_start,
   extension_end,allocation_status,created_by,policy_hash,source_change_id)
VALUES
  ('00000000-0000-0900-0000-000000000001','CMP-900-TST',900,
   'CMP-900-TST-RANGE',7900,7999,'PROPOSED','sql-test',repeat('0',64),
   'sql-test');

INSERT INTO campaign_registry
  (id,campaign_number,campaign_code,campaign_public_id,name,
   vicidial_campaign_id,agent_group,dialplan_context,extension_allocation_id,
   policy_hash,source_change_id)
VALUES
  ('00000000-0000-0000-0000-000000000900',900,'TST','CMP-900-TST',
   'Disposable Test Campaign','TST900','TST900_AGENTS',
   'cs-test-tst900',
   '00000000-0000-0900-0000-000000000001',
   repeat('0',64),'sql-test');

DO $$
BEGIN
  IF (SELECT registry_status FROM campaign_registry WHERE campaign_number=900)
     <> 'PROPOSED_DISABLED' THEN
    RAISE EXCEPTION 'campaign default is not disabled';
  END IF;
END $$;

INSERT INTO campaign_object_identity
  (id,campaign_number,identity_type,sequence_value,public_id,full_alias,
   source_system,source_object_id)
VALUES
  ('90000000-0000-0000-0000-000000000001',900,'LEAD',1,
   '900-L-00000001','TST-900-L-00000001','test','lead-1');

DO $$
BEGIN
  IF (SELECT dialing_state FROM campaign_object_identity
      WHERE public_id='900-L-00000001') <> 'NOT_ELIGIBLE' THEN
    RAISE EXCEPTION 'lead identity activated dialing';
  END IF;
END $$;

DO $$
BEGIN
  BEGIN
    DELETE FROM campaign_object_identity WHERE public_id='900-L-00000001';
    RAISE EXCEPTION 'identity delete unexpectedly succeeded';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END $$;

SELECT 'CAMPAIGN_REGISTRY_SQL_GATE=PASS';
