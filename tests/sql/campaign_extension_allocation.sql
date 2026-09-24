\set ON_ERROR_STOP on
TRUNCATE campaign_extension_allocation;

INSERT INTO campaign_extension_allocation
(id,campaign_id,campaign_number,allocation_public_id,extension_start,
 extension_end,created_by,policy_hash,source_change_id)
VALUES
(gen_random_uuid(),'B6999',100,'ALLOC-6999',6999,6999,'test',repeat('a',64),'test'),
(gen_random_uuid(),'B7000',200,'ALLOC-7000',7000,7000,'test',repeat('a',64),'test'),
(gen_random_uuid(),'B7899',300,'ALLOC-7899',7899,7899,'test',repeat('a',64),'test'),
(gen_random_uuid(),'B9999',400,'ALLOC-9999',9999,9999,'test',repeat('a',64),'test');

DO $$
BEGIN
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'BAD10000',500,'BAD-10000',10000,10000,
           'test',repeat('a',64),'test');
    RAISE EXCEPTION '10000 accepted';
  EXCEPTION WHEN check_violation OR data_exception THEN NULL; END;
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'BADORDER',500,'BAD-ORDER',7200,7199,
           'test',repeat('a',64),'test');
    RAISE EXCEPTION 'invalid order accepted';
  EXCEPTION WHEN check_violation OR data_exception THEN NULL; END;
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'BADNULL',500,'BAD-NULL',NULL,7199,
           'test',repeat('a',64),'test');
    RAISE EXCEPTION 'null accepted';
  EXCEPTION WHEN not_null_violation THEN NULL; END;
END $$;

TRUNCATE campaign_extension_allocation;
INSERT INTO campaign_extension_allocation
(id,campaign_id,campaign_number,allocation_public_id,extension_start,
 extension_end,allocation_status,created_by,policy_hash,source_change_id)
VALUES(gen_random_uuid(),'RLP100',100,'ALLOC-RLP',7100,7199,'RETIRED',
       'test',repeat('b',64),'test');

DO $$
BEGIN
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'EXACT',200,'ALLOC-EXACT',7100,7199,
           'test',repeat('b',64),'test');
    RAISE EXCEPTION 'exact overlap accepted';
  EXCEPTION WHEN exclusion_violation THEN NULL; END;
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'PART',200,'ALLOC-PART',7199,7298,
           'test',repeat('b',64),'test');
    RAISE EXCEPTION 'boundary overlap accepted';
  EXCEPTION WHEN exclusion_violation THEN NULL; END;
  BEGIN
    INSERT INTO campaign_extension_allocation
    (id,campaign_id,campaign_number,allocation_public_id,extension_start,
     extension_end,created_by,policy_hash,source_change_id)
    VALUES(gen_random_uuid(),'INSIDE',200,'ALLOC-INSIDE',7120,7130,
           'test',repeat('b',64),'test');
    RAISE EXCEPTION 'contained overlap accepted';
  EXCEPTION WHEN exclusion_violation THEN NULL; END;
END $$;

INSERT INTO campaign_extension_allocation
(id,campaign_id,campaign_number,allocation_public_id,extension_start,
 extension_end,created_by,policy_hash,source_change_id)
VALUES(gen_random_uuid(),'ADJACENT',200,'ALLOC-ADJACENT',7200,7299,
       'test',repeat('b',64),'test');

DO $$
DECLARE disabled_count integer;
BEGIN
  SELECT count(*) INTO disabled_count
  FROM campaign_extension_allocation
  WHERE allocation_status IN ('PROPOSED','RESERVED_DISABLED');
  IF disabled_count <> 1 THEN
    RAISE EXCEPTION 'disabled default mismatch';
  END IF;
  BEGIN
    DELETE FROM campaign_extension_allocation WHERE campaign_id='RLP100';
    RAISE EXCEPTION 'historical allocation deleted';
  EXCEPTION WHEN integrity_constraint_violation THEN NULL; END;
  BEGIN
    UPDATE campaign_extension_allocation SET extension_end=7198
    WHERE campaign_id='RLP100';
    RAISE EXCEPTION 'historical range changed';
  EXCEPTION WHEN integrity_constraint_violation THEN NULL; END;
END $$;
