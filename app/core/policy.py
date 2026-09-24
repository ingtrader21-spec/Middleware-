class PolicyError(ValueError):
    pass


def enforce_test_campaign(payload: dict) -> None:
    if payload.get("campaign_id") != "TEST_SYN":
        raise PolicyError("only TEST_SYN is permitted")
