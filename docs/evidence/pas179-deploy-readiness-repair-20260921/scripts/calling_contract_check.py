import json
import os
from pathlib import Path

# Verbatim body of calling-contract-pin.yml verify-head + verify-merge-result python steps.
expected = {
    "version": "1.0.0",
    "sha256": os.environ["CONTRACT_DIGEST"],
    "authority": os.environ["CONTRACT_AUTHORITY"],
    "role": os.environ["CONTRACT_ROLE"],
    "external_effects_enabled": False,
}


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


raw = Path(".codestra/calling-contract.lock.json").read_text(encoding="utf-8")
document = json.loads(raw, object_pairs_hook=reject_duplicates)
if type(document) is not dict or set(document) != set(expected):
    raise SystemExit("calling contract lock schema mismatch")
for field in ("version", "sha256", "authority", "role"):
    if type(document[field]) is not str or document[field] != expected[field]:
        raise SystemExit(f"calling contract {field} mismatch")
if type(document["external_effects_enabled"]) is not bool or document["external_effects_enabled"] is not False:
    raise SystemExit("external_effects_enabled must be JSON boolean false")

for sample in (
    '{"external_effects_enabled":true,"external_effects_enabled":false}',
    '{"external_effects_enabled":false,"external_effects_enabled":true}',
    '{"authority":"wrong","authority":"appolon1908-hue/codestra-production-platform#257"}',
):
    try:
        json.loads(sample, object_pairs_hook=reject_duplicates)
    except ValueError:
        continue
    raise SystemExit("duplicate-key negative fixture was accepted")
print("CALLING_CONTRACT_PIN=PASS")
if document != expected or type(document["external_effects_enabled"]) is not bool:
    raise SystemExit("calling contract merge-result mismatch")
print("CALLING_CONTRACT_MERGE_RESULT=PASS")
