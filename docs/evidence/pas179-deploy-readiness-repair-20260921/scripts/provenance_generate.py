import os
import pathlib
import re
import runpy

# Verbatim body of test-provenance-integrity.yml "generate" step (minus GITHUB_ENV exports).
module = runpy.run_path("tests/test_reusable_provenance.py")
root = pathlib.Path(os.environ["RUNNER_TEMP"]) / "provenance-roundtrip"
root.mkdir()
module["generated"](root)
types = re.findall(r"--type (https://slsa.dev/provenance/v1)", module["RELEASE"])
assert len(types) == 2
with open(os.environ["GITHUB_ENV"], "a") as output:
    output.write(f"CODESTRA_PROVENANCE_TYPE={types[0]}\n")
    output.write(f"CODESTRA_COSIGN_PREDICATE={root}/evidence/provenance.json\n")
    output.write(f"CODESTRA_COSIGN_OUTPUT={root}/statement.json\n")
print("provenance predicate generated:", (root / "evidence/provenance.json").exists())
