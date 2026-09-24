import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.schemas.registry import REGISTRY

root = Path(__file__).resolve().parents[1] / "schemas"
root.mkdir(exist_ok=True)
for event_type, definition in sorted(REGISTRY.items()):
    target = root / f"{event_type}.v{definition['version']}.schema.json"
    target.write_text(
        json.dumps(definition["model"].model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
