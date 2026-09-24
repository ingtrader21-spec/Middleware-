import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MERGE = ROOT / "migrations/versions/0023_merge_control_heads.py"


def assignments(path: Path) -> dict[str, object]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"revision", "down_revision"}
    }


def test_merge_revision_joins_both_0022_heads_with_valid_width():
    values = assignments(MERGE)
    assert values == {
        "revision": "0023_merge_control_heads",
        "down_revision": (
            "0022_n8n_transport_ack",
            "0022_test_trace_binding",
        ),
    }
    assert len(values["revision"]) <= 32


def test_merge_revision_has_no_schema_or_data_operations():
    tree = ast.parse(MERGE.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert set(functions) == {"upgrade", "downgrade"}
    for function in functions.values():
        assert all(
            isinstance(statement, (ast.Expr, ast.Pass)) for statement in function.body
        )
