"""Offline syntax/selection checks only; never imports or executes the harness."""
import ast
from pathlib import Path
import sys

root = Path(sys.argv[1])
path = root / "scripts/test-context-storage.py"
source = path.read_text()
tree = ast.parse(source, filename=str(path))
compile(tree, str(path), "exec")
names = {"qualification_selection", "qualification_environment"}
definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
assert len(definitions) == 2
space = {}
exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), space)
select = space["qualification_selection"]
exact = "^TestDirectHolderObservationWithRealKubernetes$"
assert select(exact, False, False) == (exact, 2)
assert select(None, False, False) == (None, 2)
assert select(None, False, False, initial_bootstrap_chain=True)[1] == 1
assert select(None, False, False, initial_bootstrap_chain=True, runtime_provider_pair=True)[1] == 1
for kwargs in ({"initial_bootstrap_chain": True}, {"runtime_object_roundtrip": True}, {"owner_provider_auth": True}):
    try:
        select(exact, False, False, **kwargs)
    except ValueError:
        pass
    else:
        raise AssertionError("direct selector mixed with another qualification")
env = space["qualification_environment"]({"ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR": "1", "ASSERVAT_INITIAL_RUNTIME_BRIDGE": "1"}, "fixture", "work", False, False)
assert env["ASSERVAT_CONTEXT_FIXTURES"] == "fixture"
assert "ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR" not in env and "ASSERVAT_INITIAL_RUNTIME_BRIDGE" not in env
main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
choice = next(n for n in main.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "direct_observation" for t in n.targets))
assert isinstance(choice.value, ast.Compare) and len(choice.value.comparators) == 1 and choice.value.comparators[0].value == exact
helper = root / "test/fixtures/observation-native"
expected = {"data.go", "enrollment.go", "inputs.go", "main.go", "metrics.go", "runtime.go"}
assert {p.name for p in helper.glob("*.go")} == expected
for name in expected:
    assert (helper / name).read_text().startswith("//go:build ignore\n")
print("Offline harness syntax, exact selection, legacy selection and closed helper source set passed; no services invoked")
