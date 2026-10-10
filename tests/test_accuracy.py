"""pytest: QuantumTrace must classify the official samples exactly as in ground_truth.json."""
from quantumtrace.evaluate import run


def test_ground_truth():
    r = run()
    assert r["passed"], "\n".join(r["failures"])
    assert r["code"]["recall"] == 1.0 and r["code"]["precision"] == 1.0
    assert r["network"]["accuracy"] == 1.0
    assert r["cloud"]["accuracy"] == 1.0
