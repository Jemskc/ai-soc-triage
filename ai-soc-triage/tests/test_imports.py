"""Every module must import.

A syntax error in autopilot.py shipped past 130 passing tests, because no test
imported it — the agentic modules are exercised by the running server, not by
unit tests, so nothing checked they even parse. This is the cheapest possible
guard against that whole class of failure.
"""

import importlib
import pkgutil
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"

# Modules that pull in torch or reach for a model at import time are excluded:
# they are slow and their failure mode is environmental, not syntactic.
HEAVY = {"llm_backend", "ai_engine", "ai_triage", "api_server", "dashboard"}

MODULES = sorted(
    m.name for m in pkgutil.iter_modules([str(SRC)])
    if not m.ispkg and m.name not in HEAVY
)


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    importlib.import_module(name)


def test_agent_package_imports():
    for sub in ("base", "triage", "intel", "hunt", "response"):
        importlib.import_module(f"agents.{sub}")


def test_every_source_file_parses():
    """Catches a syntax error even in the heavy modules, without importing
    them — parsing is free and does not need a GPU."""
    import ast

    failures = []
    for path in sorted(SRC.rglob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            failures.append(f"{path.name}:{exc.lineno} {exc.msg}")
    assert not failures, "syntax errors: " + "; ".join(failures)


def test_scripts_parse():
    import ast

    scripts = Path(__file__).resolve().parent.parent / "scripts"
    for path in sorted(scripts.glob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"))


# --- wiring contracts -------------------------------------------------------
# A blind string replacement silently failed to patch Orchestrator.__init__,
# leaving the autopilot calling it with keywords it did not accept. The file
# still parsed and every test still passed; the failure only appeared at
# runtime as "agents.unavailable" fifteen times. These pin the call signatures
# that cross module boundaries.

def test_orchestrator_accepts_the_arguments_autopilot_passes():
    import inspect

    from orchestrator import Orchestrator

    params = set(inspect.signature(Orchestrator.__init__).parameters)
    for required in ("agentic", "inventory", "memory", "stream_stats", "on_step"):
        assert required in params, f"Orchestrator.__init__ is missing {required}"


def test_orchestrator_runs_the_agentic_path():
    import inspect

    from orchestrator import Orchestrator

    source = inspect.getsource(Orchestrator.run_case)
    assert "if self.agentic:" in source
    assert "Investigator" in source
    assert "autonomy.decide" in source


def test_investigator_accepts_what_the_orchestrator_passes():
    import inspect

    from investigator import Investigator

    params = set(inspect.signature(Investigator.__init__).parameters)
    for required in ("backend", "toolbox", "max_steps", "on_step"):
        assert required in params


def test_toolbox_accepts_what_the_orchestrator_passes():
    import inspect

    from agent_tools import ToolBox

    params = set(inspect.signature(ToolBox.__init__).parameters)
    for required in ("df", "assets", "case_memory"):
        assert required in params
