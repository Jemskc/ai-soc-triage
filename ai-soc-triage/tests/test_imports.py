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


# ── access control ────────────────────────────────────────────────────────────
# The API approves containment actions and ingests telemetry. Unauthenticated on
# 0.0.0.0, anyone who can route to the port can approve a response action or
# read every case file in the estate.

def test_api_key_is_read_from_the_environment_not_generated():
    """A key that generates itself gets committed and never rotated."""
    src = (Path(__file__).resolve().parents[1] / "src" / "api_server.py").read_text()
    assert 'os.environ.get("SOC_API_KEY"' in src
    # No fallback that invents a key.
    assert "secrets.token" not in src
    assert "uuid4()" not in src.split("API_KEY =")[1][:200]


def test_health_stays_open_so_probes_work_without_a_key():
    src = (Path(__file__).resolve().parents[1] / "src" / "api_server.py").read_text()
    assert '"/health"' in src.split("_OPEN_PATHS")[1][:200]


def test_wildcard_cors_is_not_used_when_a_key_is_set():
    """A wildcard origin plus a header key lets any page the analyst visits
    read the whole SOC through their browser."""
    src = (Path(__file__).resolve().parents[1] / "src" / "api_server.py").read_text()
    # Take the whole CORS configuration block, not the gap between the first
    # two mentions of the variable.
    start = src.index('_origins_env = os.environ.get')
    block = src[start:src.index("app.add_middleware(", start)]
    assert "elif API_KEY:" in block, block
    assert "localhost:8000" in block, block
    # The wildcard must only survive when no key is configured.
    assert block.index('["*"]') > block.index("elif API_KEY:")
