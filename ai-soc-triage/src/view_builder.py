"""AI-powered custom chart builder.

Accepts a plain English description, uses Claude to generate Plotly + pandas
code, executes it safely in a sandboxed namespace, and returns the figure.
Named views can be saved to disk and reloaded across sessions.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px

from llm_backend import get_llm_backend

BASE_DIR = Path(__file__).resolve().parent.parent
SAVED_VIEWS_DIR = BASE_DIR / "data" / "saved_views"


def generate_view_code(
    description: str,
    df_columns: list[str],
    df_sample: str,
) -> str:
    """Ask Claude to generate Plotly Express chart code from a description.

    Args:
        description: Analyst's natural language chart description.
        df_columns: List of available DataFrame column names.
        df_sample: JSON string of a few sample rows for context.

    Returns:
        Python code string (no imports, assigns figure to 'fig').
    """
    backend = get_llm_backend()
    if backend is None:
        return ""

    try:
        system_prompt = (
            "You are a Python data visualisation expert specialising in Plotly Express "
            "and pandas. Generate clean, working code to create the requested chart. "
            "Rules:\n"
            "- The DataFrame is called 'df' and is already loaded.\n"
            f"- Available columns: {', '.join(df_columns)}\n"
            f"- Sample data: {df_sample}\n"
            "- Return ONLY executable Python code. No markdown, no backticks, no imports.\n"
            "- Assign the final Plotly figure to a variable called 'fig'.\n"
            "- Use plotly.express as px (already imported).\n"
            "- Use pandas as pd (already imported).\n"
            "- Handle empty DataFrames gracefully with a check at the start.\n"
            "- Add a descriptive title to every chart."
        )

        code = backend.generate_text(
            system=system_prompt,
            user=f"Create this chart: {description}",
            max_tokens=800,
        )
        code = code.strip()

        # Strip any accidental markdown fences.
        code = re.sub(r"^```(?:python)?\s*", "", code, flags=re.IGNORECASE)
        code = re.sub(r"\s*```$", "", code)
        return code.strip()
    except Exception as err:
        print(f"[-] View code generation failed: {err}")
        return ""


def execute_view_code(
    code: str,
    df: pd.DataFrame,
) -> tuple[Any, str | None]:
    """Execute generated chart code in a sandboxed namespace.

    Only 'df', 'px', and 'pd' are available to the generated code to
    prevent access to arbitrary Python built-ins.

    Args:
        code: Generated Python code string.
        df: DataFrame to pass in as 'df'.

    Returns:
        Tuple of (plotly_figure_or_None, error_message_or_None).
    """
    if not code.strip():
        return None, "No code to execute."

    # Restricted namespace — only safe data/viz libraries.
    namespace: dict[str, Any] = {
        "df": df.copy(),
        "px": px,
        "pd": pd,
        "__builtins__": {
            "len": len,
            "range": range,
            "list": list,
            "dict": dict,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "print": print,
            "sorted": sorted,
            "enumerate": enumerate,
            "zip": zip,
            "min": min,
            "max": max,
            "sum": sum,
        },
    }

    try:
        compiled = compile(code, "<view>", "exec")
        exec(compiled, namespace)  # noqa: S102
        fig = namespace.get("fig")
        if fig is None:
            return None, "Code executed but did not assign a figure to variable 'fig'."
        return fig, None
    except Exception as err:
        return None, str(err)


def build_view(
    description: str,
    df: pd.DataFrame,
    max_retries: int = 2,
) -> tuple[Any, str]:
    """Generate, execute, and optionally retry a custom chart.

    Args:
        description: Analyst's chart description.
        df: Events/alerts DataFrame.
        max_retries: How many times to retry on execution failure.

    Returns:
        Tuple of (plotly_figure_or_None, code_or_error_message).
    """
    load_dotenv(BASE_DIR / ".env")
    if df.empty:
        return None, "DataFrame is empty — load logs first."

    df_columns = list(df.columns)
    df_sample = df.head(3).to_json(orient="records", default_handler=str)

    code = generate_view_code(description, df_columns, df_sample)
    if not code:
        return None, "API key not configured or code generation failed."

    for attempt in range(max_retries + 1):
        fig, error = execute_view_code(code, df)
        if fig is not None:
            return fig, code
        if attempt < max_retries:
            # Ask Claude to fix the error.
            fix_prompt = (
                f"This Python code raised an error:\n{code}\n\n"
                f"Error: {error}\n\n"
                "Fix it and return ONLY the corrected code. "
                "The DataFrame is 'df', use plotly.express as px, assign result to 'fig'."
            )
            fixed_code = generate_view_code(fix_prompt, df_columns, df_sample)
            if fixed_code:
                code = fixed_code

    return None, f"Chart generation failed after {max_retries + 1} attempts. Last error: {error}"


def save_view(
    name: str,
    description: str,
    code: str,
    folder: str = "",
) -> None:
    """Save a named view to disk as JSON.

    Args:
        name: Human-readable view name.
        description: Original analyst description.
        code: Generated Python code.
        folder: Override directory path.
    """
    target_dir = Path(folder) if folder else SAVED_VIEWS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:50]
    filename = target_dir / f"{slug}.json"

    view_data = {
        "name": name,
        "description": description,
        "code": code,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        with filename.open("w", encoding="utf-8") as fh:
            json.dump(view_data, fh, indent=2)
        print(f"[+] Saved view '{name}' to {filename}")
    except Exception as err:
        print(f"[-] Failed to save view '{name}': {err}")


def load_saved_views(folder: str = "") -> list[dict[str, Any]]:
    """Load all saved view definitions from disk.

    Args:
        folder: Override directory path.

    Returns:
        List of view dicts sorted by creation date descending.
    """
    target_dir = Path(folder) if folder else SAVED_VIEWS_DIR
    if not target_dir.exists():
        return []

    views: list[dict[str, Any]] = []
    for json_file in target_dir.glob("*.json"):
        try:
            with json_file.open("r", encoding="utf-8") as fh:
                view = json.load(fh)
                view["_filename"] = str(json_file)
                views.append(view)
        except Exception as err:
            print(f"[!] Could not load view file {json_file}: {err}")

    views.sort(key=lambda v: v.get("created_at", ""), reverse=True)
    return views


def render_saved_view(view: dict[str, Any], df: pd.DataFrame) -> Any:
    """Execute a saved view's code against the current DataFrame.

    Args:
        view: View dict loaded from disk.
        df: Current events/alerts DataFrame.

    Returns:
        Plotly figure or None if execution fails.
    """
    code = view.get("code", "")
    if not code:
        return None
    fig, error = execute_view_code(code, df)
    if error:
        print(f"[!] Render failed for view '{view.get('name', '')}': {error}")
    return fig


def delete_saved_view(view: dict[str, Any]) -> bool:
    """Delete a saved view file from disk.

    Args:
        view: View dict with '_filename' key.

    Returns:
        True if deleted successfully.
    """
    filename = view.get("_filename", "")
    if not filename:
        return False
    try:
        Path(filename).unlink(missing_ok=True)
        return True
    except Exception as err:
        print(f"[-] Failed to delete view: {err}")
        return False
