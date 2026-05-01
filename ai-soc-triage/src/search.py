"""Search module providing filter-syntax and natural language log queries.

Supports two modes:
  - Filter syntax: event_id=4625 AND source_ip=10.0.0.1
  - Natural language: "show all failed logins from external IPs"
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd

from llm_backend import get_llm_backend

BASE_DIR = Path(__file__).resolve().parent.parent


def parse_filter_syntax(query: str, df: pd.DataFrame) -> pd.DataFrame:
    """Parse and apply a filter-syntax query to the DataFrame.

    Supported operators: = != > < >= <= contains
    Supports AND / OR combinations (AND takes precedence).

    Examples:
        event_id=4625 AND source_ip=192.168.1.45
        process_name contains mimikatz
        severity != low AND urgency_score > 5

    Args:
        query: Filter expression string.
        df: Events or alerts DataFrame to query.

    Returns:
        Filtered DataFrame; returns empty DataFrame on invalid query.
    """
    if df.empty or not query.strip():
        return df.copy()

    # Tokenise on AND/OR boundaries (case-insensitive).
    and_parts = re.split(r"\s+AND\s+", query, flags=re.IGNORECASE)

    try:
        result_mask = pd.Series([True] * len(df), index=df.index)
        for part in and_parts:
            part = part.strip()
            # OR within each AND-segment.
            or_parts = re.split(r"\s+OR\s+", part, flags=re.IGNORECASE)
            or_mask = pd.Series([False] * len(df), index=df.index)
            for or_part in or_parts:
                or_part = or_part.strip()
                segment_mask = _apply_single_condition(or_part, df)
                or_mask = or_mask | segment_mask
            result_mask = result_mask & or_mask

        return df[result_mask].copy()
    except Exception:
        return pd.DataFrame(columns=df.columns)


def _apply_single_condition(condition: str, df: pd.DataFrame) -> pd.Series:
    """Evaluate a single field operator value condition.

    Args:
        condition: e.g. 'event_id=4625' or 'process_name contains mimikatz'.
        df: DataFrame to evaluate against.

    Returns:
        Boolean Series mask.
    """
    false_mask = pd.Series([False] * len(df), index=df.index)

    # 'contains' operator.
    contains_match = re.match(
        r"^(\w+)\s+contains\s+(.+)$", condition, flags=re.IGNORECASE
    )
    if contains_match:
        field, value = contains_match.group(1).strip(), contains_match.group(2).strip().strip("'\"")
        if field not in df.columns:
            return false_mask
        return df[field].astype(str).str.contains(re.escape(value), case=False, na=False)

    # Comparison operators: >= <= != > < =
    comp_match = re.match(
        r"^(\w+)\s*(>=|<=|!=|>|<|=)\s*(.+)$", condition
    )
    if comp_match:
        field = comp_match.group(1).strip()
        operator = comp_match.group(2).strip()
        value = comp_match.group(3).strip().strip("'\"")
        if field not in df.columns:
            return false_mask

        col = df[field]

        # Try numeric comparison first.
        try:
            numeric_val = float(value)
            numeric_col = pd.to_numeric(col, errors="coerce")
            if operator == "=":
                return numeric_col == numeric_val
            if operator == "!=":
                return numeric_col != numeric_val
            if operator == ">":
                return numeric_col > numeric_val
            if operator == "<":
                return numeric_col < numeric_val
            if operator == ">=":
                return numeric_col >= numeric_val
            if operator == "<=":
                return numeric_col <= numeric_val
        except ValueError:
            pass

        # String comparison.
        col_str = col.astype(str).str.lower()
        value_lower = value.lower()
        if operator == "=":
            return col_str == value_lower
        if operator == "!=":
            return col_str != value_lower
        # For string columns > < >= <= fall through to False.

    return false_mask


def translate_natural_language(query: str, columns: list[str]) -> str:
    """Use the configured LLM to convert a natural language query to a filter expression.

    Args:
        query: Natural language query from analyst.
        columns: Available DataFrame column names.

    Returns:
        Filter expression string (may be empty if translation fails).
    """
    backend = get_llm_backend()
    if backend is None:
        return ""

    try:
        cols_str = ", ".join(columns)
        system = "You are a log search assistant. Convert natural language queries to filter expressions. Return ONLY the filter string, nothing else."
        user = (
            f"Available columns: {cols_str}\n"
            f"Query: {query}\n\n"
            "Return ONLY the filter string. No explanation.\n"
            "Examples:\n"
            "  Input: failed logins from 10.0.0.1\n"
            "  Output: event_id=4625 AND source_ip=10.0.0.1\n"
            "  Input: critical alerts involving powershell\n"
            "  Output: severity=critical AND process_name contains powershell\n"
        )
        result = backend.generate_text(system=system, user=user, max_tokens=80)
        return result.strip().strip("'\"")
    except Exception as err:
        print(f"[-] NL translation failed: {err}")
        return ""


def search_logs(
    query: str,
    df: pd.DataFrame,
    mode: str = "auto",
) -> tuple[pd.DataFrame, str]:
    """Search the log/alert DataFrame using filter or natural language syntax.

    Args:
        query: Search query string.
        df: DataFrame to search.
        mode: 'auto' tries syntax first then NL; 'syntax' is syntax only;
              'nl' is natural language only.

    Returns:
        Tuple of (results_dataframe, explanation_string).
    """
    if df.empty or not query.strip():
        return df.copy(), "No query provided."

    columns = list(df.columns)

    if mode == "nl":
        translated = translate_natural_language(query, columns)
        if not translated:
            return pd.DataFrame(columns=columns), "Natural language translation returned no filter."
        results = parse_filter_syntax(translated, df)
        explanation = f"Interpreted as: {translated}"
        return results, explanation

    if mode == "syntax":
        results = parse_filter_syntax(query, df)
        explanation = f"Filter applied: {query}"
        return results, explanation

    # auto: try syntax first.
    results = parse_filter_syntax(query, df)
    if not results.empty:
        return results, f"Filter applied: {query}"

    # Fall back to natural language translation.
    translated = translate_natural_language(query, columns)
    if translated:
        results = parse_filter_syntax(translated, df)
        if not results.empty:
            return results, f"Interpreted as: {translated}"

    return pd.DataFrame(columns=columns), "No results found for query."
