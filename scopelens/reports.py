"""Public report-rendering API.

HTML and Markdown implementations live in ``reporting``. Dashboard assets are
bundled with the package and embedded in every HTML file for offline viewing.
"""
from __future__ import annotations

import json

from .reporting.html import render_html
from .reporting.markdown import render_markdown

__all__ = ["render_html", "render_json", "render_markdown"]


def render_json(report: dict) -> str:
    """Serialize the full versioned contract, suitable for automation."""
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
