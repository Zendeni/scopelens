"""Read trusted package assets without relying on the current directory."""
from __future__ import annotations

from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def dashboard_assets() -> tuple[str, str]:
    """Return the static CSS and JavaScript embedded into an offline report.

    ``importlib.resources`` also supports a package installed from a wheel or
    imported from an archive; no adjacent checkout or external files are needed.
    """
    assets = files(__package__).joinpath("assets")
    return (assets.joinpath("report.css").read_text(encoding="utf-8"),
            assets.joinpath("report.js").read_text(encoding="utf-8"))
