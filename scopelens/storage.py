"""Bounded file reads and non-overwriting publication of generated artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import tempfile

from .inputs import is_link

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_SCOPE_BYTES = 1024 * 1024


def no_links(path: Path) -> None:
    """Reject links and Windows reparse points in the path or its parents."""
    path = path.expanduser().absolute()
    for part in (*reversed(path.parents), path):
        if os.path.lexists(part) and is_link(part):
            raise ValueError(f"Links are not allowed for workspace files: {part}")


def regular_file(path: Path, *, missing: bool = False) -> bool:
    no_links(path)
    if not path.exists() and missing:
        return False
    if not path.is_file():
        raise ValueError(f"Expected a regular file: {path}")
    return True


def read_json(path: Path, limit: int = MAX_JSON_BYTES):
    path = path.expanduser().absolute()
    no_links(path)
    if not path.is_file():
        raise ValueError(f"Expected a regular JSON file: {path}")
    if type(limit) is not int or limit < 1:
        raise ValueError("JSON byte limit must be a positive integer")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"JSON file exceeds {limit} bytes")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid JSON: {path.name}") from exc


def new_directory(path: Path) -> Path:
    """Validate a future destination without creating it or its parents."""
    path = path.expanduser().absolute()
    no_links(path)
    if os.path.lexists(path):
        raise ValueError(f"Output already exists; choose a new directory: {path}")
    return path


def _relative_file(name: str) -> Path:
    # Treat Windows drive paths and separators consistently on every platform.
    if (not isinstance(name, str) or not name or "\\" in name or ":" in name
            or PureWindowsPath(name).anchor
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ValueError(f"Expected a relative output filename: {name}")
    return Path(name)


def publish_directory(destination: Path, files: dict[str, str]) -> None:
    """Stage complete files, then claim a new directory without replacing data.

    Failures during publication leave any partial output for inspection. All
    destination files are opened exclusively, including after the directory is
    claimed; a file created by another process is never overwritten.
    """
    destination = new_directory(destination)
    paths = {_relative_file(name): content for name, content in files.items()}
    destination.parent.mkdir(parents=True, exist_ok=True)
    no_links(destination.parent)
    stage = Path(tempfile.mkdtemp(prefix=".scopelens-", dir=destination.parent))
    try:
        for name, content in paths.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        # mkdir is exclusive on all supported platforms, unlike directory rename.
        destination.mkdir(mode=0o700)
        for name in paths:
            path = destination / name
            no_links(path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (stage / name).open("rb") as source, path.open("xb") as target:
                shutil.copyfileobj(source, target)
            try:
                path.chmod(0o600)
            except OSError:
                pass
    finally:
        # This is only our private temporary directory, never the destination.
        # A cleanup error must not replace an original read/write failure.
        try:
            shutil.rmtree(stage)
        except OSError:
            pass
