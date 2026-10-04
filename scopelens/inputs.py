"""Bounded, read-only artifact loading. Archives are never extracted."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile
import zlib

from .model import Document, clean


@dataclass(frozen=True)
class Limits:
    max_files: int = 3000
    max_file_bytes: int = 4 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_ratio: int = 200


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "loot",
             "exploits", "shells", "screenshots", "scopelens-report", "reports"}
SKIP_NAMES = {"report.json", "report.html", "report.md", "recon-analysis.md",
              "notes.md", "writeup.md", "recon-console.log"}
SUFFIXES = {".xml", ".txt", ".nmap", ".gnmap", ".json", ".jsonl", ".ndjson", ".md", ".headers", ".log"}


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def supported(path: str) -> bool:
    p = PurePosixPath(path)
    return (not any(part.lower() in SKIP_DIRS for part in p.parts)
            and p.name.lower() not in SKIP_NAMES
            and (p.suffix.lower() in SUFFIXES or p.name == ".target.env"))


def load_input(source: Path, limits: Limits | None = None,
               exclude: Path | None = None) -> tuple[list[Document], list[dict], list[dict]]:
    limits = limits or Limits()
    source = Path(source).expanduser().absolute()
    if source.exists() and is_link(source):
        raise ValueError("Input must not be a symbolic link")
    if not source.exists():
        raise ValueError(f"Input does not exist: {source}")
    documents: list[Document] = []
    coverage: list[dict] = []
    warnings: list[dict] = []
    consumed = 0

    def skip(path: str, reason: str, size: int = 0, status: str = "skipped") -> None:
        coverage.append({"path": clean(path), "status": status, "bytes": size, "reason": reason})
        if reason != "unsupported or excluded artifact":
            warnings.append({"code": "input_skipped", "path": clean(path), "message": reason})

    def accept(path: str, size: int, opener) -> None:
        nonlocal consumed
        if not supported(path):
            skip(path, "unsupported or excluded artifact", size)
            return
        if size > limits.max_file_bytes:
            skip(path, "file size limit exceeded; no partial parsing", size)
            return
        if consumed + size > limits.max_total_bytes:
            skip(path, "total input byte limit exceeded", size)
            return
        try:
            with opener() as stream:
                raw = stream.read(limits.max_file_bytes + 1)
        except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error, NotImplementedError) as exc:
            skip(path, f"read failed: {type(exc).__name__}", size, "error")
            return
        consumed += len(raw)
        if len(raw) > limits.max_file_bytes or consumed > limits.max_total_bytes:
            skip(path, "input changed or exceeded byte limit during read", len(raw))
            return
        digest = hashlib.sha256(raw).hexdigest()
        if not raw:
            coverage.append({"path": clean(path), "status": "empty", "bytes": 0, "sha256": digest})
            return
        if b"\x00" in raw:
            skip(path, "binary or unsupported text encoding", size)
            return
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            warnings.append({"code": "encoding_replaced", "path": clean(path),
                             "message": "Non-UTF-8 bytes replaced; interpretation may be incomplete"})
        documents.append(Document(clean(path), text, digest, len(raw)))
        coverage.append({"path": clean(path), "status": "loaded", "bytes": len(raw), "sha256": digest})

    if source.is_file() and source.suffix.lower() == ".zip":
        if source.stat().st_size > 128 * 1024 * 1024:
            raise ValueError("Archive exceeds 128 MiB compressed size limit")
        try:
            with zipfile.ZipFile(source) as archive:
                members = archive.infolist()
                if len(members) > limits.max_files:
                    raise ValueError(f"Archive has more than {limits.max_files} entries")
                names: set[str] = set()
                for member in sorted(members, key=lambda item: item.filename):
                    name = member.filename
                    parts = PurePosixPath(name).parts
                    if (not parts or name.startswith(("/", "\\")) or "\\" in name
                            or ".." in parts or any(":" in p for p in parts)
                            or any(ord(c) < 32 for c in name)):
                        raise ValueError("Archive contains an unsafe member name")
                    normalized = "/".join(parts).casefold()
                    if normalized in names:
                        raise ValueError("Archive contains duplicate or ambiguous member names")
                    names.add(normalized)
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                        skip(name, "archive links and special files are unsupported", member.file_size)
                    elif member.is_dir():
                        continue
                    elif member.flag_bits & 1:
                        skip(name, "encrypted archive member", member.file_size)
                    elif member.file_size > max(member.compress_size, 1) * limits.max_ratio:
                        skip(name, "archive compression ratio limit exceeded", member.file_size)
                    else:
                        accept(name, member.file_size, lambda item=member: archive.open(item))
        except zipfile.BadZipFile as exc:
            raise ValueError("Invalid or damaged ZIP archive") from exc
    elif source.is_dir():
        count = 0
        stop = False
        excluded = exclude.resolve() if exclude else None
        def walk_error(exc):
            warnings.append({"code": "directory_unreadable", "path": clean(str(exc.filename)),
                             "message": "Directory could not be read"})
        for directory, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
            dirs.sort()
            keep = []
            for name in dirs:
                path = Path(directory) / name
                count += 1
                if count > limits.max_files:
                    stop = True
                    break
                relative = path.relative_to(source).as_posix()
                if is_link(path):
                    skip(relative, "directory link ignored")
                elif name.lower() not in SKIP_DIRS and (excluded is None or path.resolve() != excluded):
                    keep.append(name)
                else:
                    skip(relative + "/", "unsupported or excluded artifact")
            dirs[:] = keep
            if stop:
                break
            for name in sorted(files):
                count += 1
                if count > limits.max_files:
                    stop = True
                    break
                path = Path(directory) / name
                relative = path.relative_to(source).as_posix()
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or is_link(path):
                        skip(relative, "links and special files ignored")
                    else:
                        accept(relative, info.st_size, lambda p=path: p.open("rb"))
                except OSError:
                    skip(relative, "file metadata unavailable", status="error")
            if stop:
                break
        if stop:
            warnings.append({"code": "entry_limit", "path": "", "message": f"Directory entry limit ({limits.max_files}) reached; analysis is incomplete"})
    elif source.is_file():
        accept(source.name, source.stat().st_size, lambda: source.open("rb"))
    else:
        raise ValueError("Input must be a regular file, directory, or ZIP archive")
    return documents, coverage, warnings
