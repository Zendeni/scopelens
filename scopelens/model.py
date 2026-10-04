"""Small, versioned primitives shared by importers and reports."""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = 1
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Document:
    path: str
    text: str
    sha256: str
    size: int

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()


def stable_id(*values: object) -> str:
    raw = json.dumps(values, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def clean(value: object, limit: int = 2000) -> str:
    text = str(value)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text[:limit]


def redact(value: object) -> str:
    text = clean(value)
    if re.search(r'''(?i)["'](?:authorization|proxy-authorization|cookie|set-cookie)["']\s*:''', text):
        return "[redacted structured header evidence]"
    text = re.sub(r'''(?i)(["']?(?:authorization|proxy-authorization|cookie|set-cookie)["']?\s*:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n,}]+)''', r"\1[redacted]", text)
    text = re.sub(r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b([\s\"']*[:=][\s\"']*)[^\s,;\"'&]+", r"\1\2[redacted]", text)
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1[redacted]@", text)
    text = re.sub(r'''https?://[^\s<>"']+''', lambda match: safe_url(match.group()) or "[invalid URL]", text)
    return text


def safe_url(value: object) -> str:
    try:
        url = urlsplit(clean(value))
        if url.scheme.lower() not in {"http", "https"} or not url.hostname:
            return ""
        host = url.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        netloc = host + (f":{url.port}" if url.port else "")
        # Query values, fragments and userinfo are intentionally never exported.
        return urlunsplit((url.scheme.lower(), netloc, url.path or "/", "", ""))
    except ValueError:
        return ""


def observation(kind: str, asset: str, data: dict, doc: Document,
                line: int = 1, locator: str = "", confidence: str = "high") -> dict:
    asset = clean(asset, 253).lower().strip().rstrip(".") or "unattributed"
    lines = doc.lines
    excerpt = clean(redact(lines[line - 1]), 320) if 0 < line <= len(lines) else ""
    return {
        "id": stable_id(kind, asset, data), "kind": kind, "asset": asset,
        "data": data, "confidence": confidence,
        "evidence": [{"path": doc.path, "sha256": doc.sha256, "line": line,
                      "locator": locator, "excerpt": excerpt}],
    }
