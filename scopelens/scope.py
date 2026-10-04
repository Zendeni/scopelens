"""Literal host and network scope; matching never resolves DNS."""
from __future__ import annotations

import ipaddress
import re


def normalize_host(value: str) -> str:
    """Canonicalize one literal scope entry, allowing a DNS root dot."""
    value = value.strip().lower()
    # A single root dot is valid; multiple trailing dots contain an empty label.
    if value.endswith(".."):
        raise ValueError(f"Invalid scope entry: {value}")
    value = value.removesuffix(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        if re.fullmatch(r"[0-9.]+", value) and "." in value:
            raise ValueError(f"Invalid IP address in scope: {value}")
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(f"Invalid scope entry: {value}") from exc
        if (len(value) > 253 or not value or
                not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split("."))):
            raise ValueError(f"Invalid scope entry: {value}")
        return value


def validate_scope(scope: dict | None) -> dict:
    """Return normalized include/exclude lists without changing the input."""
    if scope is None:
        return {"include": [], "exclude": []}
    if not isinstance(scope, dict) or set(scope) - {"include", "exclude"}:
        raise ValueError("Scope must be an object with include and exclude arrays")
    result = {}
    for key in ("include", "exclude"):
        values = scope.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"Scope {key} must be an array of hostnames, IPs, or CIDRs")
        result[key] = sorted({normalize_host(value) for value in values})
    return result


def in_scope(asset: str, scope: dict) -> bool:
    """Match a host against validated scope, with exclusions taking priority."""
    try:
        asset = normalize_host(asset)
    except ValueError:
        asset = asset.lower().rstrip(".")
    def matches(entry: str) -> bool:
        try:
            if "/" in entry:
                return ipaddress.ip_address(asset) in ipaddress.ip_network(entry)
        except ValueError:
            return False
        return asset.lower().rstrip(".") == entry
    if any(matches(entry) for entry in scope["exclude"]):
        return False
    return not scope["include"] or any(matches(entry) for entry in scope["include"])
