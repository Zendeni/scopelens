"""Offline importers for evidence produced by common inventory tools.

Importing never invokes a shell, resolves a hostname, or follows a URL. Unknown
fields stay out of the report. In particular, response cookie values and command
lines are not observations.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import PurePosixPath
import re
import shlex
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from xml.parsers import expat

from .model import Document, clean, observation, redact, safe_url


_HEADERS = frozenset({
    "server", "x-powered-by", "strict-transport-security",
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "content-type", "cache-control",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
})
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_PORT = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+([\w|?-]+)\s+(\S+)(?:\s+(.*))?$")
_SCAN_HOST = re.compile(r"^Nmap scan report for (.+?)\s*$")
_HTTP_STATUS = re.compile(r"^HTTP/(?:\d(?:\.\d)?|2|3)\s+(\d{3})(?:\s|$)", re.I)
MAX_OBSERVATIONS = 10_000
MAX_OBSERVATIONS_PER_DOCUMENT = 5_000
MAX_WARNINGS = 1_000
MAX_WARNINGS_PER_DOCUMENT = 100
MAX_WEB_METADATA_ITEMS = 256


class _ImportLimit(Exception):
    def __init__(self, code: str, message: str, global_limit: bool = False):
        self.code, self.message, self.global_limit = code, message, global_limit


class _BoundedRecords(list):
    """Stop the active importer as soon as either record budget is exhausted."""
    def __init__(self, total_limit: int, document_limit: int, label: str):
        super().__init__()
        self.total_limit, self.document_limit, self.label = total_limit, document_limit, label
        self.document_count = 0

    def begin_document(self) -> None:
        self.document_count = 0

    def append(self, value: dict) -> None:
        if len(self) >= self.total_limit:
            raise _ImportLimit(f"{self.label}-limit",
                               f"Import stopped after {self.total_limit} {self.label}s; evidence is incomplete.", True)
        if self.document_count >= self.document_limit:
            raise _ImportLimit(f"{self.label}-limit",
                               f"Document import stopped after {self.document_limit} {self.label}s; evidence is incomplete.")
        super().append(value)
        self.document_count += 1


def _name(doc: Document) -> str:
    return PurePosixPath(doc.path.replace("\\", "/")).name.lower()


def _warning(warnings: list, doc: Document, code: str, message: str) -> None:
    # Errors never interpolate raw source material or exception messages.
    warnings.append({"code": code, "path": doc.path, "message": message})


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return ""


def _hostname(value: str) -> str:
    value = clean(value, 254).strip().rstrip(".").lower()
    if _ip(value):
        return _ip(value)
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        return ""
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           for label in value.split(".")):
        return ""
    return value


def _asset(url: str) -> str:
    return urlsplit(url).hostname or ""


def _status(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        code = int(str(value))
    except (ValueError, TypeError):
        return None
    return code if 100 <= code <= 599 else None


def _line(doc: Document, needle: str) -> int:
    at = doc.text.find(needle)
    return doc.text.count("\n", 0, max(at, 0)) + 1


def _header_data(raw: object) -> tuple[dict, list]:
    headers: dict[str, str] = {}
    cookies: list[dict] = []
    if not isinstance(raw, dict):
        return headers, cookies
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        key = key.lower().replace("_", "-").strip()
        values = value if isinstance(value, list) else [value]
        values = [v for v in values if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
        if key == "set-cookie":
            for item in values:
                # Do not split on commas: Expires dates contain commas.
                for cookie in str(item).splitlines():
                    parts = [part.strip() for part in cookie.split(";")]
                    if not parts or "=" not in parts[0]:
                        continue
                    name = parts[0].split("=", 1)[0].strip()
                    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-zA-Z-]{1,128}", name):
                        continue
                    attributes = {p.split("=", 1)[0].strip().lower():
                                  p.split("=", 1)[1].strip() if "=" in p else ""
                                  for p in parts[1:]}
                    same_site = attributes.get("samesite", "").lower()
                    if len(cookies) >= MAX_WEB_METADATA_ITEMS:
                        raise _ImportLimit("web-metadata-limit", "Document import stopped at the cookie metadata limit; evidence is incomplete.")
                    cookies.append({"name": name, "secure": "secure" in attributes,
                                    "http_only": "httponly" in attributes,
                                    "same_site": same_site if same_site in {"strict", "lax", "none"} else ""})
        elif key in _HEADERS and values:
            headers[key] = redact(", ".join(str(v) for v in values))
    return headers, cookies


def _web(doc: Document, url: str, *, line: int = 1, locator: str = "",
         title: str = "", status: object = None, technologies: object = None,
         headers: object = None, complete: bool = False) -> dict:
    retained, cookies = _header_data(headers)
    tech = technologies if isinstance(technologies, list) else []
    if len(tech) > MAX_WEB_METADATA_ITEMS:
        raise _ImportLimit("web-metadata-limit", "Document import stopped at the technology metadata limit; evidence is incomplete.")
    data = {"url": url, "title": redact(title) if isinstance(title, str) else "",
            "status": _status(status),
            "technologies": sorted({redact(v) for v in tech if isinstance(v, str) and v.strip()}),
            "headers": retained, "headers_complete": complete, "cookies": cookies}
    return observation("web", _asset(url), data, doc, line, locator)


def _target_env(doc: Document, out: list, warnings: list) -> None:
    fields: dict[str, str] = {}
    for index, raw in enumerate(doc.lines, 1):
        match = re.match(r"^\s*(?:export\s+)?(BOX|NAME|IP|HOST)\s*=\s*(.*?)\s*$", raw)
        if not match:
            continue
        key, value = match.groups()
        # Shell-looking values are ignored as data, never evaluated.
        if "$" in value or "`" in value or ";" in value or "\\" in value:
            _warning(warnings, doc, "unsafe-target-value", f"Ignored nonliteral target assignment at line {index}.")
            continue
        try:
            tokens = shlex.split(value, comments=True, posix=True)
        except ValueError:
            tokens = []
        if len(tokens) != 1:
            _warning(warnings, doc, "invalid-target-value", f"Ignored malformed target assignment at line {index}.")
            continue
        fields[key] = tokens[0]
    ip, host = _ip(fields.get("IP", "")), _hostname(fields.get("HOST", ""))
    if not ip and not host:
        _warning(warnings, doc, "unattributed-target", "No literal valid IP address or hostname was present.")
        return
    out.append(observation("target", ip or host,
                           {"name": redact(fields.get("BOX", fields.get("NAME", host or ip))),
                            "ip": ip, "host": host}, doc, locator="target environment"))


def _xml_locations(text: str) -> list[dict]:
    """Record exact source lines, including repeated ports on different hosts."""
    locations: list[dict] = []
    stack: list[str] = []
    parser = expat.ParserCreate()

    def start(tag: str, attrs: dict) -> None:
        if tag == "host" and stack == ["nmaprun"]:
            locations.append({"line": parser.CurrentLineNumber, "ports": [], "addresses": {}})
        elif locations and tag == "port" and stack == ["nmaprun", "host", "ports"]:
            locations[-1]["ports"].append(parser.CurrentLineNumber)
        elif locations and tag == "address" and stack == ["nmaprun", "host"]:
            locations[-1]["addresses"][attrs.get("addr", "")] = parser.CurrentLineNumber
        stack.append(tag)

    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _tag: stack.pop()
    parser.Parse(text, True)
    return locations


def _nmap_xml(doc: Document, out: list, warnings: list) -> None:
    text = doc.text
    # Nmap's ordinary <!DOCTYPE nmaprun> is harmless. Other DTDs, entity
    # declarations and external identifiers are rejected before XML parsing.
    if re.search(r"<!\s*ENTITY\b", text, re.I):
        _warning(warnings, doc, "unsafe-xml", "XML entity declarations are not accepted.")
        return
    for doctype in re.finditer(r"<!\s*DOCTYPE\b", text, re.I):
        if not re.match(r"<!DOCTYPE\s+nmaprun\s*>", text[doctype.start():]):
            _warning(warnings, doc, "unsafe-xml", "Only the plain Nmap doctype is accepted; DTDs and external references are rejected.")
            return
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, LookupError):
        _warning(warnings, doc, "malformed-xml", "Could not parse the XML document.")
        return
    if root.tag != "nmaprun":
        _warning(warnings, doc, "unsupported-xml", "The XML root is not nmaprun.")
        return
    try:
        locations = _xml_locations(text)
    except (expat.ExpatError, ValueError, LookupError):
        _warning(warnings, doc, "malformed-xml", "Could not parse XML source locations.")
        return
    for hi, host in enumerate(root.findall("host"), 1):
        source = locations[hi - 1]
        addresses = [_ip(a.get("addr", "")) for a in host.findall("address")
                     if a.get("addrtype") in {"ipv4", "ipv6"}]
        ip = next((a for a in addresses if a), "")
        names = [_hostname(n.get("name", "")) for n in host.findall("./hostnames/hostname")]
        name = next((n for n in names if n), "")
        asset = ip or name
        if not asset:
            _warning(warnings, doc, "unattributed-nmap-host", f"Skipped Nmap host {hi} without a valid address or hostname.")
            continue
        out.append(observation("target", asset, {"name": name or ip, "ip": ip, "host": name},
                               doc, source["addresses"].get(ip, source["line"]), f"/nmaprun/host[{hi}]"))
        for pi, port in enumerate(host.findall("./ports/port"), 1):
            protocol, number = port.get("protocol", ""), port.get("portid", "")
            if protocol not in {"tcp", "udp"} or not number.isdigit() or not 1 <= int(number) <= 65535:
                _warning(warnings, doc, "invalid-nmap-port", f"Skipped invalid port in Nmap host {hi}.")
                continue
            state, service = port.find("state"), port.find("service")
            data = {"port": int(number), "protocol": protocol,
                    "state": clean(state.get("state", "unknown")) if state is not None else "unknown",
                    "service": redact(service.get("name", "")) if service is not None else "",
                    "tunnel": redact(service.get("tunnel", "")) if service is not None else "",
                    "product": redact(service.get("product", "")) if service is not None else "",
                    "version": redact(service.get("version", "")) if service is not None else ""}
            # Protocol is part of the observation identity, so UDP and TCP survive.
            out.append(observation("service", asset, data, doc,
                                   source["ports"][pi - 1],
                                   f"/nmaprun/host[{hi}]/ports/port[{pi}]"))


def _nmap_text(doc: Document, out: list, warnings: list) -> None:
    current = ""
    for index, raw in enumerate(doc.lines, 1):
        raw = clean(raw)
        match = _SCAN_HOST.match(raw)
        if match:
            # Reset before parsing: an invalid next host cannot inherit the last.
            current = ""
            label = match.group(1)
            named = re.fullmatch(r"(.+?)\s+\(([^()]+)\)", label)
            ip = _ip(named.group(2) if named else label)
            host = _hostname(named.group(1) if named else label) if not _ip(label) else ""
            current = ip or host
            if current:
                out.append(observation("target", current, {"name": host or ip, "ip": ip, "host": host},
                                       doc, index, "Nmap scan report"))
            else:
                _warning(warnings, doc, "unattributed-nmap-host", f"Invalid host at line {index}; following ports will not be attributed.")
            continue
        match = _PORT.match(raw)
        if not match:
            continue
        if not current:
            _warning(warnings, doc, "unattributed-service", f"Skipped service at line {index} without an explicit Nmap host.")
            continue
        number, protocol, state, service, banner = match.groups()
        if not 1 <= int(number) <= 65535:
            _warning(warnings, doc, "invalid-nmap-port", f"Skipped invalid port at line {index}.")
            continue
        banner = banner or ""
        version_match = re.match(r"^(.*?)\s+(\d[\w.+:~_-]*)(?:\s|$)", banner)
        product = version_match.group(1) if version_match else banner
        version = version_match.group(2) if version_match else ""
        data = {"port": int(number), "protocol": protocol, "state": state,
                "service": redact(service), "tunnel": "ssl" if service.startswith("ssl/") else "",
                "product": redact(product), "version": redact(version)}
        out.append(observation("service", current, data, doc, index, "Nmap port row"))


def _httpx_row(doc: Document, row: object, out: list, warnings: list, line: int) -> None:
    if not isinstance(row, dict):
        _warning(warnings, doc, "invalid-httpx-record", f"Expected a JSON object at line {line}.")
        return
    # httpx can retain the original request URL while returning status and
    # headers from a redirected response. Attribute those fields to final_url.
    if "final_url" in row:
        url = safe_url(row["final_url"]) if isinstance(row["final_url"], str) else ""
        if not url:
            _warning(warnings, doc, "invalid-final-url", f"Skipped response at line {line} because its explicit final URL is invalid.")
            return
    else:
        url = safe_url(row.get("url", ""))
        if not url:
            url = safe_url(row.get("input", ""))
    if not url:
        _warning(warnings, doc, "unattributed-web", f"Record at line {line} has no explicit valid HTTP URL.")
        return
    if "status_code" in row and _status(row["status_code"]) is None:
        _warning(warnings, doc, "invalid-http-status", f"Ignored invalid HTTP status at line {line}.")
    headers = row.get("header", row.get("headers", {}))
    headers = dict(headers) if isinstance(headers, dict) else {}
    if isinstance(row.get("webserver"), str):
        headers.setdefault("server", row["webserver"])
    out.append(_web(doc, url, line=line, locator="httpx record", title=row.get("title", ""),
                    status=row.get("status_code", row.get("status")),
                    technologies=row.get("tech", row.get("technologies", [])), headers=headers))


def _ffuf(doc: Document, payload: dict, out: list, warnings: list) -> None:
    results = payload.get("results")
    if not isinstance(results, list):
        _warning(warnings, doc, "invalid-ffuf-schema", "ffuf results must be an array.")
        return
    config = payload.get("config", {})
    config = config if isinstance(config, dict) else {}
    raw_headers = config.get("headers", {})
    vhost_fuzzing = ("vhost" in _name(doc) or
                    (isinstance(raw_headers, dict) and
                     any(str(k).lower() == "host" and "FUZZ" in str(v)
                         for k, v in raw_headers.items())) or
                    (isinstance(raw_headers, list) and
                     any(isinstance(h, str) and re.match(r"(?i)^host\s*:", h) and "FUZZ" in h
                         for h in raw_headers)))
    for index, row in enumerate(results):
        if not isinstance(row, dict):
            _warning(warnings, doc, "invalid-ffuf-record", f"Skipped non-object ffuf result {index}.")
            continue
        url = safe_url(row.get("url", ""))
        host = row.get("host")
        if vhost_fuzzing or isinstance(host, str) and host:
            # ffuf's URL is the transport target, not necessarily the Host tested.
            authority = safe_url(f"http://{host}/") if isinstance(host, str) else ""
            if (not authority or not _hostname(_asset(authority)) or
                    any(character in host for character in "/@?#")):
                _warning(warnings, doc, "unattributed-vhost", f"Skipped ffuf result {index} without a literal response host.")
                continue
            if url:
                parts = urlsplit(url)
                host_parts = urlsplit(authority)
                host_authority = host_parts.netloc
                if host_parts.port is None and parts.port is not None:
                    host_authority += f":{parts.port}"
                url = safe_url(f"{parts.scheme}://{host_authority}{parts.path}")
        if not url:
            _warning(warnings, doc, "unattributed-web", f"Skipped ffuf result {index} without a valid HTTP URL.")
            continue
        out.append(_web(doc, url, line=_line(doc, '"url"'), locator=f"/results/{index}", status=row.get("status")))


def _json(doc: Document, out: list, warnings: list) -> None:
    try:
        payload = json.loads(doc.text)
    except (ValueError, RecursionError):
        # JSONL is parsed independently so one broken record does not hide others.
        for index, raw in enumerate(doc.lines, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except (ValueError, RecursionError):
                _warning(warnings, doc, "malformed-json", f"Could not parse JSON at line {index}.")
                continue
            _httpx_row(doc, row, out, warnings, index)
        return
    if isinstance(payload, dict) and ("results" in payload or "ffuf" in _name(doc)):
        _ffuf(doc, payload, out, warnings)
    elif isinstance(payload, list):
        for row in payload:
            _httpx_row(doc, row, out, warnings, 1)
    else:
        _httpx_row(doc, payload, out, warnings, 1)


def _httpx_text(doc: Document, out: list, warnings: list) -> None:
    for index, raw in enumerate(doc.lines, 1):
        raw = clean(raw).strip()
        if not raw or raw.startswith("#"):
            continue
        match = re.match(r"^(https?://\S+)(?:\s+(.*))?$", raw, re.I)
        if not match:
            continue
        url = safe_url(match.group(1))
        if not url:
            _warning(warnings, doc, "unattributed-web", f"Skipped invalid URL at line {index}.")
            continue
        fields = re.findall(r"\[([^\]]*)\]", match.group(2) or "")
        # Plain httpx field order depends on flags. Status is recognizable; other
        # bracket groups cannot reliably be distinguished from titles or banners.
        status = next((_status(x) for x in fields if _status(x) is not None), None)
        out.append(_web(doc, url, line=index, locator="HTTP URL row", status=status))


def _sanitized_url(url: str) -> str:
    return re.sub(r"[/:?&=.]", "_", url)


def _header_url(doc: Document, known_urls: set[str]) -> str:
    explicit = []
    for line in doc.lines:
        if re.match(r"^\s*(?:#\s*)?(?:URL|Request URL|Effective URL)\s*:", line, re.I):
            explicit.extend(safe_url(m.group(0)) for m in _URL.finditer(line))
    explicit = sorted({u for u in explicit if u})
    if len(explicit) == 1:
        return explicit[0]
    if explicit:
        return ""  # Several requests require separate captures.
    name = PurePosixPath(doc.path.replace("\\", "/")).name
    if name.lower().startswith("headers-host-"):
        return ""  # htb-init passes a separate Host header not encoded in filename.
    match = re.fullmatch(r"headers-(.+)\.txt", name, re.I)
    if not match:
        return ""
    encoded = match.group(1)
    matching = {u for u in known_urls if encoded in {_sanitized_url(u), _sanitized_url(u.rstrip("/"))}}
    if len(matching) == 1:
        return matching.pop()
    # An IPv4 origin can be recovered unambiguously. Generic DNS/path strings
    # cannot: all dots, slashes and ports share the same underscore encoding.
    origin = re.fullmatch(r"(https?)___(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})(?:_(\d{1,5}))?_?", encoded)
    if origin:
        scheme, *rest = origin.groups()
        ip = _ip(".".join(rest[:4]))
        port = rest[4]
        if ip and (port is None or 1 <= int(port) <= 65535):
            return safe_url(f"{scheme}://{ip}" + (f":{port}" if port else ""))
    return ""


def _raw_headers(doc: Document, out: list, warnings: list, known_urls: set[str]) -> None:
    url = _header_url(doc, known_urls)
    if not url:
        _warning(warnings, doc, "unattributed-headers", "Headers have no unambiguous response URL; add a 'URL: https://host/path' line to a single-response capture.")
        return
    blocks: list[tuple[int, int, dict]] = []
    current: dict | None = None
    status, start = None, 1
    for index, raw in enumerate(doc.lines, 1):
        match = _HTTP_STATUS.match(raw.strip())
        if match:
            if current is not None:
                blocks.append((start, status, current))
            status, start, current = int(match.group(1)), index, {}
        elif current is not None and ":" in raw and not raw[:1].isspace():
            key, value = raw.split(":", 1)
            if re.fullmatch(r"[A-Za-z0-9-]+", key):
                current.setdefault(key.lower(), []).append(value.strip())
        elif current is not None and not raw.strip():
            blocks.append((start, status, current))
            current = None
    if current is not None:
        blocks.append((start, status, current))
    # Skip informational responses and CONNECT proxy negotiation.
    substantive = [(line, code, headers) for line, code, headers in blocks
                   if code >= 200 and "connection established" not in doc.lines[line - 1].lower()]
    if len(substantive) != 1:
        _warning(warnings, doc, "ambiguous-headers", "Capture does not contain exactly one attributable final response; split redirect chains into individual captures.")
        return
    line, status, headers = substantive[0]
    out.append(_web(doc, url, line=line, locator="HTTP response headers", status=status,
                    headers=headers, complete=True))


def _requirements(doc: Document, out: list, warnings: list) -> None:
    for index, raw in enumerate(doc.lines, 1):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;[^#]*)?(?:\s+#.*)?", raw)
        if not match:
            _warning(warnings, doc, "unpinned-requirement", f"Skipped non-exact or unsupported requirement at line {index}.")
            continue
        name, version = match.groups()
        name = re.sub(r"[-_.]+", "-", name).lower()
        out.append(observation("package", f"dependency:{name}",
                               {"ecosystem": "pypi", "name": name, "version": version},
                               doc, index, "exact requirement pin"))


def _npm(doc: Document, out: list, warnings: list) -> None:
    try:
        payload = json.loads(doc.text)
    except (ValueError, RecursionError):
        _warning(warnings, doc, "malformed-json", "Could not parse package-lock.json.")
        return
    if not isinstance(payload, dict):
        _warning(warnings, doc, "invalid-package-lock", "package-lock.json must contain an object.")
        return
    emitted = 0
    def emit(name: object, info: object, locator: str) -> None:
        nonlocal emitted
        if not isinstance(name, str) or not isinstance(info, dict):
            return
        version = info.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.+-]+)?", version):
            return
        if not re.fullmatch(r"(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+", name):
            return
        out.append(observation("package", f"dependency:{name}",
                               {"ecosystem": "npm", "name": name, "version": version},
                               doc, _line(doc, f'"{name}"'), locator))
        emitted += 1
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not isinstance(path, str) or "node_modules/" not in path:
                continue
            name = path.rsplit("node_modules/", 1)[1]
            emit(name, info, f"/packages/{path}")
    elif isinstance(payload.get("dependencies"), dict):
        stack = [(payload["dependencies"], "/dependencies")]
        while stack:
            dependencies, prefix = stack.pop()
            for name, info in dependencies.items():
                emit(name, info, prefix + "/" + name)
                if isinstance(info, dict) and isinstance(info.get("dependencies"), dict):
                    stack.append((info["dependencies"], prefix + "/" + name + "/dependencies"))
    else:
        _warning(warnings, doc, "invalid-package-lock", "No packages or dependencies mapping was present.")


def _parse_document(doc: Document, out: list, warnings: list, header_docs: list) -> None:
    name, stripped = _name(doc), doc.text.lstrip("\ufeff \t\r\n")
    if name == ".target.env":
        _target_env(doc, out, warnings)
    elif name == "package-lock.json":
        _npm(doc, out, warnings)
    elif re.fullmatch(r"requirements(?:[._-][\w.-]+)?\.txt", name):
        _requirements(doc, out, warnings)
    elif stripped.startswith(("<?xml", "<nmaprun", "<!DOCTYPE", "<!doctype")) or (name.endswith(".xml") and "nmap" in stripped[:500].lower()):
        _nmap_xml(doc, out, warnings)
    elif any(_SCAN_HOST.match(line) for line in doc.lines) or "nmap" in name:
        _nmap_text(doc, out, warnings)
    elif any(_HTTP_STATUS.match(line.strip()) for line in doc.lines):
        header_docs.append(doc)
    elif name.endswith((".json", ".jsonl", ".ndjson")) or stripped.startswith(("{", "[")):
        _json(doc, out, warnings)
    elif "httpx" in name or name in {"live-web-urls.txt", "web-candidates.txt"} or any(re.match(r"^https?://", line) for line in doc.lines):
        _httpx_text(doc, out, warnings)
    elif any(_PORT.match(line) for line in doc.lines):
        _nmap_text(doc, out, warnings)


def parse_documents(documents: list[Document]) -> tuple[list[dict], list[dict]]:
    """Parse supported evidence with bounded observation and warning counts.

    Each document supplies its own host attribution. A target file never causes
    unrelated network observations to be silently assigned to that target.
    Reaching a limit stops the affected import and adds an incompleteness warning.
    """
    out = _BoundedRecords(MAX_OBSERVATIONS, MAX_OBSERVATIONS_PER_DOCUMENT, "observation")
    warnings = _BoundedRecords(MAX_WARNINGS, MAX_WARNINGS_PER_DOCUMENT, "warning")
    header_docs: list[Document] = []

    def run(doc: Document, parser, *args) -> bool:
        out.begin_document()
        warnings.begin_document()
        try:
            parser(doc, out, warnings, *args)
        except _ImportLimit as limit:
            # Reserve one terminal warning even if the warning budget caused
            # the stop. This append intentionally bypasses the bounded method.
            list.append(warnings, {"code": limit.code, "path": doc.path, "message": limit.message})
            return not limit.global_limit and len(warnings) <= MAX_WARNINGS
        return True

    for doc in documents:
        if not run(doc, _parse_document, header_docs):
            return list(out), list(warnings)
    known_urls = {o["data"]["url"] for o in out if o["kind"] == "web"}
    for doc in header_docs:
        if not run(doc, _raw_headers, known_urls):
            break
    return list(out), list(warnings)
