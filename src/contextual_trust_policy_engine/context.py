"""Context aggregation for Zero Trust Agent Benchmark shaped requests."""

from __future__ import annotations

import base64
import binascii
import codecs
import fnmatch
import ipaddress
import re
import time
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from .models import Attributes
from .trust import Outcome, TrustOracle

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SECRET_RE = re.compile(
    r"(?i)("
    r"AKIA[0-9A-Z]{12,20}|"
    r"sk_live_[A-Za-z0-9]{24,}|"
    r"ghp_[A-Za-z0-9]{24,}|"
    r"token\s*[=:]|api[_-]?key|password|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


@dataclass(frozen=True, slots=True)
class ToolMeta:
    risk: str
    required_scopes: tuple[str, ...]
    relations: dict[str, str]
    egress: bool = False


DEFAULT_TOOL_CATALOG: dict[str, ToolMeta] = {
    "*": ToolMeta("critical", (), {}, False),
}


def _as_map(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _as_str_seq(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(str(x) for x in value)
    return ()


def parse_spiffe_id(spiffe_id: str) -> tuple[str | None, tuple[str, ...]]:
    parsed = urlparse(spiffe_id)
    if parsed.scheme != "spiffe" or not parsed.netloc:
        return None, ()
    return parsed.netloc, tuple(p for p in parsed.path.split("/") if p)


def _extract_hosts(value: object) -> set[str]:
    hosts: set[str] = set()
    if isinstance(value, Mapping):
        for item in value.values():
            hosts.update(_extract_hosts(item))
    elif isinstance(value, Sequence) and not isinstance(value, str):
        for item in value:
            hosts.update(_extract_hosts(item))
    elif isinstance(value, str):
        for match in re.finditer(r"https?://[^\s'\")<>]+", value):
            parsed = urlparse(match.group(0))
            if parsed.hostname:
                hosts.add(parsed.hostname.lower())
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            hosts.add(parsed.hostname.lower())
        if "@" in value and _EMAIL_RE.fullmatch(value.strip()):
            hosts.add(value.rsplit("@", 1)[1].lower())
        for match in _EMAIL_RE.finditer(value):
            hosts.add(match.group(0).rsplit("@", 1)[1].lower())
    return hosts


def _safe_decode(marker: str) -> str:
    try:
        padded = marker + "=" * (-len(marker) % 4)
        return base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def jsonish(value: object) -> str:
    if isinstance(value, Mapping):
        return " ".join(f"{k} {jsonish(v)}" for k, v in value.items())
    if isinstance(value, Sequence) and not isinstance(value, str):
        return " ".join(jsonish(v) for v in value)
    return str(value)


_SECRET_URI_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s'\")<>]+")


def has_control_format_chars(value: object) -> bool:
    text = jsonish(value)
    return any(unicodedata.category(ch) in {"Cf", "Cc"} and ch not in "\t\n\r" for ch in text)


def has_truncated_structured_frame(value: object) -> bool:
    text = jsonish(value)
    if not any(ch in text for ch in "{}[]"):
        return False
    stack: list[str] = []
    pairs = {"}": "{", "]": "["}
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):
            return True
    return in_string or bool(stack)


def has_unsafe_secret_reference(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(has_unsafe_secret_reference(v) for v in value.values())
    if isinstance(value, Sequence) and not isinstance(value, str):
        return any(has_unsafe_secret_reference(v) for v in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    refs = [
        m.group(0)
        for m in _SECRET_URI_RE.finditer(text)
        if m.group(0).lower().startswith("secret://")
    ]
    return bool(refs) and text not in refs


def contains_secret_marker(value: object, secrets: Sequence[str] = ()) -> bool:
    text = jsonish(value)
    candidates = _secret_candidates(text)
    if any(_SECRET_RE.search(candidate) for candidate in candidates):
        return True
    return any(secret and secret in candidate for secret in secrets for candidate in candidates)


def _secret_candidates(text: str) -> set[str]:
    candidates = {text, unquote(text), text[::-1]}
    compact = re.sub(r"[^A-Za-z0-9_]", "", text)
    if compact:
        candidates.add(compact)
        candidates.add(compact[::-1])
    with suppress(ValueError):
        candidates.add(codecs.decode(text, "rot_13"))
    for token in _TOKEN_RE.findall(text):
        candidates.add(token)
        candidates.add(token[::-1])
        decoded = _safe_decode(token)
        if decoded:
            candidates.add(decoded)
        if len(token) >= 24 and len(token) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", token):
            with suppress(ValueError):
                candidates.add(bytes.fromhex(token).decode("utf-8", "ignore"))
    return candidates


def contains_pii(value: object) -> bool:
    return _EMAIL_RE.search(jsonish(value)) is not None


def _allowed_host(host: str, allowlist: Sequence[str]) -> bool:
    normalized = host.lower().rstrip(".")
    if any(normalized == item or normalized.endswith("." + item) for item in allowlist):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass
    return any(
        normalized.endswith("." + suffix.lstrip("*."))
        for suffix in allowlist
        if suffix.startswith("*.")
    )


def untrusted_hosts(value: object, allowlist: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(h for h in _extract_hosts(value) if not _allowed_host(h, allowlist)))


def load_tool_catalog(path: str | None) -> dict[str, ToolMeta]:
    if path is None:
        return dict(DEFAULT_TOOL_CATALOG)
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    tools = data.get("tools", data) if isinstance(data, Mapping) else {}
    out = dict(DEFAULT_TOOL_CATALOG)
    if isinstance(tools, Mapping):
        for name, raw in tools.items():
            if isinstance(raw, Mapping):
                relations = _as_map(raw.get("relations"))
                out[str(name)] = ToolMeta(
                    str(raw.get("risk", "critical")),
                    _as_str_seq(raw.get("required_scopes", raw.get("scopes", ()))),
                    {str(k): str(v) for k, v in relations.items()},
                    bool(raw.get("egress", False)),
                )
    return out


class ContextAggregator:
    """Turns a defense request into normalized policy attributes."""

    def __init__(
        self,
        *,
        trust_oracle: TrustOracle | None = None,
        tool_catalog: Mapping[str, ToolMeta] | None = None,
        allowlist: Sequence[str] = (),
        trust_domain: str = "acme.test",
    ) -> None:
        self.trust_oracle = trust_oracle or TrustOracle()
        self.tool_catalog = dict(tool_catalog or DEFAULT_TOOL_CATALOG)
        self.allowlist = tuple(str(item).lower().rstrip(".") for item in allowlist)
        self.trust_domain = trust_domain

    def _tool_meta(self, tool: str) -> ToolMeta:
        if tool in self.tool_catalog:
            return self.tool_catalog[tool]
        for pattern, meta in self.tool_catalog.items():
            if pattern != "*" and fnmatch.fnmatchcase(tool, pattern):
                return meta
        return self.tool_catalog["*"]

    def aggregate(self, request: Mapping[str, Any], *, now_s: float | None = None) -> Attributes:
        now = time.time() if now_s is None else now_s
        agent = _as_map(request.get("agent"))
        context = _as_map(request.get("context"))
        args = _as_map(request.get("args"))
        agent_id = str(agent.get("agent_id", ""))
        for i, outcome in enumerate(_as_str_seq(agent.get("trust_history"))):
            try:
                self.trust_oracle.observe(agent_id, Outcome(outcome), now - 1000.0 + float(i))
            except ValueError:
                self.trust_oracle.observe(agent_id, Outcome.UNKNOWN, now - 1000.0 + float(i))
        trust_domain, path = parse_spiffe_id(str(agent.get("spiffe_id", "")))
        tool = str(request.get("tool", ""))
        meta = self._tool_meta(tool)
        hosts = tuple(sorted(_extract_hosts(args)))
        untrusted = tuple(h for h in hosts if not _allowed_host(h, self.allowlist))
        return Attributes(
            int(request.get("step", 0)),
            agent_id,
            trust_domain,
            path,
            agent.get("svid") == "valid" and trust_domain == self.trust_domain,
            agent.get("attestation") == "valid",
            self.trust_oracle.score(agent_id, now),
            tool,
            meta.risk,
            meta.egress,
            meta.required_scopes,
            _as_str_seq(context.get("declared_scopes")),
            _as_str_seq(agent.get("scopes")),
            args,
            contains_secret_marker(args, _as_str_seq(request.get("secrets"))),
            contains_pii(args),
            hosts,
            untrusted,
            str(context.get("origin", "user")),
            str(context.get("content", "")),
            str(context.get("user_task", "")),
            str(context.get("tool_description", "")),
            str(context.get("raw_generation", "")),
            int(context.get("reasoning_tokens", 0)),
            now,
            {str(k): str(v) for k, v in _as_map(request.get("rebac")).items()},
        )
