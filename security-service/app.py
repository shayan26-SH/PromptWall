import base64
import binascii
import re
import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

try:
    import redis
except ImportError:
    redis = None


app = FastAPI(title="PromptWall Security Service")
REDIS_URL = os.getenv("REDIS_URL", "")
redis_client = redis.Redis.from_url(REDIS_URL) if redis and REDIS_URL else None
memory_windows: dict[str, list[float]] = {}

INJECTION_PATTERNS = (
    r"ignore\s+(?:all|any|previous|above|prior)\s+(?:previous\s+)?(?:instructions|rules)",
    r"disregard\s+(?:all|any|previous|above|prior)\s+(?:previous\s+)?(?:instructions|rules)",
    r"(reveal|show|print|display)\s+(your|the)\s+(system|hidden|developer)\s+(prompt|instructions)",
    r"you\s+are\s+now\s+(dan|an?\s*evil|unrestricted)",
    r"bypass\s+(safety|security|guardrails|filters)",
    r"developer\s+mode",
)

SECRET_PATTERNS = (
    (re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"), "[REDACTED_PHONE]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b"), "[REDACTED_API_KEY]"),
)


class InspectRequest(BaseModel):
    prompt: str = ""
    messages: list[dict[str, Any]] | None = None


class RedactRequest(BaseModel):
    text: str


class RateLimitRequest(BaseModel):
    client: str
    limit: int = 60
    window_seconds: int = 60


def normalized_text(text: str) -> str:
    normalized = text.lower()
    decoded_parts: list[str] = []

    for value in re.findall(r"[A-Za-z0-9+/]{16,}(?:={0,2})", text):
        value = value.rstrip("=")
        try:
            padded = value + "=" * ((-len(value)) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded:
            decoded_parts.append(decoded.lower())

    for value in re.findall(r"(?:[0-9A-Fa-f]{2}[\s,:-]*){8,}", text):
        try:
            stripped = re.sub(r"[\s,:-]", "", value)
            decoded = bytes.fromhex(stripped).decode("utf-8", "ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded:
            decoded_parts.append(decoded.lower())

    if decoded_parts:
        normalized += "\n" + "\n".join(decoded_parts)
    return normalized


def inspect_prompt(prompt: str) -> dict[str, Any]:
    text = normalized_text(prompt)
    reasons = [
        pattern
        for pattern in INJECTION_PATTERNS
        if re.search(pattern, text, flags=re.IGNORECASE)
    ]
    blocked = bool(reasons)
    return {
        "blocked": blocked,
        "reasons": [f"Potential prompt-injection pattern: {pattern}" for pattern in reasons],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/inspect")
def inspect(request: InspectRequest) -> dict[str, Any]:
    parts: list[str] = [request.prompt] if request.prompt else []
    if request.messages:
        parts.extend(
            str(message.get("content", ""))
            for message in request.messages
            if isinstance(message, dict)
        )
    return inspect_prompt("\n".join(part for part in parts if part))


@app.post("/redact")
def redact(request: RedactRequest) -> dict[str, Any]:
    sanitized = request.text
    replacements = 0
    for pattern, replacement in SECRET_PATTERNS:
        sanitized, count = pattern.subn(replacement, sanitized)
        replacements += count
    return {"sanitized": sanitized, "replacements": replacements}


@app.post("/rate-limit/check")
def check_rate_limit(request: RateLimitRequest) -> dict[str, Any]:
    now = time.time()
    if redis_client:
        key = f"promptwall:ratelimit:{request.client}"
        pipeline = redis_client.pipeline()
        pipeline.zremrangebyscore(key, 0, now - request.window_seconds)
        pipeline.zcard(key)
        pipeline.zadd(key, {str(now): now})
        pipeline.expire(key, request.window_seconds)
        _, count, _, _ = pipeline.execute()
        allowed = count < request.limit
        remaining = max(0, request.limit - count - 1)
        return {"allowed": allowed, "remaining": remaining, "backend": "redis"}

    timestamps = memory_windows.setdefault(request.client, [])
    cutoff = now - request.window_seconds
    timestamps[:] = [timestamp for timestamp in timestamps if timestamp > cutoff]
    allowed = len(timestamps) < request.limit
    if allowed:
        timestamps.append(now)
    return {
        "allowed": allowed,
        "remaining": max(0, request.limit - len(timestamps)),
        "backend": "memory",
    }

