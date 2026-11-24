"""
auditor/runner.py
=================
Synchronous HTTP client for local LLM endpoints.

Supports:
  - OpenAI-compatible  /v1/chat/completions  (MODE_OPENAI)
  - Ollama native      /api/chat             (MODE_OLLAMA)

All requests force stream=False for deterministic latency measurement.

Every returned result records:
  - injected_system_prompt  (str | None)  — the exact system message that was sent
  - is_control              (bool)        — benign control vector flag (excluded from attack score)
  - negative_indicators     (list[str])   — refusal phrases, log-only (never affect PASS/FAIL)
"""
from __future__ import annotations

import time
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Endpoint mode constants
# ---------------------------------------------------------------------------
MODE_OPENAI: str = "openai"   # /v1/chat/completions (OpenAI-compat, Ollama /v1 shim)
MODE_OLLAMA: str = "ollama"   # /api/chat (Ollama native JSON protocol)


# ---------------------------------------------------------------------------
# Internal payload builders
# ---------------------------------------------------------------------------

def _build_messages(
    prompt: str,
    system_prompt: str | None,
    context_messages: list[dict],
) -> list[dict]:
    """Assemble the ordered messages list: system → context history → user prompt."""
    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.extend(context_messages)
    messages.append({"role": "user", "content": prompt})
    return messages


def _build_openai_payload(
    model: str,
    prompt: str,
    system_prompt: str | None,
    context_messages: list[dict],
) -> dict[str, Any]:
    return {
        "model": model,
        "messages": _build_messages(prompt, system_prompt, context_messages),
        "stream": False,
    }


def _build_ollama_payload(
    model: str,
    prompt: str,
    system_prompt: str | None,
    context_messages: list[dict],
) -> dict[str, Any]:
    return {
        "model": model,
        "messages": _build_messages(prompt, system_prompt, context_messages),
        "stream": False,
    }


# ---------------------------------------------------------------------------
# Response content extractors
# ---------------------------------------------------------------------------

def _extract_text_openai(response_json: dict) -> str:
    """Extract assistant reply from /v1/chat/completions response body."""
    try:
        return response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_text_ollama(response_json: dict) -> str:
    """Extract assistant reply from Ollama native /api/chat response body."""
    try:
        return response_json["message"]["content"]
    except (KeyError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# Endpoint URL resolver
# ---------------------------------------------------------------------------

def _resolve_endpoint(base_url: str, mode: str) -> str:
    """
    Build the full request URL from the user-supplied base URL and mode.

    OpenAI mode: <base_url>/chat/completions
      e.g.  http://localhost:11434/v1  →  http://localhost:11434/v1/chat/completions

    Ollama native mode: strip trailing /v1 if present, then append /api/chat
      e.g.  http://localhost:11434      →  http://localhost:11434/api/chat
            http://localhost:11434/v1   →  http://localhost:11434/api/chat
    """
    clean = base_url.rstrip("/")
    if mode == MODE_OPENAI:
        return f"{clean}/chat/completions"
    # Ollama native — strip /v1 shim suffix if the user copied an OpenAI-compat URL
    if clean.endswith("/v1"):
        clean = clean[:-3]
    return f"{clean}/api/chat"


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

def health_check(base_url: str, timeout: float = 3.0) -> tuple[bool, str]:
    """
    Ping the configured endpoint to verify reachability before running the suite.

    Tries GET /v1/models first (OpenAI-compat model list), then GET / as a fallback
    so it works with both Ollama and custom wrappers.

    Returns:
        (ok: bool, message: str)
    """
    clean = base_url.rstrip("/")
    probe_paths = ["/v1/models", "/api/tags", "/"]

    with httpx.Client(timeout=timeout) as client:
        for path in probe_paths:
            url = clean + path
            try:
                resp = client.get(url)
                if resp.status_code < 500:
                    return (
                        True,
                        f"Endpoint reachable — {url} responded HTTP {resp.status_code}",
                    )
            except httpx.TransportError:
                continue
            except httpx.TimeoutException:
                continue

    return (
        False,
        f"Endpoint unreachable at {base_url}. Ensure your model server is running.",
    )


# ---------------------------------------------------------------------------
# Result factories
# ---------------------------------------------------------------------------

def _suite_fields(benchmark: dict[str, Any]) -> dict[str, Any]:
    """Suite-level metadata carried through runner → scorer → dashboard → exports."""
    return {
        "name": benchmark.get("name", ""),
        "attack_vector": benchmark.get("attack_vector", "—"),
        "expected_behavior": benchmark.get("expected_behavior", ""),
        "tags": benchmark.get("tags", []) or [],
        "severity": benchmark.get("severity", "MEDIUM"),
        "fail_indicators": benchmark.get("fail_indicators", []) or [],
        "negative_indicators": benchmark.get("negative_indicators", []) or [],
        "is_control": bool(benchmark.get("is_control", False)),
    }


def _error_result(
    benchmark: dict[str, Any],
    status_code: int,
    latency_ms: float,
    error_message: str,
    system_prompt_used: str | None,
) -> dict[str, Any]:
    """Return a standardised ERROR result dict for a failed request."""
    return {
        "benchmark_id": benchmark["id"],
        "category": benchmark["category"],
        "prompt": benchmark["prompt"],
        "raw_response": "",
        "status_code": status_code,
        "latency_ms": latency_ms,
        "status": "ERROR",
        "error_message": error_message,
        "injected_system_prompt": system_prompt_used,
        **_suite_fields(benchmark),
        "passed": None,
        "score": None,
        "matched_indicators": [],
        "negative_indicators_matched": [],
    }


# ---------------------------------------------------------------------------
# Main benchmark executor
# ---------------------------------------------------------------------------

def run_benchmark(
    benchmark: dict[str, Any],
    base_url: str,
    model: str,
    mode: str,
    connect_timeout: float,
    read_timeout: float,
    system_prompt_override: str | None = None,
) -> dict[str, Any]:
    """
    Execute a single benchmark prompt against the configured LLM endpoint.

    Priority for system_prompt:
        sidebar override / injected canary (passed as `system_prompt_override`)
            > benchmark-level system_prompt > None (no system message)

    The app layer resolves the canary/target prompt and passes it in as the
    override, so this function stays deterministic and records exactly what
    was sent in `injected_system_prompt`.

    Returns a raw result dict. Scoring fields (passed, score, matched_indicators,
    negative_indicators_matched) are populated by scorer.score_result().
    """
    bench_id: str = benchmark["id"]
    category: str = benchmark["category"]
    prompt: str = benchmark["prompt"]

    effective_system_prompt: str | None = (
        system_prompt_override
        if system_prompt_override
        else benchmark.get("system_prompt")
    )
    context_messages: list[dict] = benchmark.get("context_messages") or []

    # Resolve endpoint URL and build payload
    endpoint = _resolve_endpoint(base_url, mode)
    if mode == MODE_OPENAI:
        payload = _build_openai_payload(model, prompt, effective_system_prompt, context_messages)
    else:
        payload = _build_ollama_payload(model, prompt, effective_system_prompt, context_messages)

    # Execute
    t_start = time.monotonic()
    try:
        with httpx.Client(
            timeout=httpx.Timeout(
                connect=connect_timeout,
                read=read_timeout,
                write=10.0,
                pool=5.0,
            )
        ) as client:
            response = client.post(endpoint, json=payload)

        latency_ms = round((time.monotonic() - t_start) * 1000, 1)
        status_code = response.status_code
        raw_text = response.text.strip()

        # Non-200 → ERROR
        if status_code != 200:
            snippet = raw_text[:300] if raw_text else "(empty body)"
            return _error_result(
                benchmark, status_code, latency_ms,
                f"HTTP {status_code}: {snippet}",
                effective_system_prompt,
            )

        # Parse JSON body
        try:
            response_json = response.json()
        except Exception:
            snippet = raw_text[:300] if raw_text else "(empty)"
            return _error_result(
                benchmark, status_code, latency_ms,
                f"Malformed/non-JSON response body: {snippet}",
                effective_system_prompt,
            )

        # Extract assistant text
        extracted = (
            _extract_text_openai(response_json)
            if mode == MODE_OPENAI
            else _extract_text_ollama(response_json)
        )

        if not extracted:
            return _error_result(
                benchmark, status_code, latency_ms,
                "Response parsed successfully but assistant content was empty.",
                effective_system_prompt,
            )

        return {
            "benchmark_id": bench_id,
            "category": category,
            "prompt": prompt,
            "raw_response": extracted,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "status": "OK",
            "error_message": None,
            "injected_system_prompt": effective_system_prompt,
            **_suite_fields(benchmark),
            # Populated by scorer.py
            "passed": None,
            "score": None,
            "matched_indicators": [],
            "negative_indicators_matched": [],
        }

    except httpx.TimeoutException:
        latency_ms = round((time.monotonic() - t_start) * 1000, 1)
        return _error_result(
            benchmark, 0, latency_ms,
            f"Request timed out after {read_timeout}s read / {connect_timeout}s connect.",
            effective_system_prompt,
        )
    except httpx.TransportError as exc:
        latency_ms = round((time.monotonic() - t_start) * 1000, 1)
        return _error_result(
            benchmark, 0, latency_ms, f"Transport error: {exc}", effective_system_prompt
        )
