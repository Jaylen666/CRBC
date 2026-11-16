from __future__ import annotations

import json
import time
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class LlmConfig:
    api_key: str
    base_url: str
    model: str
    timeout_s: int = 90
    thinking: str | None = None  # "low" | "medium" | "high" | None


class OpenAICompatibleClient:
    def __init__(self, config: LlmConfig):
        self.config = config
        self.call_count: int = 0
        self.total_input_tokens: int = 0
        self.total_cached_input_tokens: int = 0
        self.total_output_tokens: int = 0
        self.total_tokens: int = 0
        self._error_count: int = 0
        self._total_wall_s: float = 0.0
        self._stats_lock = threading.Lock()

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 1800,
    ) -> str:
        payload: dict = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Pass thinking strength if configured.
        # DeepSeek expects an object: {"type": "enabled"}
        # OpenAI-compatible providers accept a string: "low" | "medium" | "high"
        if self.config.thinking:
            tv = self.config.thinking
            try:
                payload["thinking"] = json.loads(tv)  # parse JSON object
            except (json.JSONDecodeError, TypeError):
                payload["thinking"] = tv  # plain string

        t0 = time.monotonic()
        body = self._post_json_with_retries(self._chat_url(), payload)
        elapsed = time.monotonic() - t0

        parsed = json.loads(body)
        try:
            msg = parsed["choices"][0]["message"]
            content = msg.get("content", "")
            # DeepSeek sometimes puts the answer in reasoning_content
            # and leaves content as an empty string.
            if not content:
                content = msg.get("reasoning_content", "")
        except (KeyError, IndexError, TypeError) as exc:
            self._error_count += 1
            raise RuntimeError(
                f"Unexpected LLM response shape: {body[:1200]}"
            ) from exc

        with self._stats_lock:
            self.call_count += 1
            self._total_wall_s += elapsed
        usage = parsed.get("usage", {})
        with self._stats_lock:
            if usage:
                inp = usage.get("prompt_tokens", 0)
                out = usage.get("completion_tokens", 0)
                details = usage.get("prompt_tokens_details") or {}
                cached = details.get("cached_tokens", 0) or usage.get("prompt_cache_hit_tokens", 0) or 0
                self.total_input_tokens += inp
                self.total_cached_input_tokens += int(cached or 0)
                self.total_output_tokens += out
                self.total_tokens += usage.get("total_tokens", inp + out)
            else:
                prompt_chars = sum(len(m.get("content", "")) for m in messages)
                self.total_input_tokens += prompt_chars // 3
                self.total_output_tokens += len(content) // 3
                self.total_tokens += prompt_chars // 3 + len(content) // 3

        return content

    def stats(self) -> dict:
        return {
            "call_count": self.call_count,
            "error_count": self._error_count,
            "total_input_tokens": self.total_input_tokens,
            "total_cached_input_tokens": self.total_cached_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "total_wall_seconds": round(self._total_wall_s, 1),
        }

    def print_stats(self) -> None:
        s = self.stats()
        print(f"  LLM calls:  {s['call_count']} ({s['error_count']} errors)")
        print(f"  Tokens:     {s['total_tokens']:,} total "
              f"({s['total_input_tokens']:,} in / {s['total_output_tokens']:,} out)")
        print(f"  Wall time:  {s['total_wall_seconds']:.0f}s "
              f"({s['total_wall_seconds'] / 60:.1f} min)")

    def _chat_url(self) -> str:
        base = self.config.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _post_json_with_retries(
        self, url: str, payload: dict, attempts: int = 3
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "rtl-bug-agent/0.1",
        }
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                return self._post_json_requests(url, payload, headers)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                if exc.code < 500 or attempt == attempts:
                    self._error_count += 1
                    raise RuntimeError(
                        f"LLM HTTP {exc.code}: {detail[:1200]}"
                    ) from exc
                last_error = exc
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt == attempts:
                    self._error_count += 1
                    raise RuntimeError(f"LLM request failed: {exc}") from exc
            except RuntimeError as exc:
                last_error = exc
                if attempt == attempts:
                    self._error_count += 1
                    raise
            time.sleep(2 * attempt)
        self._error_count += 1
        raise RuntimeError(f"LLM request failed after retries: {last_error}")

    def _post_json_requests(
        self, url: str, payload: dict, headers: dict[str, str]
    ) -> str:
        try:
            import requests
        except ImportError:
            return self._post_json_urllib(url, payload, headers)
        try:
            resp = requests.post(
                url, headers=headers, json=payload,
                timeout=self.config.timeout_s,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise RuntimeError(f"LLM HTTP {resp.status_code}: {resp.text[:1200]}")
        # Some OpenAI-compatible gateways return HTTP 200 with an error body
        # (e.g. {"error":{"message":"Service load is too high"}}) instead of a
        # 5xx.  Treat a top-level "error" field as a retryable failure so the
        # surrounding retry loop backs off and retries rather than aborting.
        self._raise_if_error_body(resp.text)
        return resp.text

    def _post_json_urllib(
        self, url: str, payload: dict, headers: dict[str, str]
    ) -> str:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:
                text = resp.read().decode("utf-8")
                self._raise_if_error_body(text)
                return text
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError:
            raise

    @staticmethod
    def _raise_if_error_body(text: str) -> None:
        """Raise RuntimeError if a 200 response body carries a top-level error.

        Some OpenAI-compatible gateways signal transient overload with HTTP 200
        and an ``{"error": ...}`` payload.  Raising here routes it through the
        retry loop.  Normal DeepSeek/OpenAI success bodies have no top-level
        ``error`` key, so this is a no-op for them.
        """
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return  # not JSON — let the normal parse path surface it
        if isinstance(parsed, dict) and parsed.get("error"):
            err = parsed["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            raise RuntimeError(f"LLM gateway error (HTTP 200 body): {msg}")
