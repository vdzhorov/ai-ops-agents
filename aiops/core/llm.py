"""LLM providers with one shared interface: complete_json(system, user, schema) -> dict.

- OllamaProvider: local model (free, private), good for bulk triage.
- AnthropicProvider: Claude, for the final assessment of the few findings that survive triage.
"""

import json
import threading
from dataclasses import dataclass, field

import anthropic
import httpx
import openai

from aiops.core.masking import Masker


class LLMError(Exception):
    pass


@dataclass
class Usage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, input_tokens=0, output_tokens=0, cache_read_tokens=0):
        with self._lock:
            self.calls += 1
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.cache_read_tokens += cache_read_tokens


class OllamaProvider:
    name = "ollama"

    def __init__(self, host: str, model: str, num_ctx: int = 8192, timeout: float = 300):
        self.host = host.rstrip("/")
        self.model = model
        self.num_ctx = num_ctx
        self.usage = Usage()
        self._http = httpx.Client(timeout=timeout)

    def available(self) -> tuple[bool, str]:
        try:
            tags = self._http.get(f"{self.host}/api/tags", timeout=5).json()
        except httpx.HTTPError as e:
            return False, f"Ollama is not reachable at {self.host} ({e.__class__.__name__}); start it with `ollama serve`"
        names = {m.get("name") for m in tags.get("models", [])}
        if self.model not in names and f"{self.model}:latest" not in names:
            return False, f"model {self.model} is not pulled; run `ollama pull {self.model}`"
        return True, ""

    _structured = True  # flips to False if the runner rejects `format` (e.g. some MLX builds)

    def _body(self, system: str, user: str, schema: dict) -> dict:
        if not self._structured:
            system += ("\n\nRespond with ONLY a JSON object (no prose, no code fences) matching this JSON schema:\n"
                       + json.dumps(schema))
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_ctx": self.num_ctx},
        }
        if self._structured:
            body["format"] = schema
        return body

    @staticmethod
    def _extract_json(text: str) -> dict:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < start:
            raise json.JSONDecodeError("no JSON object in output", text, 0)
        return json.loads(text[start : end + 1])

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        try:
            r = self._http.post(f"{self.host}/api/chat", json=self._body(system, user, schema))
            if r.status_code == 501 and self._structured and "structured output" in r.text:
                self._structured = False
                r = self._http.post(f"{self.host}/api/chat", json=self._body(system, user, schema))
            r.raise_for_status()
            data = r.json()
            self.usage.add(data.get("prompt_eval_count", 0), data.get("eval_count", 0))
            return self._extract_json(data["message"]["content"])
        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as e:
            raise LLMError(f"ollama: {e}") from e


# $ per 1M tokens (input, output) -- for the end-of-run cost estimate only.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-fable-5-1": (10.00, 50.00),
}

# Models that accept the server-side refusal fallback (`fallbacks: "default"`).
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1"}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, effort: str, masker: Masker, max_calls: int | None = None):
        self.model = model
        self.effort = effort
        self.masker = masker
        self.max_calls = max_calls
        self.usage = Usage()
        self._client = None
        self._reserved = 0
        self._lock = threading.Lock()

    def available(self) -> tuple[bool, str]:
        try:
            self._client = anthropic.Anthropic()
        except anthropic.AnthropicError as e:
            return False, f"no Anthropic credentials ({e}); set ANTHROPIC_API_KEY in .env"
        return True, ""

    def try_reserve_call(self) -> bool:
        """Budget guard: returns False once max_calls requests have been reserved."""
        with self._lock:
            if self.max_calls is not None and self._reserved >= self.max_calls:
                return False
            self._reserved += 1
            return True

    def estimated_cost(self) -> float | None:
        price = PRICES.get(self.model)
        if not price:
            return None
        u = self.usage
        return (u.input_tokens * price[0] + u.output_tokens * price[1]) / 1_000_000

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        if self._client is None:
            self.available()
        kwargs = dict(
            model=self.model,
            max_tokens=16000,
            # Static system prompt first, marked for caching; the per-request part goes in `messages`.
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": self.masker.mask(user)}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        try:
            if self.model in FALLBACK_MODELS:
                resp = self._client.beta.messages.create(
                    **kwargs, betas=["server-side-fallback-2026-07-01"], fallbacks="default"
                )
            else:
                resp = self._client.messages.create(**kwargs)
        except anthropic.AuthenticationError as e:
            raise LLMError("anthropic: invalid API key") from e
        except anthropic.RateLimitError as e:
            raise LLMError("anthropic: rate limited (SDK retries exhausted)") from e
        except anthropic.APIStatusError as e:
            raise LLMError(f"anthropic: HTTP {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:
            raise LLMError("anthropic: connection error") from e

        u = resp.usage
        self.usage.add(
            (u.input_tokens or 0) + (u.cache_creation_input_tokens or 0) + (u.cache_read_input_tokens or 0),
            u.output_tokens or 0,
            u.cache_read_input_tokens or 0,
        )
        if resp.stop_reason == "refusal":
            raise LLMError("anthropic: request declined (refusal)")
        if resp.stop_reason == "max_tokens":
            raise LLMError("anthropic: output truncated (max_tokens)")
        text = next((b.text for b in resp.content if b.type == "text"), None)
        if text is None:
            raise LLMError("anthropic: no text block in response")
        try:
            return json.loads(self.masker.unmask(text))
        except json.JSONDecodeError as e:
            raise LLMError(f"anthropic: invalid JSON: {e}") from e


class OpenAIProvider:
    """OpenAI (or any OpenAI-compatible endpoint via OPENAI_BASE_URL) with strict JSON-schema structured outputs."""

    name = "openai"

    def __init__(self, model: str, reasoning_effort: str, masker: Masker, max_calls: int | None = None):
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.masker = masker
        self.max_calls = max_calls
        self.usage = Usage()
        self._client = None
        self._reserved = 0
        self._lock = threading.Lock()

    def available(self) -> tuple[bool, str]:
        try:
            self._client = openai.OpenAI()
        except openai.OpenAIError:
            return False, "no OpenAI credentials; set OPENAI_API_KEY in .env"
        return True, ""

    def try_reserve_call(self) -> bool:
        with self._lock:
            if self.max_calls is not None and self._reserved >= self.max_calls:
                return False
            self._reserved += 1
            return True

    def estimated_cost(self) -> float | None:
        return None  # prices vary per model; token counts are reported instead

    def complete_json(self, system: str, user: str, schema: dict) -> dict:
        if self._client is None:
            self.available()
        kwargs = dict(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": self.masker.mask(user)}],
            response_format={"type": "json_schema", "json_schema": {"name": "result", "schema": schema, "strict": True}},
            max_completion_tokens=16000,
        )
        if self.reasoning_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        try:
            try:
                resp = self._client.chat.completions.create(**kwargs)
            except openai.BadRequestError as e:
                if "reasoning_effort" not in str(e):
                    raise
                kwargs.pop("reasoning_effort")  # non-reasoning model
                self.reasoning_effort = ""
                resp = self._client.chat.completions.create(**kwargs)
        except openai.AuthenticationError as e:
            raise LLMError("openai: invalid API key") from e
        except openai.RateLimitError as e:
            body = e.body if isinstance(e.body, dict) else {}
            body = body.get("error", body) if isinstance(body.get("error"), dict) else body
            kinds = {getattr(e, "code", None), getattr(e, "type", None), body.get("code"), body.get("type")}
            if kinds & {"insufficient_quota", "credit_balance_exhausted"}:
                raise LLMError("openai: няма кредит/квота в OpenAI акаунта (insufficient_quota) — "
                               "провери Billing на platform.openai.com") from e
            raise LLMError(f"openai: rate limit (HTTP 429): {e.message}") from e
        except openai.APIStatusError as e:
            raise LLMError(f"openai: HTTP {e.status_code}: {e.message}") from e
        except openai.APIConnectionError as e:
            raise LLMError("openai: connection error") from e

        if resp.usage:
            cached = getattr(resp.usage.prompt_tokens_details, "cached_tokens", 0) or 0
            self.usage.add(resp.usage.prompt_tokens or 0, resp.usage.completion_tokens or 0, cached)
        choice = resp.choices[0]
        if getattr(choice.message, "refusal", None):
            raise LLMError(f"openai: refusal: {choice.message.refusal}")
        if choice.finish_reason == "length":
            raise LLMError("openai: output truncated (max_completion_tokens)")
        try:
            return json.loads(self.masker.unmask(choice.message.content or ""))
        except json.JSONDecodeError as e:
            raise LLMError(f"openai: invalid JSON: {e}") from e
