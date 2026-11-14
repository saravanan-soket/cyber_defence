"""Per-provider message-list builders.

Anthropic and OpenAI use different message shapes. The agent loop is
provider-agnostic; it manipulates messages through this builder API.

Anthropic format:
  user message can be either a string or a list of content blocks.
  assistant message has content as a list of {"type": "text"|"tool_use", ...}.
  tool results go in a single user message with a list of
    {"type": "tool_result", "tool_use_id", "content"} blocks.

OpenAI tools format:
  user message has content: str.
  assistant message has content: str (or null) plus tool_calls list.
  each tool result is its own message with role="tool", tool_call_id, content.

Pick one via `build_messages_for(client_route)`.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from cvepatch.runner.llm.base import NormalizedResponse, NormalizedToolCall

# Triple = (the tool call we're answering, response text, whether MCP flagged it as error)
ToolResultTriple = tuple[NormalizedToolCall, str, bool]


class MessageList(Protocol):
    """Provider-agnostic builder for the running message history."""

    def initial(self, human_text: str) -> None: ...
    def append_assistant(self, resp: NormalizedResponse) -> None: ...
    def append_tool_results(self, results: list[ToolResultTriple]) -> None: ...
    def append_user(self, text: str) -> None: ...
    def get(self) -> list[dict[str, Any]]: ...


class AnthropicMessages:
    """Anthropic-shape message list."""

    def __init__(self) -> None:
        self._msgs: list[dict[str, Any]] = []

    def initial(self, human_text: str) -> None:
        self._msgs.append({"role": "user", "content": human_text})

    def append_assistant(self, resp: NormalizedResponse) -> None:
        # When the Anthropic client captured raw content blocks (always the
        # case for AnthropicNative), replay them verbatim in original order.
        # Required for extended-thinking signature validation: the next
        # multi-turn request is rejected if any thinking block is dropped,
        # mutated, or moved relative to surrounding tool_use blocks.
        if resp.content_blocks:
            blocks = [dict(b) for b in resp.content_blocks]
            self._msgs.append({"role": "assistant", "content": blocks})
            return

        # Fallback for clients that don't populate content_blocks (mock,
        # or hand-built test responses): rebuild from text + tool_calls.
        blocks: list[dict[str, Any]] = []
        if resp.text:
            blocks.append({"type": "text", "text": resp.text})
        for tc in resp.tool_calls:
            blocks.append(
                {
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.name,
                    "input": tc.arguments,
                }
            )
        # An empty assistant turn shouldn't happen in practice but guard anyway.
        if not blocks:
            blocks = [{"type": "text", "text": ""}]
        self._msgs.append({"role": "assistant", "content": blocks})

    def append_tool_results(self, results: list[ToolResultTriple]) -> None:
        blocks: list[dict[str, Any]] = []
        for tc, content, is_error in results:
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": content,
            }
            if is_error:
                block["is_error"] = True
            blocks.append(block)
        if blocks:
            self._msgs.append({"role": "user", "content": blocks})

    def append_user(self, text: str) -> None:
        self._msgs.append({"role": "user", "content": text})

    def get(self) -> list[dict[str, Any]]:
        return list(self._msgs)


TRIM_MARK = "\n[... older tool output trimmed to save context; re-run the command if needed]"


class OpenAIMessages:
    """OpenAI tools-format message list (shape used by LiteLLM).

    `preserve_reasoning_content`: when True, include `reasoning_content`
    on assistant messages whenever the response carried one. Required
    for Moonshot's API (without it the model loses access to its prior
    thinking trace turn-over-turn; LiteLLM warns and injects a
    placeholder); other providers reject unknown fields so the default
    is False. Set automatically by `build_messages_for(...)` based on
    the model id.
    `preserve_reasoning_items`: when True, replay Responses API reasoning
    items from LiteLLM's raw response. This is the stateless encrypted-state
    mechanism documented by OpenAI.
    """

    def __init__(
        self,
        *,
        preserve_reasoning_content: bool = False,
        preserve_reasoning_items: bool = False,
    ) -> None:
        self._msgs: list[dict[str, Any]] = []
        self._preserve_reasoning = preserve_reasoning_content
        self._preserve_reasoning_items = preserve_reasoning_items

    def initial(self, human_text: str) -> None:
        self._msgs.append({"role": "user", "content": human_text})

    def append_assistant(self, resp: NormalizedResponse) -> None:
        msg: dict[str, Any] = {
            "role": "assistant",
            "content": resp.text if resp.text else None,
        }
        if resp.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                    },
                }
                for tc in resp.tool_calls
            ]
        if self._preserve_reasoning and resp.reasoning_content:
            msg["reasoning_content"] = resp.reasoning_content
        if self._preserve_reasoning_items:
            choices = resp.raw.get("choices") or []
            raw_message = choices[0].get("message", {}) if choices else {}
            reasoning_items = raw_message.get("reasoning_items") or []
            if reasoning_items:
                msg["reasoning_items"] = [dict(item) for item in reasoning_items]
        self._msgs.append(msg)

    def append_tool_results(self, results: list[ToolResultTriple]) -> None:
        for tc, content, is_error in results:
            entry: dict[str, Any] = {
                "role": "tool",
                "tool_call_id": tc.id,
                "content": content,
            }
            # OpenAI doesn't have an is_error field; embed it in the content
            # so the model can react. Some gateways do honor a `name` field.
            if is_error:
                entry["content"] = f"[tool error]\n{content}"
            self._msgs.append(entry)

    def append_user(self, text: str) -> None:
        self._msgs.append({"role": "user", "content": text})

    def trim_old_tool_results(self, keep_last: int = 6, keep_chars: int = 400) -> int:
        """Shorten every tool result except the last `keep_last` to a stub, to keep
        a long episode under the context limit. The model's own messages are never
        touched. Returns how many were trimmed (already-trimmed ones are skipped)."""
        tools = [m for m in self._msgs if m.get("role") == "tool"]
        n = 0
        for m in tools[:-keep_last] if keep_last else tools:
            c = m.get("content")
            if isinstance(c, str) and len(c) > keep_chars and TRIM_MARK not in c:
                m["content"] = c[:keep_chars] + TRIM_MARK
                n += 1
        return n

    def get(self) -> list[dict[str, Any]]:
        return list(self._msgs)


def build_messages_for(
    client_route: str, *, model_id: str = "",
) -> MessageList:
    """Pick the right builder based on the LLM client's route tag.

    `model_id` is used to opt into provider-specific replay quirks that
    can't be inferred from the route alone:
      - Moonshot's API requires `reasoning_content` to be replayed
        verbatim in the assistant message history (otherwise the
        model loses its prior thinking trace and LiteLLM injects a
        placeholder, warning every turn). Other providers reject the
        unknown field, so we gate the inclusion on model_id starting
        with `moonshot/` (and self-hosted GLM, whose chat template accepts it).
    """
    if client_route == "anthropic_native":
        return AnthropicMessages()
    # mock and litellm/litellm_gateway all use the OpenAI shape — that's the
    # format LiteLLM normalizes to, and what MockClient pretends to be.
    # Self-hosted GLM (SGLang behind the LiteLLM proxy, routed as openai/ or
    # litellm_proxy/) keeps its interleaved thinking when prior
    # `reasoning_content` is replayed; cvepatch traces are training data, so
    # the chain must stay coherent. z.ai's hosted API is left alone.
    preserve_reasoning = model_id.lower().startswith(
        ("moonshot/", "openai/glm", "litellm_proxy/glm"))
    preserve_reasoning_items = model_id.startswith("openai/")
    return OpenAIMessages(
        preserve_reasoning_content=preserve_reasoning,
        preserve_reasoning_items=preserve_reasoning_items,
    )
