import httpx
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

ALLOWED_TARGETS = {("localhost", 8000), ("127.0.0.1", 8000)}
NETWORK_TOOLS = {"send_http_request"}


def is_allowed_url(url: str) -> bool:
    """Return True only for plain-HTTP URLs pointing at the local target app."""
    try:
        parsed = httpx.URL(url)
    except Exception:
        return False
    return parsed.scheme == "http" and (parsed.host, parsed.port) in ALLOWED_TARGETS


class SandboxHook(HookProvider):
    """Cancels any network tool call whose URL is outside the allow-list."""

    def __init__(self) -> None:
        self.blocked_calls: list[dict] = []

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self.check_tool_call)

    def check_tool_call(self, event: BeforeToolCallEvent) -> None:
        tool_name = event.tool_use["name"]
        if tool_name not in NETWORK_TOOLS:
            return

        url = event.tool_use["input"].get("url", "")
        if is_allowed_url(url):
            return

        self.blocked_calls.append({"tool": tool_name, "url": url})
        event.cancel_tool = (
            f"BLOCKED by sandbox: '{url}' is outside the allowed targets. "
            "Only http://localhost:8000 and http://127.0.0.1:8000 may be contacted."
        )
