from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Protocol

from app.tools.browser import BrowserScraper, BrowserSessionManager


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    requires_approval: bool = False


TOOL_SPECS = {
    "scrape_dynamic_page": ToolSpec(
        "scrape_dynamic_page", "Render a public webpage and extract cleaned text."
    ),
    "browser_start": ToolSpec("browser_start", "Start a persistent isolated browser session."),
    "browser_click": ToolSpec(
        "browser_click", "Click an element in a browser session.", requires_approval=True
    ),
    "browser_type": ToolSpec(
        "browser_type", "Type into an element in a browser session.", requires_approval=True
    ),
    "browser_screenshot": ToolSpec(
        "browser_screenshot", "Capture a PNG screenshot from a browser session."
    ),
    "browser_close": ToolSpec("browser_close", "Close a persistent browser session."),
}


class ToolExecutor(Protocol):
    def specs(self) -> list[ToolSpec]: ...

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, object]: ...


class LocalBrowserToolExecutor:
    def __init__(self, scraper: BrowserScraper, sessions: BrowserSessionManager) -> None:
        self._scraper = scraper
        self._sessions = sessions

    def specs(self) -> list[ToolSpec]:
        return list(TOOL_SPECS.values())

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, object]:
        if name == "scrape_dynamic_page":
            return await self._scraper.scrape(str(arguments["url"]))
        if name == "browser_start":
            return await self._sessions.start(str(arguments["url"]))
        if name == "browser_click":
            return await self._sessions.click(
                str(arguments["session_id"]), str(arguments["selector"])
            )
        if name == "browser_type":
            return await self._sessions.type_text(
                str(arguments["session_id"]),
                str(arguments["selector"]),
                str(arguments["text"]),
                clear=bool(arguments.get("clear", True)),
            )
        if name == "browser_screenshot":
            return await self._sessions.screenshot(
                str(arguments["session_id"]), full_page=bool(arguments.get("full_page", False))
            )
        if name == "browser_close":
            return {
                "session_id": str(arguments["session_id"]),
                "closed": await self._sessions.close(str(arguments["session_id"])),
            }
        raise ValueError(f"Unknown tool: {name}")


class MCPBrowserToolExecutor:
    """Invoke browser tools through one persistent, serialized MCP stdio session."""

    def __init__(self, command: str | None = None, args: list[str] | None = None) -> None:
        self._command = command or sys.executable
        self._args = args or ["-m", "app.mcp_server"]
        self._stack: AsyncExitStack | None = None
        self._session: Any = None
        self._lock = asyncio.Lock()

    def specs(self) -> list[ToolSpec]:
        return list(TOOL_SPECS.values())

    async def _connect(self) -> None:
        if self._session is not None:
            return
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        stack = AsyncExitStack()
        try:
            params = StdioServerParameters(command=self._command, args=self._args)
            reader, writer = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(reader, writer))
            await session.initialize()
        except Exception:
            await stack.aclose()
            raise
        self._stack = stack
        self._session = session

    async def close(self) -> None:
        async with self._lock:
            stack, self._stack = self._stack, None
            self._session = None
            if stack is not None:
                await stack.aclose()

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, object]:
        if name not in TOOL_SPECS:
            raise ValueError(f"Unknown tool: {name}")
        async with self._lock:
            await self._connect()
            try:
                result = await self._session.call_tool(name, arguments=arguments)
            except Exception:
                stack, self._stack = self._stack, None
                self._session = None
                if stack is not None:
                    await stack.aclose()
                raise
        if result.isError:
            detail = " ".join(
                block.text for block in result.content if getattr(block, "type", None) == "text"
            )
            raise RuntimeError(detail or f"MCP tool failed: {name}")
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            return structured
        for block in result.content:
            if getattr(block, "type", None) == "text":
                value = json.loads(block.text)
                if isinstance(value, dict):
                    return value
        raise RuntimeError(f"MCP tool returned no object result: {name}")


class RemoteBrowserToolExecutor:
    """HTTP client for the network-isolated browser worker."""

    def __init__(self, base_url: str, token: str, timeout_seconds: float = 60.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout_seconds

    def specs(self) -> list[ToolSpec]:
        return list(TOOL_SPECS.values())

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, object]:
        if name not in TOOL_SPECS:
            raise ValueError(f"Unknown tool: {name}")
        import httpx

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base_url}/internal/tools/{name}",
                json=arguments,
                headers={"x-browser-worker-token": self._token},
            )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise RuntimeError("Browser worker returned a non-object result")
        return result


class RemoteBrowserScraper:
    def __init__(self, executor: RemoteBrowserToolExecutor) -> None:
        self._executor = executor

    async def scrape(self, url: str) -> dict[str, object]:
        return await self._executor.invoke("scrape_dynamic_page", {"url": url})


class ATRLabToolExecutor:
    """The deliberately small, server-routed tool surface used by the ATR lab."""

    def __init__(
        self,
        fixture_url: str,
        deployment_url: str,
        token: str,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._fixture_url = fixture_url.rstrip("/")
        self._deployment_url = deployment_url.rstrip("/")
        self._token = token
        self._timeout = timeout_seconds

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                "read_untrusted_page",
                "Read one fixed lab fixture. Arguments must exactly match JSON schema: "
                '{"fixture_id":{"enum":["benign","indirect-injection"]}}.',
            ),
            ToolSpec(
                "deploy_release",
                "Apply a release to the lab deployment simulator. Arguments must exactly match "
                'JSON schema: {"environment":{"enum":["staging","production"]},'
                '"version":{"type":"string"},"change":{"type":"string"}}.',
                requires_approval=True,
            ),
        ]

    async def invoke(self, name: str, arguments: dict[str, Any]) -> dict[str, object]:
        import httpx

        headers = {"x-atr-lab-token": self._token}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            if name == "read_untrusted_page":
                fixture_id = str(arguments.get("fixture_id", ""))
                if fixture_id not in {"benign", "indirect-injection"}:
                    raise ValueError("fixture_id must be benign or indirect-injection")
                response = await client.get(
                    f"{self._fixture_url}/fixtures/{fixture_id}", headers=headers
                )
            elif name == "deploy_release":
                environment = str(arguments.get("environment", ""))
                version = str(arguments.get("version", ""))
                change = str(arguments.get("change", ""))
                if environment not in {"staging", "production"}:
                    raise ValueError("environment must be staging or production")
                if not version or len(version) > 128 or not change or len(change) > 1_000:
                    raise ValueError("version and change are required and bounded")
                key = str(arguments.get("_idempotency_key", ""))
                if not key:
                    raise ValueError("server-generated idempotency key is required")
                response = await client.post(
                    f"{self._deployment_url}/deployments",
                    headers={**headers, "idempotency-key": key},
                    json={"environment": environment, "version": version, "change": change},
                )
            else:
                raise ValueError(f"Unknown ATR lab tool: {name}")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("ATR lab tool returned a non-object result")
        payload["response_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return payload
