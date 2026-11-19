import asyncio
import os
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from playwright.async_api import async_playwright

from guarded_browser_mcp import server


@pytest.fixture
def sessions(tmp_path, monkeypatch):
    def declare(cdp, **policies):
        declared = {}
        for name, (isolated, sites) in policies.items():
            path = tmp_path / f"{name}.yaml"
            path.write_text(sites)
            declared[name] = {"token": name * 32, "cdp": cdp, "policy": str(path), "isolated": isolated, "label": None}
        monkeypatch.setattr(server, "SESSIONS", declared)
    for name, value in (("_browsers", {}), ("_contexts", {}), ("_tabs", {}), ("_locks", {}), ("_playwright", {})):
        monkeypatch.setattr(server, name, value)
    monkeypatch.setattr(server, "_setup", asyncio.Lock())
    monkeypatch.setattr(server, "STATE_DIR", str(tmp_path))
    return declare


ALLOWLIST = "sites:\n  mode: allowlist\n  allowed: [example.com]\n"
DENYLIST = "sites:\n  mode: denylist\n  allowed: ['127.0.0.1']\n  denied: []\n"


def caller(session, agent="agent-1"):
    request = SimpleNamespace(state=SimpleNamespace(session=session), headers={server.AGENT_HEADER: agent})
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


class FakeContext:
    def __init__(self, browser):
        self.browser = browser
        self.pages = []

    async def route(self, pattern, handler):
        pass


class FakeBrowser:
    def __init__(self):
        self.default = FakeContext(self)
        self.created = []

    @property
    def contexts(self):
        return [*self.created, self.default]

    def is_connected(self):
        return True

    async def new_context(self, storage_state=None):
        self.created.append(FakeContext(self))
        return self.created[-1]


def test_the_shared_session_never_takes_an_isolated_context(sessions):
    sessions("cdp", assistant=(False, ALLOWLIST), shop=(True, DENYLIST))
    browser = FakeBrowser()
    server._browsers["cdp"] = browser

    async def scenario():
        shop = await server._context("shop")
        assistant = await server._context("assistant")
        return shop, assistant

    shop, assistant = asyncio.run(scenario())
    assert assistant is browser.default
    assert shop is not assistant


class FakeRoute:
    def __init__(self, url, context=None):
        self.request = SimpleNamespace(resource_type="document", url=url)
        if context is not None:
            self.request.frame = SimpleNamespace(page=SimpleNamespace(context=context))
        self.outcome = None

    async def abort(self, reason):
        self.outcome = "abort"

    async def fallback(self):
        self.outcome = "fallback"


def test_a_session_filter_only_judges_its_own_context(sessions):
    sessions("cdp", assistant=(False, ALLOWLIST), shop=(True, DENYLIST))
    server._contexts.update(assistant=object(), shop=object())
    guard = server._guard("assistant")

    def outcome(url, context=None):
        route = FakeRoute(url, context)
        asyncio.run(guard(route))
        return route.outcome

    assert outcome("https://example.org/", server._contexts["shop"]) == "fallback"
    assert outcome("https://example.org/", server._contexts["assistant"]) == "abort"
    assert outcome("https://example.com/", server._contexts["assistant"]) == "fallback"
    assert outcome("https://example.org/") == "abort"


def test_tools_keep_their_arguments_and_hide_the_context():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    assert set(tools["open_url"].input_schema["properties"]) == {"url"}
    assert set(tools["click"].input_schema["properties"]) == {"ref"}
    assert set(tools["sites"].input_schema.get("properties", {})) == set()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _chromium_executable():
    async def path():
        async with async_playwright() as pw:
            return pw.chromium.executable_path
    return asyncio.run(path())


@pytest.fixture
def chromium():
    executable = _chromium_executable()
    if not os.path.exists(executable):
        pytest.skip("Chromium for Playwright is not installed (playwright install chromium)")
    port = _free_port()
    with tempfile.TemporaryDirectory() as profile:
        process = subprocess.Popen(
            [executable, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
             "--no-first-run", "--no-default-browser-check", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            yield f"http://127.0.0.1:{port}"
        finally:
            process.kill()
            process.wait()


def test_a_hanging_site_fails_before_the_gateway_gives_up_and_the_session_still_answers(sessions, chromium):
    sessions(chromium, assistant=(False, ALLOWLIST), shop=(True, DENYLIST))
    ctx = caller("shop")

    async def scenario():
        async def hang(reader, writer):
            await asyncio.sleep(120)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()

        listener = await asyncio.start_server(hang, "127.0.0.1", 0)
        url = f"http://127.0.0.1:{listener.sockets[0].getsockname()[1]}/slow"
        try:
            started = time.monotonic()
            with pytest.raises(ToolError) as error:
                await server.open_url(url=url, ctx=ctx)
            elapsed = time.monotonic() - started
            left_open = list(server._contexts["shop"].pages)
            rules = await server.sites(ctx=ctx)
            page = await server.read_page(ctx=ctx)
            fresh = server._tab("shop", "agent-1")
            return str(error.value), elapsed, left_open, rules, page, fresh
        finally:
            listener.close()
            if "pw" in server._playwright:
                await server._playwright["pw"].stop()

    message, elapsed, left_open, rules, page, fresh = asyncio.run(scenario())
    assert "navigation_timeout" in message and "/slow" in message
    assert elapsed < server.GATEWAY_TIMEOUT
    assert left_open == []
    assert rules.startswith("Mode: denylist")
    assert page.startswith("Page: ") and "about:blank" in page
    assert fresh is not None and not fresh.is_closed()
