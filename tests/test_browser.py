import asyncio
from types import SimpleNamespace

import pytest

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
