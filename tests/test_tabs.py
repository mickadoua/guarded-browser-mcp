import asyncio

from guarded_browser_mcp import server


class FakePage:
    def __init__(self) -> None:
        self.closed = False

    def is_closed(self) -> bool:
        return self.closed

    async def close(self) -> None:
        self.closed = True


def test_sweep_closes_idle_tabs_and_spares_recent_or_busy_ones(monkeypatch):
    idle, recent, busy = FakePage(), FakePage(), FakePage()
    monkeypatch.setattr(server, "_tabs", {("obt", "a"): idle, ("obt", "b"): recent, ("obt", "c"): busy})
    monkeypatch.setattr(server, "_last_use", {("obt", "a"): 0.0, ("obt", "b"): 950.0, ("obt", "c"): 0.0})

    async def sweep_while_c_runs() -> None:
        lock = asyncio.Lock()
        await lock.acquire()
        monkeypatch.setattr(server, "_locks", {"obt/c": lock})
        await server._sweep_idle_tabs(now=1000.0)

    asyncio.run(sweep_while_c_runs())

    assert (idle.closed, recent.closed, busy.closed) == (True, False, False)
    assert set(server._tabs) == {("obt", "b"), ("obt", "c")}
    assert set(server._last_use) == {("obt", "b"), ("obt", "c")}
