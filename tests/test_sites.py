import pytest

from guarded_browser_mcp.server import site_allowed

DENYLIST = {"mode": "denylist", "allowed": [], "denied": ["*bank*"]}
INTERNAL = [
    "http://portainer/", "http://localhost:3000/", "http://jellyfin:8096/", "http://localhost./",
    "http://[::1]/", "http://[fe80::1]/", "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/", "http://[::]/",
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://172.16.18.3:3100/api",
    "http://10.0.0.1/", "http://192.168.1.80:5555/", "http://100.64.0.1/", "http://0.0.0.0/", "http://224.0.0.1/",
    "http://127.1/", "http://0x7f.1/", "http://2130706433/", "http://0177.0.0.1/", "http://0/", "http://0x7f000001/",
    "http://%31%32%37.0.0.1/", "http://１２７.0.0.1/", "http://08.1/",
    "http://nas.local/", "http://paperclip.internal/", "http://box.lan/", "http://printer.home.arpa/",
    "http://app.localhost/",
]
PUBLIC = ["https://example.com/", "https://obturo.app/", "http://8.8.8.8/", "http://[2001:4860:4860::8888]/",
          "http://134.744/", "https://decaf.cab/"]


@pytest.mark.parametrize("url", INTERNAL)
@pytest.mark.parametrize("mode", ["denylist", "allowlist"])
def test_the_local_network_is_refused_in_both_modes(url, mode):
    ok, why = site_allowed(url, {**DENYLIST, "mode": mode, "allowed": ["example.com"]})
    assert not ok and "local network" in why


@pytest.mark.parametrize("url", PUBLIC)
def test_public_sites_open_in_denylist_mode(url):
    assert site_allowed(url, DENYLIST) == (True, "")


def test_an_internal_host_listed_as_is_in_allowed_opens():
    rules = {**DENYLIST, "allowed": ["preview", "192.168.1.80"]}
    assert site_allowed("http://preview:8080/", rules) == (True, "")
    assert site_allowed("http://192.168.1.80/", rules) == (True, "")
    assert not site_allowed("http://other/", rules)[0]


def test_a_wildcard_in_allowed_does_not_open_the_local_network():
    rules = {"mode": "allowlist", "allowed": ["*"], "denied": []}
    assert site_allowed("https://example.com/", rules) == (True, "")
    assert not site_allowed("http://portainer/", rules)[0]


def test_the_denylist_still_wins_over_allowed():
    rules = {**DENYLIST, "allowed": ["mybank"], "denied": ["*bank*"]}
    assert site_allowed("http://mybank/", rules) == (False, "mybank is on the denied sites list")
