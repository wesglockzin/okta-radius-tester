import json

import pytest

import registry as reg

KEY = "Typed-Key-123"


def dev(doc=None, **over):
    kw = {"app": "VPN - RADIUS Application", "port_": "1812", "secret_": KEY,
          "hint": "sAMAccountName", "by": "a@x"}
    kw.update(over)
    return reg.put_tenant(doc or reg.empty(), "dev", **kw)[0]


@pytest.mark.parametrize("value,want", [
    ("Agent-A.Example.COM.", "agent-a.example.com"),
    (" 127.0.0.2 ", "127.0.0.2"),
])
def test_host_accepts_and_normalises(value, want):
    assert reg.host(value) == want


@pytest.mark.parametrize("value", ["agent-a", "a..b", "-x.example.com", "x-.example.com", "1.2.3",
                                   "http://x.example.com", "x.example.com:1812", "x y.example.com", "", None,
                                   "a." + "b" * 64 + ".gov"])
def test_host_refuses(value):
    with pytest.raises(reg.Invalid):
        reg.host(value)


@pytest.mark.parametrize("value", ["", " lead", "trail ", "tab\tin", "nön-ascii", "x" * 129])
def test_secret_refuses(value):
    with pytest.raises(reg.Invalid):
        reg.secret(value)


@pytest.mark.parametrize("value", ["0", "65536", "udp", ""])
def test_port_refuses(value):
    with pytest.raises(reg.Invalid):
        reg.port(value)


def test_a_new_tenant_needs_its_secret():
    with pytest.raises(reg.Invalid, match="needs its RADIUS app's shared secret"):
        dev(secret_=None)


def test_secret_never_in_views_or_history():
    d = dev()
    d, _ = reg.add_agent(d, "dev", "agent-a.example.com", "a@x")
    d, _ = reg.put_tenant(d, "dev", app="x", port_="1813", secret_="Other-Key-456", hint="", by="b@x")
    shown = json.dumps([reg.public(d), d["history"]])
    assert KEY not in shown and "Other-Key-456" not in shown
    assert d["tenants"]["dev"]["secret"] == "Other-Key-456"
    assert d["tenants"]["dev"]["secret_changed"]["by"] == "b@x"
    assert "shared secret" in d["history"][0]["what"]


def test_blank_secret_on_edit_keeps_it_and_noop_is_not_a_change():
    d = dev()
    d2, what = reg.put_tenant(d, "dev", app=d["tenants"]["dev"]["app"], port_="1812", secret_=None,
                              hint="sAMAccountName", by="b@x")
    assert what is None and d2 is d
    d3, what = reg.put_tenant(d, "dev", app="renamed", port_="1812", secret_=None, hint="sAMAccountName", by="b@x")
    assert d3["tenants"]["dev"]["secret"] == KEY and what == "DEV: changed RADIUS app"


def test_changes_never_mutate_their_input():
    d = dev()
    before = json.dumps(d, sort_keys=True)
    reg.add_agent(d, "dev", "agent-a.example.com", "a@x")
    reg.put_tenant(d, "dev", app="y", port_="1", secret_="New-1", hint="", by="a@x")
    reg.remove_tenant(d, "dev", "DEV", "a@x")
    assert json.dumps(d, sort_keys=True) == before


def test_agents():
    d = dev()
    d, _ = reg.add_agent(d, "dev", "agent-a.example.com", "a@x")
    with pytest.raises(reg.Invalid, match="already a DEV agent"):
        reg.add_agent(d, "dev", "agent-a.example.com", "a@x")
    with pytest.raises(reg.Invalid, match="has not been added"):
        reg.add_agent(d, "stg", "agent-b.example.com", "a@x")
    with pytest.raises(reg.Invalid, match="not a DEV agent"):
        reg.remove_agent(d, "dev", "agent-z.example.com", "a@x")
    d, _ = reg.remove_agent(d, "dev", "agent-a.example.com", "a@x")
    assert d["tenants"]["dev"]["agents"] == []


def test_lookup_is_per_tenant():
    d = dev()
    d, _ = reg.add_agent(d, "dev", "agent-a.example.com", "a@x")
    assert reg.lookup(d, "dev", "agent-a.example.com")["secret"] == KEY
    assert reg.lookup(d, "stg", "agent-a.example.com") is None
    assert reg.lookup(d, "dev", "agent-b.example.com") is None
    assert reg.lookup(d, "", "agent-a.example.com") is None


def test_remove_tenant_needs_its_name_typed():
    d = dev()
    with pytest.raises(reg.Invalid, match="type DEV to confirm"):
        reg.remove_tenant(d, "dev", "dev", "a@x")
    d, what = reg.remove_tenant(d, "dev", "DEV", "a@x")
    assert d["tenants"] == {} and "removed tenant DEV" in what


def test_unknown_tenant_is_refused_everywhere():
    for fn in (lambda: reg.put_tenant(reg.empty(), "qa", app="x", port_="1", secret_="k", hint="", by="a"),
               lambda: reg.add_agent(dev(), "qa", "agent-a.example.com", "a")):
        with pytest.raises(reg.Invalid, match="unknown tenant"):
            fn()


def test_history_is_capped_newest_first():
    d = dev()
    for i in range(reg.HISTORY_MAX + 5):
        d, _ = reg.put_tenant(d, "dev", app=f"app {i}", port_="1812", secret_=None, hint="", by="a@x")
    assert len(d["history"]) == reg.HISTORY_MAX
    assert d["history"][0]["what"].startswith("DEV: changed RADIUS app")


def test_missing_and_public_order():
    d = reg.put_tenant(dev(), "prod", app="p", port_="1812", secret_="P-1", hint="", by="a")[0]
    assert [t["label"] for t in reg.public(d)] == ["DEV", "PROD"]
    assert reg.missing(d) == [("stg", "STG")]


@pytest.mark.parametrize("bad,needle", [
    ({"tenants": {"qa": {}}}, "tenants.qa: not one of"),
    ({"tenants": {"dev": {"app": "a", "port": 1812, "secret": "", "agents": []}}}, "tenants.dev: the shared secret"),
    ({"tenants": {"dev": {"app": "a", "port": 1812, "secret": "k", "agents": ["Bad Host"]}}}, "tenants.dev:"),
    ({"tenants": {"dev": {"app": "a", "port": 1812, "secret": "k", "agents": ["X.Example.com"]}}}, "normal form"),
    ({"tenants": []}, "must have a 'tenants' object"),
])
def test_check_refuses_a_malformed_document(bad, needle):
    with pytest.raises(reg.Invalid, match=needle.replace("(", r"\(")):
        reg.check(bad)


def test_check_accepts_empty_and_good():
    assert reg.check({}) == reg.empty()
    d = dev()
    assert reg.check(json.loads(json.dumps(d))) == d
