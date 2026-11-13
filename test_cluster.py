import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).parent
BASE = "https://radius-tester.example.com"
REG = "okta-radius-tester-registry"
DEV_SECRET = "[REDACTED]"
GOOD = {"APP_BASE_URL": BASE, "FLASK_SECRET_KEY": "k" * 64,
        "OIDC_ISSUER": "https://host.example.com", "OIDC_CLIENT_ID": "0oaGATE",
        "OIDC_CLIENT_SECRET": "gate-secret", "FLEET_STATE_SECRET": REG,
        "KUBERNETES_SERVICE_HOST": "127.0.0.1"}
SEED = {"tenants": {"dev": {"app": "VPN - RADIUS Application", "port": 1812,
                            "secret": DEV_SECRET, "hint": "sAMAccountName",
                            "agents": ["agent-a.example.com", "agent-b.example.com"]}},
        "history": []}

PROBE = r"""
import json, os, pathlib, tempfile
import test_state_store as K
mode, name = os.environ.get("FAKE_MODE", "ok"), os.environ.get("FLEET_STATE_SECRET", "unset")
objs = {"ok": lambda: K.FakeKubeAPI.secret_obj(name, json.loads(os.environ["SEED"])),
        "badjson": lambda: K.FakeKubeAPI.secret_obj(name, raw=b"{"),
        "badtenant": lambda: K.FakeKubeAPI.secret_obj(name, {"tenants": {"qa": {}}}),
        "403": lambda: K.FakeKubeAPI.secret_obj(name, {})}
fake = K.FakeKubeAPI({name: objs[mode]()} if mode in objs else {}, forbidden={name} if mode == "403" else ())
fake.point(pathlib.Path(tempfile.mkdtemp()))
import _bootstrap
flask_app = _bootstrap.cluster_app()
import app as A
c = flask_app.test_client()
out = {"cookie": flask_app.config["SESSION_COOKIE_NAME"], "secure": flask_app.config["SESSION_COOKIE_SECURE"]}
for p in ("/health", "/", "/settings"):
    r = c.get(p)
    out[p] = [r.status_code, r.headers.get("Location", "")]
out["anon POST /send"] = c.post("/send", data={"username": "u"}).status_code
with c.session_transaction() as s:
    s["user"] = {"email": "x@y"}
r = c.get("/")
page = r.get_data(as_text=True)
out["signed_in /"] = [r.status_code, 'value="dev|agent-a.example.com"' in page,
                      "DEV — VPN - RADIUS Application" in page]
r = c.get("/settings")
sp = r.get_data(as_text=True)
out["settings"] = [r.status_code, os.environ["DEV_SECRET"] in sp + page, name in sp]
out["no-csrf POST"] = c.post("/settings/agent", data={"tenant": "dev", "agent": "agent-c.example.com", "action": "add"}).status_code
out["PUTs after no-csrf"] = [m for m, *_ in fake.calls].count("PUT")
with c.session_transaction() as s:
    tok = s["csrf"]
r = c.post("/settings/agent", data={"csrf": tok, "tenant": "dev", "agent": "agent-c.example.com", "action": "add"})
out["csrf POST"] = [r.status_code, fake.doc(name)["tenants"]["dev"]["agents"][-1], fake.doc(name)["history"][0]["by"]]
out["safe_next"] = [A._safe_next(n) for n in ("/x?y=1", "//evil", "https://evil.example.com", "/\\evil", None)]
print("PROBE" + json.dumps(out))
"""


def run(code, env_over, drop=()):
    env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"],
           "SEED": json.dumps(SEED), "DEV_SECRET": DEV_SECRET}
    env.update(env_over)
    for k in drop:
        env.pop(k, None)
    return subprocess.run([sys.executable, "-c", code], cwd=HERE, env=env,
                          capture_output=True, text=True, timeout=60)


def parsed(r, tag):
    line = [l for l in r.stdout.splitlines() if l.startswith(tag)]
    return json.loads(line[0][len(tag):]) if line else None


def refused(r, needle):
    return r.returncode != 0 and needle in (r.stderr + r.stdout)


def test_cluster_starts_gated_with_its_registry():
    r = run(PROBE, GOOD)
    o = parsed(r, "PROBE")
    assert o, r.stderr[-800:]
    assert o["cookie"] == "rt_session" and o["secure"] is True
    assert o["/health"][0] == 200
    assert o["/"][0] == 302 and "/login" in o["/"][1]
    assert o["/settings"][0] == 302 and "/login" in o["/settings"][1]
    assert o["anon POST /send"] == 302
    assert o["signed_in /"] == [200, True, True]
    assert o["settings"] == [200, False, True]
    assert o["no-csrf POST"] == 400 and o["PUTs after no-csrf"] == 0
    assert o["csrf POST"] == [302, "agent-c.example.com", "x@y"]
    assert o["safe_next"] == ["/x?y=1", "/", "/", "/", "/"]
    assert "DEV: VPN - RADIUS Application" in r.stdout


@pytest.mark.parametrize("over,drop,needle", [
    ({"APP_BASE_URL": "http://x.example.com"}, (), "APP_BASE_URL must be"),
    ({}, ("OIDC_ISSUER",), "missing ['OIDC_ISSUER']"),
    ({}, ("OIDC_CLIENT_ID",), "missing ['OIDC_CLIENT_ID']"),
    ({}, ("OIDC_CLIENT_SECRET",), "missing ['OIDC_CLIENT_SECRET']"),
    ({}, ("FLASK_SECRET_KEY",), "missing ['FLASK_SECRET_KEY']"),
    ({"OIDC_ISSUER": "https://other-org.example.com"}, (), "is not PROD Okta"),
    ({"RT_TENANT": "dev"}, (), "still has v0.1 keys ['RT_TENANT']"),
    ({"RADIUS_SHARED_SECRET": "old"}, (), "still has v0.1 keys ['RADIUS_SHARED_SECRET']"),
    ({}, ("FLEET_STATE_SECRET",), "no FLEET_STATE_SECRET — set stateSecret in the values file (the chart"),
    ({"FAKE_MODE": "absent"}, (), "HTTP 404 — it does not exist"),
    ({"FAKE_MODE": "403"}, (), "HTTP 403 — this pod's ServiceAccount may not do that"),
    ({"FAKE_MODE": "badjson"}, (), "is not valid JSON"),
    ({"FAKE_MODE": "badtenant"}, (), "tenants.qa: not one of"),
])
def test_cluster_app_refuses(over, drop, needle):
    r = run(PROBE, {**GOOD, **over}, drop)
    assert refused(r, needle), (r.returncode, r.stderr[-500:])
    assert "PROBE" not in r.stdout


@pytest.mark.parametrize("drop,needle", [
    (("OIDC_CLIENT_SECRET",), "refusing to start open"),
    (("FLEET_STATE_SECRET",), "in a cluster with no FLEET_STATE_SECRET"),
])
def test_app_import_refuses_in_cluster(drop, needle):
    r = run("import app", GOOD, drop)
    assert refused(r, needle), (r.returncode, r.stderr[-500:])


def test_app_py_is_not_runnable():
    r = subprocess.run([sys.executable, "app.py"], cwd=HERE, capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"], "HOME": os.environ["HOME"]}, timeout=60)
    assert refused(r, "not runnable")


FLOW = r"""
import json, os
import registry as reg, state_store as ss, test_radius_client as T
script = json.loads(os.environ["SCRIPT"])
srv = T.FakeServer(server_secret=os.environ.get("AGENT_KEY", "flow-key").encode(),
                   script=[(c, bytes.fromhex(a)) for c, a in script])
import app as A
A.ROUND_TIMEOUT_S = 3
doc = reg.put_tenant(reg.empty(), "dev", app="fake app", port_=str(srv.port), secret_="flow-key",
                     hint="sAMAccountName", by="t")[0]
A.STORE = ss.MemoryStore(reg.add_agent(doc, "dev", "127.0.0.1", "t")[0])
c = A.app.test_client()
with c.session_transaction() as s:
    s["user"] = {"email": "x@y"}
    s["csrf"] = "tok"
def post(path, **d):
    r = c.post(path, data={"csrf": "tok", **d})
    return [r.status_code, r.get_data(as_text=True)]
out = {"send": post("/send", username="probe_user", password="Sup3r-Secret-PW", agent="dev|127.0.0.1")}
out["seen1"] = {"password": srv.seen.get("password", b"").decode(errors="replace"),
                "tunnel_group": srv.seen.get("tunnel_group")}
with c.session_transaction() as s:
    out["session1"] = json.dumps(dict(s))
if os.environ.get("REMOVE_AGENT_FIRST"):            # an admin removes the agent mid-challenge
    d, v = A.STORE.load()
    A.STORE.save(reg.remove_agent(d, "dev", "127.0.0.1", "admin")[0], v)
if os.environ.get("RESPOND"):
    out["respond"] = post("/respond", response=os.environ["RESPOND"])
    srv.t.join(timeout=5)
    out["seen2"] = {"password": srv.seen.get("password", b"").decode(), "state": srv.seen.get("state", b"").decode()}
bads = {"unlisted agent": {"agent": "dev|agent-z.example.com"}, "tenant not added": {"agent": "stg|127.0.0.1"},
        "no tenant": {"agent": "127.0.0.1"}, "tunnel_group": {"tunnel_group": "x" * 65},
        "client_ip": {"client_ip": "not-an-ip"}}
for name, bad in bads.items():
    out["bad " + name] = post("/send", **{"username": "u", "password": "p", "agent": "dev|127.0.0.1", **bad})[0]
out["no csrf"] = c.post("/send", data={"username": "u", "password": "p", "agent": "dev|127.0.0.1"}).status_code
print("FLOW" + json.dumps(out))
"""
LOCAL = {"FLASK_SECRET_KEY": "k" * 64}


def test_accept_end_to_end_and_secrets_never_kept():
    r = run(FLOW, {**LOCAL, "SCRIPT": json.dumps([[2, ""]])})
    o = parsed(r, "FLOW")
    assert o, r.stderr[-800:]
    code, page = o["send"]
    assert code == 200 and "<b>ACCEPT</b>" in page and "verified with the shared secret" in page
    assert "Tenant <b>DEV</b>" in page
    assert o["seen1"] == {"password": "Sup3r-Secret-PW", "tunnel_group": "RADIUS-TEST"}
    assert "Sup3r-Secret-PW" not in page and "Sup3r-Secret-PW" not in o["session1"]
    assert "flow-key" not in page and "flow-key" not in o["session1"]
    assert {k: v for k, v in o.items() if k.startswith("bad ")} == {
        "bad unlisted agent": 400, "bad tenant not added": 400, "bad no tenant": 400,
        "bad tunnel_group": 400, "bad client_ip": 400}
    assert o["no csrf"] == 400


def test_challenge_then_accept_carries_state():
    challenge = (bytes([24, 2 + 6]) + b"st-777" + bytes([18, 2 + 10]) + b"1 - Push?\n").hex()
    r = run(FLOW, {**LOCAL, "SCRIPT": json.dumps([[11, challenge], [2, ""]]), "RESPOND": "1"})
    o = parsed(r, "FLOW")
    assert o, r.stderr[-800:]
    assert o["send"][0] == 200 and "<b>CHALLENGE</b>" in o["send"][1] and "1 - Push?" in o["send"][1]
    assert o["respond"][0] == 200 and "<b>ACCEPT</b>" in o["respond"][1]
    assert o["seen2"] == {"password": "1", "state": "st-777"}


def test_agent_removed_mid_challenge_is_not_contacted_again():
    challenge = (bytes([24, 2 + 6]) + b"st-777").hex()
    r = run(FLOW, {**LOCAL, "SCRIPT": json.dumps([[11, challenge], [2, ""]]), "RESPOND": "1",
                   "REMOVE_AGENT_FIRST": "1"})
    o = parsed(r, "FLOW")
    assert o, r.stderr[-800:]
    assert o["respond"][0] == 409 and "is no longer a DEV agent" in o["respond"][1]
    assert o["seen2"]["state"] == ""


def test_key_mismatch_is_shown_as_mismatch_not_reject():
    r = run(FLOW, {**LOCAL, "SCRIPT": json.dumps([[3, ""]]), "AGENT_KEY": "the-other-key"})
    o = parsed(r, "FLOW")
    assert o, r.stderr[-800:]
    assert "<b>KEY MISMATCH</b>" in o["send"][1] and "<b>REJECT</b>" not in o["send"][1]


SETTINGS = r"""
import json
import app as A, registry as reg, state_store as ss
A.STORE = ss.MemoryStore(reg.empty())
c = A.app.test_client()
with c.session_transaction() as s:
    s["user"] = {"email": "admin@x"}
    s["csrf"] = "tok"
def post(path, **d):
    return c.post(path, data={"csrf": "tok", **d}).status_code
doc = lambda: A.STORE.load()[0]
out = {"empty test page": "No RADIUS tenants yet" in c.get("/").get_data(as_text=True)}
out["add dev without secret"] = post("/settings/tenant", tenant="dev", app="VPN", port="1812", secret="", hint="")
out["add dev"] = post("/settings/tenant", tenant="dev", app="VPN - RADIUS Application (0oa1)", port="1812",
                      secret="Dev-Key-1", hint="sAMAccountName")
out["add agent"] = post("/settings/agent", tenant="dev", agent="Agent-A.Example.com", action="add")
out["dup agent"] = post("/settings/agent", tenant="dev", agent="agent-a.example.com", action="add")
out["bad agent"] = post("/settings/agent", tenant="dev", agent="not a host", action="add")
out["bad action"] = post("/settings/agent", tenant="dev", agent="agent-y.example.com", action="nuke")
out["add stg"] = post("/settings/tenant", tenant="stg", app="STG app", port="1812", secret="Stg-Key-2", hint="")
out["stg agent"] = post("/settings/agent", tenant="stg", agent="agent-s.example.com", action="add")
out["edit dev, secret blank"] = post("/settings/tenant", tenant="dev", app="VPN - RADIUS Application (0oa1)",
                                     port="1645", secret="", hint="sAMAccountName")
out["dev after edit"] = [doc()["tenants"]["dev"]["port"], doc()["tenants"]["dev"]["secret"]]
out["edit dev secret"] = post("/settings/tenant", tenant="dev", app="VPN - RADIUS Application (0oa1)",
                              port="1645", secret="Dev-Key-9", hint="sAMAccountName")
out["dev secret now"] = doc()["tenants"]["dev"]["secret"]
page, test_page = c.get("/settings").get_data(as_text=True), c.get("/").get_data(as_text=True)
out["secrets shown"] = [k for k in ("Dev-Key-1", "Dev-Key-9", "Stg-Key-2") if k in page + test_page]
out["settings shows"] = ["agent-a.example.com" in page, "by admin@x" in page, "Add a tenant" in page,
                         "STG app" in page]
out["test page options"] = ['value="dev|agent-a.example.com"' in test_page, 'value="stg|agent-s.example.com"' in test_page]
out["remove stg unconfirmed"] = post("/settings/tenant/remove", tenant="stg", confirm="stg")
out["remove stg"] = post("/settings/tenant/remove", tenant="stg", confirm="STG")
out["tenants left"] = sorted(doc()["tenants"])
orig = A.load_registry
def racing():                        # someone else writes between our read and our write
    got = orig()
    A.STORE.bump()
    return got
A.load_registry = racing
out["conflict"] = post("/settings/agent", tenant="dev", agent="agent-x.example.com", action="add")
A.load_registry = orig
out["after conflict"] = doc()["tenants"]["dev"]["agents"]
out["no csrf"] = c.post("/settings/tenant/remove", data={"tenant": "dev", "confirm": "DEV"}).status_code
out["dev survives"] = "dev" in doc()["tenants"]
out["history"] = [(h["by"], h["what"]) for h in doc()["history"]]
print("SET" + json.dumps(out))
"""


def test_tenants_and_agents_end_to_end():
    r = run(SETTINGS, LOCAL)
    o = parsed(r, "SET")
    assert o, r.stderr[-800:]
    assert o["empty test page"] is True
    assert o["add dev without secret"] == 400 and o["add dev"] == 302
    assert o["add agent"] == 302 and o["dup agent"] == 400 and o["bad agent"] == 400 and o["bad action"] == 400
    assert o["add stg"] == 302 and o["stg agent"] == 302
    assert o["dev after edit"] == [1645, "Dev-Key-1"]
    assert o["edit dev secret"] == 302 and o["dev secret now"] == "Dev-Key-9"
    assert o["secrets shown"] == []
    assert o["settings shows"] == [True, True, True, True]
    assert o["test page options"] == [True, True]
    assert o["remove stg unconfirmed"] == 400 and o["remove stg"] == 302 and o["tenants left"] == ["dev"]
    assert o["conflict"] == 409 and o["after conflict"] == ["agent-a.example.com"]
    assert o["no csrf"] == 400 and o["dev survives"] is True
    whats = [w for _, w in o["history"]]
    assert whats[0] == "removed tenant STG (its agents and shared secret)"
    assert "DEV: changed shared secret" in whats and "DEV: changed port" in whats
    assert all(b == "admin@x" for b, _ in o["history"])
    assert not any("Key" in w for w in whats)
