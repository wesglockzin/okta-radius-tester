from __future__ import annotations

import hmac
import ipaddress
import os
import secrets

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import radius_client as rc
import registry as reg
import state_store

if __name__ == "__main__":
    raise SystemExit("[radius-tester] app.py is not runnable — the entry point is "
                     "`gunicorn wsgi:app` (see CLAUDE.md)")

APP_VERSION = "0.2.0"

ROUND_TIMEOUT_S = 60
MAX_ROUNDS = 5

APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)
STATE_SECRET = os.environ.get("FLEET_STATE_SECRET", "")
IN_CLUSTER = bool(os.environ.get("KUBERNETES_SERVICE_HOST"))

if IN_CLUSTER:
    if not OIDC_ENABLED:
        raise SystemExit("[radius-tester] in a cluster with no OIDC_* sign-in config — refusing to start open")
    if not STATE_SECRET:
        raise SystemExit("[radius-tester] in a cluster with no FLEET_STATE_SECRET — set stateSecret "
                         "in the values file; refusing to start")

STORE = state_store.KubeSecretStore(STATE_SECRET) if IN_CLUSTER else state_store.MemoryStore(reg.empty())


def load_registry() -> tuple[dict, dict]:
    doc, version = STORE.load()
    return reg.check(doc), version


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_NAME"] = "rt_session"
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "").encode() or os.urandom(32)

HEAD = """
<!doctype html><meta charset=utf-8><title>Okta RADIUS Tester</title>
<style>
 body{font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      max-width:860px;margin:40px auto;padding:0 20px;color:#1a1a1a}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#666;font-size:13px;margin-bottom:12px}
 h2{font-size:15px;margin:22px 0 6px;color:#333} h3{font-size:15px;margin:26px 0 4px}
 nav{margin:0 0 22px;border-bottom:1px solid #e5e5e5}
 nav a{display:inline-block;padding:6px 2px;margin-right:18px;color:#555;text-decoration:none;font-size:14px}
 nav a.on{color:#1662dd;border-bottom:2px solid #1662dd;font-weight:600}
 button,a.btn{display:inline-block;background:#1662dd;color:#fff;text-decoration:none;border:0;
       padding:9px 16px;border-radius:6px;margin:8px 8px 8px 0;font-size:14px;cursor:pointer}
 a.btn.alt{background:#4a4a4a}
 button.small{padding:3px 10px;margin:0;font-size:12px;background:#eee;color:#333}
 button.danger{background:#c62828}
 form.inline{display:inline}
 label{display:block;font-size:13px;color:#555;margin:10px 0 3px}
 input,select{font:inherit;padding:7px 9px;border:1px solid #ccc;border-radius:5px;width:100%;box-sizing:border-box}
 .row{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
 .ok{background:#e8f5e9;border-left:4px solid #2e7d32;padding:12px 16px;border-radius:4px;margin-bottom:12px}
 .no{background:#fdecea;border-left:4px solid #c62828;padding:12px 16px;border-radius:4px;margin-bottom:12px}
 .ask{background:#fff8e1;border-left:4px solid #f9a825;padding:12px 16px;border-radius:4px}
 .hint{background:#fff8e1;border-left:4px solid #f9a825;padding:10px 14px;border-radius:4px;margin-top:10px;font-size:14px}
 table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:14px}
 th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #e5e5e5;vertical-align:top}
 th{color:#555;font-weight:600}
 code{background:#f4f4f4;padding:2px 5px;border-radius:3px;font-size:13px}
 pre{background:#f7f7f7;padding:10px 12px;border-radius:6px;white-space:pre-wrap;font-size:13px;margin:6px 0}
 .dim{color:#777;font-size:13px}
 .meta{color:#777;font-size:12px;margin-top:28px;border-top:1px solid #eee;padding-top:12px}
 details{margin:10px 0}
</style>
<h1>Okta RADIUS Tester</h1>
<div class=sub>
  v{{ version }} &middot; DEV / STG / PROD
  {% if user %}&middot; {{ user.email or user.name }} &middot; <a href="/logout">Sign out of this tool</a>{% endif %}
</div>
<nav><a href="/" {% if page == "test" %}class=on{% endif %}>Test</a><a href="/settings" {% if page == "settings" %}class=on{% endif %}>Tenants &amp; agents</a></nav>
{% if error %}<div class=no><b>{{ error_title }}</b> — {{ error }}</div>{% endif %}
{% if notice %}<div class=ok>{{ notice }}</div>{% endif %}
"""

TEST_PAGE = """
{% if flow and flow.rounds %}
  {% set last = flow.rounds[-1] %}
  {% if last.code == "ACCEPT" %}
    <div class=ok><b>ACCEPT</b> — Okta {{ flow.label }} authenticated <code>{{ flow.username }}</code>. The ASA would let this user connect.</div>
  {% elif last.code == "REJECT" %}
    <div class=no><b>REJECT</b> — Okta {{ flow.label }} refused <code>{{ flow.username }}</code>.</div>
    {% if "@" in flow.username and flow.hint %}<div class=hint>If the username is the cause: {{ flow.label }}'s RADIUS app expects {{ flow.hint }}.</div>{% endif %}
  {% elif last.code == "CHALLENGE" %}
    <div class=ask><b>CHALLENGE</b> — Okta wants a second step. Answer it the way you would in the VPN client.</div>
    {% if last.reply_message %}<pre>{{ last.reply_message }}</pre>{% endif %}
    {% if flow.rounds|length < max_rounds %}
    <form method=post action="/respond">
      <input type=hidden name=csrf value="{{ csrf }}">
      <label>Response (the factor number, or the code)</label>
      <input name=response autocomplete=off autofocus>
      <button>Send response</button>
      <span class=dim>waits up to {{ timeout }}s — long enough to approve a push</span>
    </form>
    {% else %}<div class=hint>{{ max_rounds }} rounds without a final answer — stopping here.</div>{% endif %}
  {% elif last.code == "NO_REPLY" %}
    <div class=no><b>NO REPLY</b> — {{ last.detail }}. Either the agent is down or the path is blocked; another agent is worth a try.</div>
  {% elif last.code == "BAD_SIGNATURE" %}
    <div class=no><b>KEY MISMATCH</b> — {{ last.detail }}. The shared secret saved for {{ flow.label }} is not the one in its Okta RADIUS app; Okta's answer is not trustworthy until they match.</div>
  {% endif %}

  <h2>Rounds</h2>
  <table>
    <tr><th>#</th><th>Sent</th><th>Result</th><th>Time</th><th>Reply-Message</th></tr>
    {% for r in flow.rounds %}
    <tr><td>{{ loop.index }}</td><td>{{ r.sent }}</td><td><b>{{ r.code }}</b></td>
        <td>{{ r.ms }} ms</td><td>{{ r.reply_message or "-" }}</td></tr>
    {% endfor %}
  </table>
  <div class=dim>Tenant <b>{{ flow.label }}</b> &middot; {{ flow.app }} &middot; agent <code>{{ flow.agent }}</code> UDP {{ flow.port }} &middot; reply signatures
    {% if last.signature_ok %}verified with the shared secret{% elif last.signature_ok is none %}not checked (no reply){% else %}<b>did not verify</b>{% endif %}</div>

  {% if last.attributes %}
  <h2>Reply attributes</h2>
  <table>{% for n, v in last.attributes %}<tr><th>{{ n }}</th><td><code>{{ v }}</code></td></tr>{% endfor %}</table>
  {% endif %}

  <details><summary>What was sent (the ASA request shape)</summary>
    <table>{% for n, v in sent %}<tr><th>{{ n }}</th><td>{{ v }}</td></tr>{% endfor %}</table>
  </details>
  <a class=btn alt href="/">New test</a>
{% elif not tenants %}
  <p>No RADIUS tenants yet. Add one under <a href="/settings">Tenants &amp; agents</a>.</p>
{% else %}
  <p>Sends the same RADIUS Access-Request a Cisco ASA sends for a VPN client login,
     straight to an Okta RADIUS agent, and shows Okta's answer.</p>
  <form method=post action="/send">
    <input type=hidden name=csrf value="{{ csrf }}">
    <div class=row>
      <div><label>Username <span class=dim>(as the tenant's RADIUS app stores it)</span></label>
           <input name=username value="{{ form.username }}" required autocomplete=off></div>
      <div><label>Password</label>
           <input name=password type=password required autocomplete=new-password></div>
    </div>
    {% for t in tenants if t.hint %}<div class=dim>{{ t.label }}: {{ t.hint }}</div>{% endfor %}
    <label>Agent</label>
    <select name=agent>
      {% for t in tenants %}<optgroup label="{{ t.label }} — {{ t.app }} (UDP {{ t.port }})">
        {% for a in t.agents %}{% set v = t.key ~ "|" ~ a %}<option value="{{ v }}" {% if v == form.agent %}selected{% endif %}>{{ t.label }} &middot; {{ a }}</option>{% endfor %}
      </optgroup>{% endfor %}
    </select>
    <details><summary>ASA attributes</summary>
      <div class=row>
        <div><label>Tunnel group</label><input name=tunnel_group value="{{ form.tunnel_group }}"></div>
        <div><label>Client IP (Calling-Station-Id)</label><input name=client_ip value="{{ form.client_ip }}"></div>
        <div><label>NAS-IP-Address (the ASA)</label><input name=nas_ip value="{{ form.nas_ip }}"></div>
      </div>
    </details>
    <button>Send Access-Request</button>
    <div class=dim>A wrong password counts toward that account's AD lockout. Use a test account.</div>
  </form>
{% endif %}

<div class=meta>
  RADIUS decisions are in each tenant's Okta System Log under <code>user.authentication.auth_via_radius</code>.
  The password goes to the agent PAP-hidden with the shared secret and is never stored or logged.
</div>
"""

SETTINGS_PAGE = """
<p>Where this tool can send a RADIUS request. A tenant is one Okta tenant's RADIUS app — its
   UDP port and shared secret — and the agents that serve it. Changes apply at once and are
   kept in the OpenShift Secret <code>{{ state_secret }}</code> (one per tier: Preview and GA
   each have their own).</p>

{% for t in tenants %}
  <h3>{{ t.label }} <span class=dim>&middot; {{ t.okta }}</span></h3>
  <table>
    <tr><th>RADIUS app</th><td>{{ t.app }}</td></tr>
    <tr><th>UDP port</th><td>{{ t.port }}</td></tr>
    <tr><th>Shared secret</th><td>set{% if t.secret_changed.at %} &middot; changed {{ t.secret_changed.at }} by {{ t.secret_changed.by }}{% endif %}
      <span class=dim>&middot; never shown</span></td></tr>
    <tr><th>Username</th><td>{{ t.hint or "-" }}</td></tr>
    <tr><th>Agents</th><td>
      {% for a in t.agents %}<div><code>{{ a }}</code>
        <form class=inline method=post action="/settings/agent">
          <input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=tenant value="{{ t.key }}">
          <input type=hidden name=agent value="{{ a }}"><input type=hidden name=action value=remove>
          <button class=small>Remove</button></form></div>
      {% else %}<span class=dim>none yet</span>{% endfor %}
      <form method=post action="/settings/agent" style="margin-top:8px">
        <input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=tenant value="{{ t.key }}">
        <input type=hidden name=action value=add>
        <div class=row><div><input name=agent placeholder="agent hostname (fully qualified) or IPv4" required></div>
          <div><button class=small style="padding:8px 12px">Add agent</button></div></div>
      </form></td></tr>
  </table>
  <details><summary>Edit {{ t.label }}</summary>
    <form method=post action="/settings/tenant">
      <input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=tenant value="{{ t.key }}">
      <div class=row>
        <div><label>RADIUS app (name and id, for people)</label><input name=app value="{{ t.app }}" required></div>
        <div><label>UDP port</label><input name=port value="{{ t.port }}" required></div>
      </div>
      <label>New shared secret <span class=dim>(leave blank to keep the current one)</span></label>
      <input name=secret type=password autocomplete=new-password>
      <label>Username format hint</label><input name=hint value="{{ t.hint }}">
      <button>Save {{ t.label }}</button>
    </form>
  </details>
  <details><summary>Remove {{ t.label }}</summary>
    <form method=post action="/settings/tenant/remove">
      <input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=tenant value="{{ t.key }}">
      <label>Removes {{ t.label }}, its agents and its shared secret. Type <b>{{ t.label }}</b> to confirm.</label>
      <input name=confirm autocomplete=off>
      <button class=danger>Remove {{ t.label }}</button>
    </form>
  </details>
{% endfor %}

{% if missing %}
<h3>Add a tenant</h3>
<form method=post action="/settings/tenant">
  <input type=hidden name=csrf value="{{ csrf }}">
  <div class=row>
    <div><label>Tenant</label><select name=tenant>{% for k, l in missing %}<option value="{{ k }}">{{ l }}</option>{% endfor %}</select></div>
    <div><label>UDP port <span class=dim>(the RADIUS app's port)</span></label><input name=port value="1812" required></div>
  </div>
  <label>RADIUS app (name and id, for people)</label><input name=app placeholder="VPN - RADIUS Application (0oa...)" required>
  <label>Shared secret <span class=dim>(the RADIUS app's Secret Key, typed exactly)</span></label>
  <input name=secret type=password autocomplete=new-password required>
  <label>Username format hint <span class=dim>(optional — e.g. sAMAccountName, not the email)</span></label><input name=hint>
  <button>Add tenant</button>
  <div class=dim>Then add its agents above.</div>
</form>
{% endif %}

<h3>Checking a new agent or secret</h3>
<p class=dim>Run a test with a username that does not exist (e.g. <code>radius-probe-nonexistent-user</code>) —
   no account's lockout counter moves. A signed <b>REJECT</b> proves the path and the shared secret;
   <b>KEY MISMATCH</b> means the secret saved here is not the one in Okta; <b>NO REPLY</b> means the agent is
   down or UDP from this cluster to the agent's port is blocked (a firewall request, not a tool change).</p>

{% if history %}
<h3>Recent changes</h3>
<table>{% for h in history %}<tr><td class=dim>{{ h.at }}</td><td>{{ h.by }}</td><td>{{ h.what }}</td></tr>{% endfor %}</table>
{% endif %}
"""


def _csrf() -> str:
    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _page(body: str, **kw):
    kw.setdefault("error", None)
    kw.setdefault("notice", None)
    return render_template_string(HEAD + body, version=APP_VERSION, csrf=_csrf(),
                                  user=session.get("user") if OIDC_ENABLED else None, **kw)


def _render(**kw):
    flow = session.get("flow")
    sent = rc.describe_request(flow["username"], rc.AsaProfile(**flow["profile"]),
                               state=len(flow["rounds"]) > 1) if flow else []
    error = kw.get("error")
    try:
        doc, _ = load_registry()
        tenants = reg.public(doc)
    except (state_store.StateError, reg.Invalid) as e:
        tenants, error = [], error or f"the tenant registry could not be read: {e}"
    first = next((f"{t['key']}|{t['agents'][0]}" for t in tenants if t["agents"]), "")
    form = kw.get("form") or {"username": "", "agent": first,
                              **{k: v for k, v in rc.AsaProfile().__dict__.items()}}
    return _page(TEST_PAGE, page="test", error_title="Not sent", error=error, tenants=tenants,
                 flow=flow, sent=sent, form=form, timeout=ROUND_TIMEOUT_S, max_rounds=MAX_ROUNDS)


def _render_settings(**kw):
    tenants, missing, history = [], [], []
    try:
        doc, _ = load_registry()
        tenants, missing, history = reg.public(doc), reg.missing(doc), doc["history"][:25]
    except (state_store.StateError, reg.Invalid) as e:
        kw["error"] = kw.get("error") or f"the tenant registry could not be read: {e}"
    return _page(SETTINGS_PAGE, page="settings", error_title="Not saved", tenants=tenants,
                 missing=missing, history=history, state_secret=STATE_SECRET or "(none — in memory)", **kw)


def _profile_from(f) -> rc.AsaProfile:
    d = rc.AsaProfile()
    p = rc.AsaProfile(nas_ip=(f.get("nas_ip") or d.nas_ip).strip(),
                      tunnel_group=(f.get("tunnel_group") or d.tunnel_group).strip(),
                      client_ip=(f.get("client_ip") or d.client_ip).strip(),
                      called_station=(f.get("nas_ip") or d.called_station).strip())
    for name in ("nas_ip", "client_ip"):
        ipaddress.IPv4Address(getattr(p, name))
    if not (0 < len(p.tunnel_group) <= 64 and p.tunnel_group.isprintable()):
        raise ValueError("tunnel group must be 1-64 printable characters")
    return p


def _round(flow: dict, password: str, sent: str, tenant: dict) -> None:
    state = bytes.fromhex(flow["state"]) if flow.get("state") else None
    r = rc.send(flow["agent"], tenant["port"], tenant["secret"], flow["username"], password,
                rc.AsaProfile(**flow["profile"]), state=state, timeout=ROUND_TIMEOUT_S)
    flow["state"] = r.state.hex() if (r.code == "CHALLENGE" and r.state) else None
    flow["rounds"].append({"sent": sent, "code": r.code, "ms": r.elapsed_ms,
                           "reply_message": r.reply_message, "attributes": r.attributes,
                           "signature_ok": r.signature_ok, "detail": r.detail})
    who = (session.get("user") or {}).get("email", "-")
    print(f"  {who} -> {flow['label']} {flow['agent']} as {flow['username']!r} round {len(flow['rounds'])}: "
          f"{r.code} {r.elapsed_ms}ms")


if OIDC_ENABLED:
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    oauth.register(name="okta", client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET,
                   server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
                   client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"})

PUBLIC_PATHS = {"/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico"}


def _safe_next(n) -> str:
    n = n or "/"
    return n if n.startswith("/") and not n.startswith("//") and "\\" not in n else "/"


@app.before_request
def _auth_gate():
    if request.path in PUBLIC_PATHS:
        return None
    if OIDC_ENABLED and not session.get("user"):
        return redirect(url_for("login", next=request.full_path.rstrip("?")))
    if request.method == "POST":
        want = session.get("csrf") or ""
        if not want or not hmac.compare_digest(request.form.get("csrf", ""), want):
            return "This form is stale — go back and reload the page.", 400
    return None


@app.get("/login")
def login():
    if not OIDC_ENABLED:
        return redirect(url_for("home"))
    session["next"] = _safe_next(request.args.get("next"))
    return oauth.okta.authorize_redirect(APP_BASE_URL + url_for("oidc_callback"))


@app.get("/oidc/login")
def oidc_login():
    return login()


@app.get("/oidc/callback")
def oidc_callback():
    if not OIDC_ENABLED:
        return redirect(url_for("home"))
    try:
        info = oauth.okta.authorize_access_token().get("userinfo") or {}
        session["user"] = {"email": info.get("email"), "name": info.get("name")}
    except Exception as e:
        print(f"  ! sign-in callback failed ({e.__class__.__name__})")
        return "Sign-in failed", 401
    return redirect(_safe_next(session.pop("next", "/")))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION)


@app.get("/")
def home():
    session.pop("flow", None)
    return _render()


@app.post("/send")
def send():
    session.pop("flow", None)
    f = request.form
    username, password, choice = (f.get("username") or "").strip(), f.get("password") or "", f.get("agent") or ""
    form = {"username": username, "agent": choice, "tunnel_group": f.get("tunnel_group", ""),
            "client_ip": f.get("client_ip", ""), "nas_ip": f.get("nas_ip", "")}
    try:
        doc, _ = load_registry()
    except (state_store.StateError, reg.Invalid) as e:
        return _render(error=f"the tenant registry could not be read: {e}", form=form), 503
    key, _, agent = choice.partition("|")
    tenant = reg.lookup(doc, key, agent)
    if tenant is None:
        return _render(error="pick one of the listed agents", form=form), 400
    if not username or not password:
        return _render(error="username and password are both required", form=form), 400
    if len(password.encode()) > 128:
        return _render(error="RADIUS PAP passwords are limited to 128 bytes", form=form), 400
    try:
        profile = _profile_from(f)
    except ValueError as e:
        return _render(error=str(e), form=form), 400
    flow = {"id": secrets.token_hex(8), "tenant": key, "label": reg.TENANTS[key][0], "app": tenant["app"],
            "port": tenant["port"], "hint": tenant.get("hint", ""), "username": username, "agent": agent,
            "profile": profile.__dict__, "state": None, "rounds": []}
    try:
        _round(flow, password, "password", tenant)
    except OSError as e:
        return _render(error=f"could not send to {agent}: {e.__class__.__name__}: {e}", form=form), 502
    session["flow"] = flow
    return _render()


@app.post("/respond")
def respond():
    flow = session.get("flow")
    if not flow or not flow.get("state"):
        return redirect(url_for("home"))
    if len(flow["rounds"]) >= MAX_ROUNDS:
        return _render()
    try:
        doc, _ = load_registry()
    except (state_store.StateError, reg.Invalid) as e:
        return _render(error=f"the tenant registry could not be read: {e}"), 503
    tenant = reg.lookup(doc, flow["tenant"], flow["agent"])
    if tenant is None:
        return _render(error=f"{flow['agent']} is no longer a {flow['label']} agent — start a new test"), 409
    response = request.form.get("response") or ""
    try:
        _round(flow, response, "challenge response", tenant)
    except OSError as e:
        return _render(error=f"could not send to {flow['agent']}: {e.__class__.__name__}: {e}"), 502
    session["flow"] = flow
    return _render()


@app.get("/settings")
def settings():
    return _render_settings(notice=session.pop("notice", None))


def _change(fn):
    who = (session.get("user") or {}).get("email") or "signed-in user"
    try:
        doc, version = load_registry()
        new, what = fn(doc, who)
        if what:
            STORE.save(new, version)
            print(f"  settings: {who}: {what}")
    except state_store.Conflict:
        return _render_settings(error="someone else changed the registry at the same moment — nothing "
                                      "was saved; check below and try again"), 409
    except reg.Invalid as e:
        return _render_settings(error=str(e)), 400
    except state_store.StateError as e:
        return _render_settings(error=str(e)), 503
    session["notice"] = f"Saved — {what}." if what else "Nothing changed."
    return redirect(url_for("settings"))


@app.post("/settings/tenant")
def settings_tenant():
    f = request.form
    return _change(lambda d, who: reg.put_tenant(d, f.get("tenant", ""), app=f.get("app"), port_=f.get("port"),
                                                 secret_=f.get("secret") or None, hint=f.get("hint"), by=who))


@app.post("/settings/tenant/remove")
def settings_tenant_remove():
    f = request.form
    return _change(lambda d, who: reg.remove_tenant(d, f.get("tenant", ""), f.get("confirm"), who))


@app.post("/settings/agent")
def settings_agent():
    f = request.form
    op = {"add": reg.add_agent, "remove": reg.remove_agent}.get(f.get("action"))
    if op is None:
        return _render_settings(error="unknown action"), 400
    return _change(lambda d, who: op(d, f.get("tenant", ""), f.get("agent", ""), who))
