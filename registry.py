from __future__ import annotations

import copy
import datetime
import ipaddress
import re

TENANTS = {
    "dev": ("DEV", "https://host.example.com"),
    "stg": ("STG", "https://host.example.com"),
    "prod": ("PROD", "https://host.example.com"),
}
HISTORY_MAX = 200
_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class Invalid(ValueError):
    pass


def empty() -> dict:
    return {"tenants": {}, "history": []}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def host(value) -> str:
    h = (value or "").strip().lower().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(h))
    except ValueError:
        pass
    parts = h.split(".")
    if 0 < len(h) <= 253 and len(parts) > 1 and all(_DNS_LABEL.match(p) for p in parts) \
            and not parts[-1].isdigit():
        return h
    raise Invalid(f"{value!r} is not a fully qualified hostname or an IPv4 address")


def port(value) -> int:
    try:
        p = int(str(value).strip())
    except ValueError:
        raise Invalid(f"port {value!r} is not a number") from None
    if not 0 < p < 65536:
        raise Invalid(f"port {p} is outside 1-65535")
    return p


def secret(value) -> str:
    s = value or ""
    if not 0 < len(s) <= 128:
        raise Invalid("the shared secret must be 1-128 characters")
    if s != s.strip():
        raise Invalid("the shared secret starts or ends with a space — retype it")
    if not all(32 <= ord(c) < 127 for c in s):
        raise Invalid("the shared secret may only contain printable ASCII characters")
    return s


def text(value, name: str, lo: int, hi: int) -> str:
    t = (value or "").strip()
    if not lo <= len(t) <= hi or not t.isprintable():
        raise Invalid(f"{name} must be {lo}-{hi} printable characters")
    return t


def check(doc: dict | None) -> dict:
    if not doc:
        return empty()
    if not isinstance(doc.get("tenants"), dict) or not isinstance(doc.get("history", []), list):
        raise Invalid("registry must have a 'tenants' object and a 'history' list")
    for key, t in doc["tenants"].items():
        if key not in TENANTS:
            raise Invalid(f"tenants.{key}: not one of {sorted(TENANTS)}")
        try:
            text(t.get("app"), "RADIUS app", 1, 100)
            port(t.get("port"))
            secret(t.get("secret"))
            if not isinstance(t.get("agents"), list):
                raise Invalid("agents must be a list")
            for a in t["agents"]:
                if host(a) != a:
                    raise Invalid(f"agent {a!r} is not in normal form")
        except Invalid as e:
            raise Invalid(f"tenants.{key}: {e}") from None
    doc.setdefault("history", [])
    return doc


def public(doc: dict) -> list[dict]:
    out = []
    for key, (label, okta) in TENANTS.items():
        t = doc["tenants"].get(key)
        if t:
            out.append({"key": key, "label": label, "okta": okta, "app": t["app"], "port": t["port"],
                        "hint": t.get("hint", ""), "agents": list(t["agents"]),
                        "secret_changed": t.get("secret_changed") or {}})
    return out


def missing(doc: dict) -> list[tuple[str, str]]:
    return [(k, lbl) for k, (lbl, _) in TENANTS.items() if k not in doc["tenants"]]


def lookup(doc: dict, key: str, agent: str) -> dict | None:
    t = doc["tenants"].get(key)
    return t if t and agent in t["agents"] else None


def _stamp(doc: dict, by: str, what: str) -> None:
    doc["history"] = ([{"at": _now(), "by": by, "what": what}] + doc.get("history", []))[:HISTORY_MAX]


def _tenant(doc: dict, key: str) -> tuple[str, dict]:
    if key not in TENANTS:
        raise Invalid(f"unknown tenant {key!r}")
    t = doc["tenants"].get(key)
    if t is None:
        raise Invalid(f"{TENANTS[key][0]} has not been added")
    return TENANTS[key][0], t


def put_tenant(doc: dict, key: str, *, app: str, port_: str, secret_: str | None, hint: str,
               by: str) -> tuple[dict, str | None]:
    if key not in TENANTS:
        raise Invalid(f"unknown tenant {key!r}")
    label = TENANTS[key][0]
    new = key not in doc["tenants"]
    if new and not secret_:
        raise Invalid(f"adding {label} needs its RADIUS app's shared secret")
    fields = {"app": text(app, "RADIUS app", 1, 100), "port": port(port_),
              "hint": text(hint, "username hint", 0, 120)}
    s = secret(secret_) if secret_ else None
    d = copy.deepcopy(doc)
    rec = d["tenants"].setdefault(key, {"agents": []})
    changed = [k if k != "app" else "RADIUS app" for k, v in fields.items() if rec.get(k, "") != v]
    rec.update(fields)
    if s is not None and s != rec.get("secret"):
        rec["secret"] = s
        rec["secret_changed"] = {"at": _now(), "by": by}
        changed.append("shared secret")
    if not new and not changed:
        return doc, None
    what = f"added tenant {label}" if new else f"{label}: changed {', '.join(changed)}"
    _stamp(d, by, what)
    return d, what


def add_agent(doc: dict, key: str, agent: str, by: str) -> tuple[dict, str]:
    label, t = _tenant(doc, key)
    h = host(agent)
    if h in t["agents"]:
        raise Invalid(f"{h} is already a {label} agent")
    d = copy.deepcopy(doc)
    d["tenants"][key]["agents"].append(h)
    what = f"{label}: added agent {h}"
    _stamp(d, by, what)
    return d, what


def remove_agent(doc: dict, key: str, agent: str, by: str) -> tuple[dict, str]:
    label, t = _tenant(doc, key)
    if agent not in t["agents"]:
        raise Invalid(f"{agent} is not a {label} agent")
    d = copy.deepcopy(doc)
    d["tenants"][key]["agents"].remove(agent)
    what = f"{label}: removed agent {agent}"
    _stamp(d, by, what)
    return d, what


def remove_tenant(doc: dict, key: str, confirm: str, by: str) -> tuple[dict, str]:
    label, _ = _tenant(doc, key)
    if (confirm or "").strip() != label:
        raise Invalid(f"type {label} to confirm removing it")
    d = copy.deepcopy(doc)
    del d["tenants"][key]
    what = f"removed tenant {label} (its agents and shared secret)"
    _stamp(d, by, what)
    return d, what
