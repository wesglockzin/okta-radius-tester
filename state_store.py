from __future__ import annotations

import base64
import copy
import json
import ssl
import urllib.error
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
KEY = "state.json"


class StateError(Exception):
    pass


class Conflict(StateError):
    pass


def _read(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


class KubeSecretStore:

    def __init__(self, name: str):
        self.name = name

    def _call(self, method: str, body: dict | None = None) -> dict:
        try:
            namespace = _read(f"{SA_DIR}/namespace")
            token = _read(f"{SA_DIR}/token")
        except OSError as e:
            raise StateError(f"no ServiceAccount credentials in this pod ({e})") from None
        url = f"{API.rstrip('/')}/api/v1/namespaces/{namespace}/secrets/{self.name}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt") if url.startswith("https:") else None
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 409:
                raise Conflict(f"secret/{self.name} changed since it was read") from None
            why = {403: "this pod's ServiceAccount may not do that — is stateSecret set in the values file?",
                   404: "it does not exist — create it out of band (see the tool's CLAUDE.md)"}.get(e.code, e.reason)
            raise StateError(f"{method} secret/{self.name} in {namespace}: HTTP {e.code} — {why}") from None
        except (urllib.error.URLError, OSError) as e:
            raise StateError(f"{method} secret/{self.name}: Kubernetes API unreachable ({e})") from None

    def load(self) -> tuple[dict, dict]:
        obj = self._call("GET")
        raw = (obj.get("data") or {}).get(KEY)
        try:
            doc = json.loads(base64.b64decode(raw)) if raw else {}
        except ValueError as e:
            raise StateError(f"secret/{self.name} key {KEY} is not valid JSON ({e})") from None
        return doc, obj

    def save(self, doc: dict, version: dict) -> None:
        body = copy.deepcopy(version)
        body.setdefault("data", {})[KEY] = base64.b64encode(json.dumps(doc, indent=1).encode()).decode()
        self._call("PUT", body)


class MemoryStore:

    def __init__(self, doc: dict | None = None):
        self._doc, self._rv = copy.deepcopy(doc or {}), 1

    def load(self) -> tuple[dict, dict]:
        return copy.deepcopy(self._doc), {"rv": self._rv}

    def save(self, doc: dict, version: dict) -> None:
        if version.get("rv") != self._rv:
            raise Conflict("changed since it was read")
        self._doc, self._rv = copy.deepcopy(doc), self._rv + 1

    def bump(self) -> None:
        self._rv += 1
