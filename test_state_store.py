import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import state_store as ss

NS = "rt-test-ns"
TOKEN = "sa-token-1"


class FakeKubeAPI:

    def __init__(self, secrets=None, forbidden=(), token=TOKEN):
        self.secrets, self.forbidden, self.token, self.calls = dict(secrets or {}), set(forbidden), token, []
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _route(self, method):
                api.calls.append((method, self.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {api.token}":
                    return self._send(401, {"reason": "Unauthorized"})
                prefix = f"/api/v1/namespaces/{NS}/secrets/"
                if not self.path.startswith(prefix):
                    return self._send(404, {"reason": "NotFound"})
                name = self.path[len(prefix):]
                if name in api.forbidden:
                    return self._send(403, {"reason": "Forbidden"})
                if name not in api.secrets:
                    return self._send(404, {"reason": "NotFound"})
                cur = api.secrets[name]
                if method == "GET":
                    return self._send(200, cur)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                rv = body["metadata"].get("resourceVersion")
                if rv is not None and rv != cur["metadata"]["resourceVersion"]:
                    return self._send(409, {"reason": "Conflict"})
                body["metadata"]["resourceVersion"] = str(int(cur["metadata"]["resourceVersion"]) + 1)
                api.secrets[name] = body
                return self._send(200, body)

            def do_GET(self):
                self._route("GET")

            def do_PUT(self):
                self._route("PUT")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @staticmethod
    def secret_obj(name, doc=None, raw=None, extra=None):
        data = dict(extra or {})
        if doc is not None or raw is not None:
            data[ss.KEY] = base64.b64encode(raw if raw is not None else json.dumps(doc).encode()).decode()
        return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "data": data,
                "metadata": {"name": name, "namespace": NS, "resourceVersion": "7",
                             "labels": {"keep": "me"}}}

    def doc(self, name):
        return json.loads(base64.b64decode(self.secrets[name]["data"][ss.KEY]))

    def point(self, sa_dir):
        (sa_dir / "namespace").write_text(NS)
        (sa_dir / "token").write_text(self.token)
        ss.SA_DIR, ss.API = str(sa_dir), self.url


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "SA_DIR", ss.SA_DIR)
    monkeypatch.setattr(ss, "API", ss.API)
    fake = FakeKubeAPI({"reg": FakeKubeAPI.secret_obj("reg", {"a": 1}, extra={"other": "eA=="})},
                       forbidden={"locked"})
    fake.point(tmp_path)
    return fake


def test_round_trip_keeps_everything_else_on_the_secret(api):
    s = ss.KubeSecretStore("reg")
    doc, v = s.load()
    assert doc == {"a": 1}
    s.save({"a": 2}, v)
    assert api.doc("reg") == {"a": 2}
    obj = api.secrets["reg"]
    assert obj["data"]["other"] == "eA==" and obj["metadata"]["labels"] == {"keep": "me"}
    assert obj["metadata"]["resourceVersion"] == "8"
    assert [c[0] for c in api.calls] == ["GET", "PUT"]


def test_concurrent_write_is_a_conflict_not_an_overwrite(api):
    s = ss.KubeSecretStore("reg")
    _, v1 = s.load()
    _, v2 = s.load()
    s.save({"by": "first"}, v1)
    with pytest.raises(ss.Conflict):
        s.save({"by": "second"}, v2)
    assert api.doc("reg") == {"by": "first"}


@pytest.mark.parametrize("name,needle", [
    ("locked", "HTTP 403 — this pod's ServiceAccount may not do that"),
    ("absent", "HTTP 404 — it does not exist — create it out of band"),
])
def test_each_failure_names_its_cause(api, name, needle):
    with pytest.raises(ss.StateError) as e:
        ss.KubeSecretStore(name).load()
    assert needle in str(e.value) and NS in str(e.value)


def test_wrong_token_is_refused(api, tmp_path):
    (tmp_path / "token").write_text("stolen")
    with pytest.raises(ss.StateError, match="HTTP 401"):
        ss.KubeSecretStore("reg").load()


def test_token_is_reread_every_call(api, tmp_path):
    s = ss.KubeSecretStore("reg")
    _, v = s.load()
    api.token = "sa-token-2"
    (tmp_path / "token").write_text("sa-token-2")
    s.save({"a": 3}, v)
    assert api.calls[-1][2] == "Bearer sa-token-2"


def test_not_json_is_a_named_error(api):
    api.secrets["junk"] = FakeKubeAPI.secret_obj("junk", raw=b"{not json")
    with pytest.raises(ss.StateError, match="not valid JSON"):
        ss.KubeSecretStore("junk").load()


def test_empty_secret_is_an_empty_document(api):
    api.secrets["new"] = FakeKubeAPI.secret_obj("new")
    doc, _ = ss.KubeSecretStore("new").load()
    assert doc == {}


def test_no_serviceaccount_files(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "SA_DIR", str(tmp_path / "nowhere"))
    with pytest.raises(ss.StateError, match="no ServiceAccount credentials"):
        ss.KubeSecretStore("reg").load()


def test_unreachable_api(monkeypatch, tmp_path):
    (tmp_path / "namespace").write_text(NS)
    (tmp_path / "token").write_text(TOKEN)
    monkeypatch.setattr(ss, "SA_DIR", str(tmp_path))
    monkeypatch.setattr(ss, "API", "http://127.0.0.1:9")
    with pytest.raises(ss.StateError, match="unreachable"):
        ss.KubeSecretStore("reg").load()


def test_memory_store_has_the_same_conflict_rule():
    m = ss.MemoryStore({"x": 1})
    _, v = m.load()
    m.bump()
    with pytest.raises(ss.Conflict):
        m.save({"x": 2}, v)
