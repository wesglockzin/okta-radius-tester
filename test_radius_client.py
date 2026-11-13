import hashlib
import hmac
import socket
import struct
import threading

import pytest

import radius_client as rc

SECRET = b"unit-test-shared-secret"


def _unhide(hidden: bytes, secret: bytes, auth: bytes) -> bytes:
    out, prev = b"", auth
    for i in range(0, len(hidden), 16):
        b = hashlib.md5(secret + prev).digest()
        out += bytes(x ^ y for x, y in zip(hidden[i:i + 16], b))
        prev = hidden[i:i + 16]
    return out.rstrip(b"\x00")


class FakeServer:

    def __init__(self, reply_code=3, reply_attrs=b"", server_secret=SECRET, with_ma=True, script=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.script = list(script or [(reply_code, reply_attrs)])
        self.secret, self.with_ma = server_secret, with_ma
        self.seen = {}
        self.t = threading.Thread(target=self._serve_all, daemon=True)
        self.t.start()

    def _serve_all(self):
        for self.reply_code, self.reply_attrs in self.script:
            self._serve()

    def _serve(self):
        data, addr = self.sock.recvfrom(4096)
        self.seen = {}
        code, ident, length = struct.unpack("!BBH", data[:4])
        auth, attrs = data[4:20], data[20:length]
        assert attrs[0] == rc.MESSAGE_AUTHENTICATOR
        ma = attrs[2:18]
        zeroed = data[:22] + b"\x00" * 16 + data[38:length]
        self.seen["ma_ok"] = hmac.compare_digest(hmac.new(self.secret, zeroed, hashlib.md5).digest(), ma)
        for t, sub, v in rc._decode(attrs):
            if t == rc.USER_PASSWORD and sub is None:
                self.seen["password"] = _unhide(v, self.secret, auth)
            if t == rc.USER_NAME and sub is None:
                self.seen["user"] = v.decode()
            if t == rc.STATE and sub is None:
                self.seen["state"] = v
            if (t, sub) == (rc.CISCO_VPN3000, 146):
                self.seen["tunnel_group"] = v.decode()

        body = self.reply_attrs
        if self.with_ma:
            body = struct.pack("!BB", 80, 18) + b"\x00" * 16 + body
        hdr = struct.pack("!BBH", self.reply_code, ident, 20 + len(body))
        if self.with_ma:
            ma = hmac.new(self.secret, hdr + auth + body, hashlib.md5).digest()
            body = body[:2] + ma + body[18:]
        resp_auth = hashlib.md5(hdr + auth + body + self.secret).digest()
        self.sock.sendto(hdr + resp_auth + body, addr)


def _send(srv, password="correct horse", **kw):
    return rc.send("127.0.0.1", srv.port, SECRET.decode(), "radius_probe_user", password,
                   timeout=3, **kw)


def test_reject_signed_with_same_key_verifies():
    srv = FakeServer(reply_code=3)
    r = _send(srv)
    assert r.code == "REJECT" and r.signature_ok is True
    assert srv.seen["ma_ok"] is True
    assert srv.seen["user"] == "radius_probe_user"
    assert srv.seen["tunnel_group"] == "RADIUS-TEST"


@pytest.mark.parametrize("pw", ["", "a", "exactly16chars!!", "a much longer password than one block"])
def test_password_round_trips(pw):
    srv = FakeServer()
    _send(srv, password=pw)
    assert srv.seen["password"] == pw.encode()


def test_wrong_key_is_bad_signature_not_reject():
    srv = FakeServer(reply_code=3, server_secret=b"some-other-key")
    r = _send(srv)
    assert r.code == "BAD_SIGNATURE" and r.signature_ok is False


def test_wrong_key_detected_by_response_authenticator_without_ma():
    srv = FakeServer(reply_code=2, server_secret=b"some-other-key", with_ma=False)
    assert _send(srv).code == "BAD_SIGNATURE"


def test_challenge_carries_state_and_reply_message():
    attrs = (struct.pack("!BB", rc.STATE, 2 + 6) + b"st-123"
             + struct.pack("!BB", rc.REPLY_MESSAGE, 2 + 9) + b"Enter OTP")
    srv = FakeServer(reply_code=11, reply_attrs=attrs)
    r = _send(srv)
    assert r.code == "CHALLENGE" and r.state == b"st-123" and r.reply_message == "Enter OTP"
    srv2 = FakeServer(reply_code=2)
    _send(srv2, password="123456", state=r.state)
    assert srv2.seen["state"] == b"st-123" and srv2.seen["password"] == b"123456"


def test_no_reply_is_reported_as_no_reply():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    r = rc.send("127.0.0.1", s.getsockname()[1], "k", "u", "p", timeout=0.5)
    s.close()
    assert r.code == "NO_REPLY"


@pytest.mark.parametrize("state", [None, b"st"])
def test_describe_matches_the_wire(state):
    p = rc.AsaProfile()
    _, _, pkt = rc.build_request("u", "pw", SECRET, p, state)
    wire = [rc._render(t, sub, v)[0] if (t, sub) != (rc.USER_PASSWORD, None) else "User-Password"
            for t, sub, v in rc._decode(pkt[20:])]
    shown = [n for n, _ in rc.describe_request("u", p, state is not None)]
    assert wire == shown


def test_secret_and_password_never_in_reply_text():
    srv = FakeServer(reply_code=3)
    r = _send(srv, password="[REDACTED]")
    blob = repr(r)
    assert "hunter2-secret-pw" not in blob and SECRET.decode() not in blob
