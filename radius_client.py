from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import time
from dataclasses import dataclass, field

ACCESS_REQUEST = 1
CODES = {2: "ACCEPT", 3: "REJECT", 11: "CHALLENGE"}

USER_NAME, USER_PASSWORD, NAS_IP_ADDRESS, NAS_PORT, SERVICE_TYPE = 1, 2, 4, 5, 6
FILTER_ID, REPLY_MESSAGE, STATE, CLASS, VENDOR_SPECIFIC = 11, 18, 24, 25, 26
SESSION_TIMEOUT, CALLED_STATION_ID, CALLING_STATION_ID = 27, 30, 31
NAS_IDENTIFIER, NAS_PORT_TYPE, TUNNEL_CLIENT_ENDPOINT = 32, 61, 66
MESSAGE_AUTHENTICATOR = 80

ATTR_NAMES = {
    1: "User-Name", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type",
    8: "Framed-IP-Address", 11: "Filter-Id", 18: "Reply-Message", 24: "State",
    25: "Class", 27: "Session-Timeout", 28: "Idle-Timeout", 30: "Called-Station-Id",
    31: "Calling-Station-Id", 32: "NAS-Identifier", 61: "NAS-Port-Type",
    66: "Tunnel-Client-Endpoint", 80: "Message-Authenticator",
}
CISCO, CISCO_VPN3000 = 9, 3076
VSA_NAMES = {
    (CISCO, 1): "Cisco-AVPair",
    (CISCO_VPN3000, 25): "ASA-Group-Policy",
    (CISCO_VPN3000, 146): "ASA-Tunnel-Group-Name",
    (CISCO_VPN3000, 150): "ASA-Client-Type",
    (CISCO_VPN3000, 151): "ASA-Session-Type",
}
TEXT_ATTRS = {1, 11, 18, 30, 31, 32, 66}
INT_ATTRS = {5, 6, 27, 28, 61}
IP_ATTRS = {4, 8}


@dataclass
class AsaProfile:
    nas_ip: str = "0.0.0.0"
    tunnel_group: str = "RADIUS-TEST"
    client_ip: str = "0.0.0.0"
    called_station: str = "0.0.0.0"
    nas_port: int = 1


@dataclass
class Reply:
    code: str
    elapsed_ms: int
    attributes: list[tuple[str, str]] = field(default_factory=list)
    reply_message: str = ""
    state: bytes | None = None
    signature_ok: bool | None = None
    detail: str = ""


def _attr(t: int, v: bytes) -> bytes:
    if len(v) > 253:
        raise ValueError(f"attribute {t} too long ({len(v)} bytes)")
    return struct.pack("!BB", t, len(v) + 2) + v


def _vsa(vendor: int, vtype: int, v: bytes) -> bytes:
    sub = struct.pack("!BB", vtype, len(v) + 2) + v
    return _attr(VENDOR_SPECIFIC, struct.pack("!I", vendor) + sub)


def _int(v: int) -> bytes:
    return struct.pack("!I", v)


def _ip(v: str) -> bytes:
    return ipaddress.IPv4Address(v).packed


def _hide_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    p = password or b"\x00"
    p += b"\x00" * (-len(p) % 16)
    out, prev = b"", authenticator
    for i in range(0, len(p), 16):
        b = hashlib.md5(secret + prev).digest()
        c = bytes(x ^ y for x, y in zip(p[i:i + 16], b))
        out += c
        prev = c
    return out


def build_request(username: str, password: str, secret: bytes, profile: AsaProfile,
                  state: bytes | None = None) -> tuple[int, bytes, bytes]:
    ident = os.urandom(1)[0]
    authenticator = os.urandom(16)
    attrs = [
        _attr(MESSAGE_AUTHENTICATOR, b"\x00" * 16),
        _attr(USER_NAME, username.encode()),
        _attr(USER_PASSWORD, _hide_password(password.encode(), secret, authenticator)),
        _attr(NAS_PORT, _int(profile.nas_port)),
        _attr(SERVICE_TYPE, _int(2)),
        _attr(CALLED_STATION_ID, profile.called_station.encode()),
        _attr(CALLING_STATION_ID, profile.client_ip.encode()),
        _attr(NAS_PORT_TYPE, _int(5)),
        _attr(TUNNEL_CLIENT_ENDPOINT, profile.client_ip.encode()),
        _attr(NAS_IP_ADDRESS, _ip(profile.nas_ip)),
        _vsa(CISCO, 1, f"ip:source-ip={profile.client_ip}".encode()),
        _vsa(CISCO_VPN3000, 146, profile.tunnel_group.encode()),
        _vsa(CISCO_VPN3000, 150, _int(2)),
    ]
    if state is not None:
        attrs.append(_attr(STATE, state))
    body = b"".join(attrs)
    length = 20 + len(body)
    packet = struct.pack("!BBH", ACCESS_REQUEST, ident, length) + authenticator + body
    ma = hmac.new(secret, packet, hashlib.md5).digest()
    packet = packet[:22] + ma + packet[38:]
    return ident, authenticator, packet


def _ma_offset(data: bytes) -> int | None:
    i = 0
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        if ln < 2:
            return None
        if t == MESSAGE_AUTHENTICATOR and ln == 18:
            return i + 2
        i += ln
    return None


def describe_request(username: str, profile: AsaProfile, state: bool = False) -> list[tuple[str, str]]:
    rows = [
        ("Message-Authenticator", "HMAC-MD5 over the packet with the shared secret"),
        ("User-Name", username),
        ("User-Password", "(PAP — hidden with the shared secret, never shown)"),
        ("NAS-Port", str(profile.nas_port)),
        ("Service-Type", "2 (Framed)"),
        ("Called-Station-Id", profile.called_station),
        ("Calling-Station-Id", profile.client_ip),
        ("NAS-Port-Type", "5 (Virtual)"),
        ("Tunnel-Client-Endpoint", profile.client_ip),
        ("NAS-IP-Address", profile.nas_ip),
        ("Cisco-AVPair", f"ip:source-ip={profile.client_ip}"),
        ("ASA-Tunnel-Group-Name", profile.tunnel_group),
        ("ASA-Client-Type", "2 (the VPN client Client SSL VPN)"),
    ]
    if state:
        rows.append(("State", "(from the previous Access-Challenge)"))
    return rows


def _decode(data: bytes) -> list[tuple[int, int | None, bytes]]:
    out, i = [], 0
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        if ln < 2 or i + ln > len(data):
            break
        v = data[i + 2:i + ln]
        if t == VENDOR_SPECIFIC and len(v) >= 6:
            vendor = struct.unpack("!I", v[:4])[0]
            j = 4
            while j + 2 <= len(v):
                vt, vl = v[j], v[j + 1]
                if vl < 2:
                    break
                out.append((vendor, vt, v[j + 2:j + vl]))
                j += vl
        else:
            out.append((t, None, v))
        i += ln
    return out


def _render(t: int, sub: int | None, v: bytes) -> tuple[str, str]:
    if sub is not None:
        name = VSA_NAMES.get((t, sub), f"Vendor-{t}-{sub}")
        text = v.decode(errors="replace")
        if text.isprintable():
            return name, text
        return name, str(struct.unpack("!I", v)[0]) if len(v) == 4 else v.hex()
    name = ATTR_NAMES.get(t, f"Attr-{t}")
    if t in TEXT_ATTRS:
        return name, v.decode(errors="replace")
    if t in INT_ATTRS and len(v) == 4:
        return name, str(struct.unpack("!I", v)[0])
    if t in IP_ATTRS and len(v) == 4:
        return name, str(ipaddress.IPv4Address(v))
    if t == CLASS:
        text = v.decode(errors="replace")
        return name, text if text.isprintable() else v.hex()
    return name, v.hex()


def send(host: str, port: int, secret: str, username: str, password: str,
         profile: AsaProfile | None = None, state: bytes | None = None,
         timeout: float = 60.0) -> Reply:
    profile = profile or AsaProfile()
    key = secret.encode()
    ident, req_auth, packet = build_request(username, password, key, profile, state)
    t0 = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(packet)
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                return Reply("NO_REPLY", int((time.monotonic() - t0) * 1000),
                             detail=f"no reply from {host}:{port} in {timeout:.0f}s")
            if len(data) >= 20 and data[1] == ident:
                break
    elapsed = int((time.monotonic() - t0) * 1000)

    code, _, length = struct.unpack("!BBH", data[:4])
    data = data[:length]
    resp_auth, attrs = data[4:20], data[20:]
    expected = hashlib.md5(data[:4] + req_auth + attrs + key).digest()
    sig_ok = hmac.compare_digest(expected, resp_auth)

    decoded = _decode(attrs)
    off = _ma_offset(attrs)
    if off is not None and sig_ok:
        zeroed = attrs[:off] + b"\x00" * 16 + attrs[off + 16:]
        calc = hmac.new(key, data[:4] + req_auth + zeroed, hashlib.md5).digest()
        sig_ok = hmac.compare_digest(calc, attrs[off:off + 16])

    rendered = [_render(t, sub, v) for t, sub, v in decoded
                if not (t == MESSAGE_AUTHENTICATOR and sub is None)]
    state_val = next((v for t, sub, v in decoded if t == STATE and sub is None), None)
    reply_msg = "\n".join(v for n, v in rendered if n == "Reply-Message")
    name = CODES.get(code, f"CODE_{code}")
    if not sig_ok:
        return Reply("BAD_SIGNATURE", elapsed, rendered, reply_msg, state_val, False,
                     detail=f"reply ({name}) does not verify with this shared secret — "
                            "the key here and the key in Okta differ")
    return Reply(name, elapsed, rendered, reply_msg, state_val, True)
