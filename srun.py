#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SRUN_B64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
DEFAULT_ACID = "1"


def hmac_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def srun_base64(text):
    if not text:
        return text
    out = []
    data = [ord(ch) for ch in text]
    end = len(data) - len(data) % 3
    for i in range(0, end, 3):
        value = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(SRUN_B64_ALPHABET[value >> 18])
        out.append(SRUN_B64_ALPHABET[(value >> 12) & 63])
        out.append(SRUN_B64_ALPHABET[(value >> 6) & 63])
        out.append(SRUN_B64_ALPHABET[value & 63])
    rest = len(data) - end
    if rest == 1:
        value = data[end] << 16
        out.append(SRUN_B64_ALPHABET[value >> 18])
        out.append(SRUN_B64_ALPHABET[(value >> 12) & 63])
        out.append("=")
        out.append("=")
    elif rest == 2:
        value = (data[end] << 16) | (data[end + 1] << 8)
        out.append(SRUN_B64_ALPHABET[value >> 18])
        out.append(SRUN_B64_ALPHABET[(value >> 12) & 63])
        out.append(SRUN_B64_ALPHABET[(value >> 6) & 63])
        out.append("=")
    return "".join(out)


def _sencode(text, include_length):
    values = []
    for i in range(0, len(text), 4):
        value = 0
        for j in range(4):
            if i + j < len(text):
                value |= ord(text[i + j]) << (8 * j)
        values.append(value)
    if include_length:
        values.append(len(text))
    return values


def _lencode(values, include_length):
    length = len(values)
    byte_len = (length - 1) << 2
    if include_length:
        marker = values[-1]
        if marker < byte_len - 3 or marker > byte_len:
            return ""
        byte_len = marker
    chars = []
    for value in values:
        chars.extend(chr((value >> (8 * shift)) & 0xff) for shift in range(4))
    result = "".join(chars)
    return result[:byte_len] if include_length else result


def xencode(text, key):
    if not text:
        return ""
    values = _sencode(text, True)
    keys = _sencode(key, False)
    if len(keys) < 4:
        keys.extend([0] * (4 - len(keys)))
    n = len(values) - 1
    z = values[n]
    y = values[0]
    c = 0x86014019 | 0x183639A0
    d = 0
    q = 6 + 52 // (n + 1)
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        for p in range(n):
            y = values[p + 1]
            m = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
            m += keys[(p & 3) ^ e] ^ z
            values[p] = (values[p] + m) & 0xFFFFFFFF
            z = values[p]
        p = n
        y = values[0]
        m = ((z >> 5) ^ (y << 2)) + (((y >> 3) ^ (z << 4)) ^ (d ^ y))
        m += keys[(p & 3) ^ e] ^ z
        values[n] = (values[n] + m) & 0xFFFFFFFF
        z = values[n]
        q -= 1
    return _lencode(values, False)


def build_info_json(username, password, ip, acid, enc_ver):
    return json.dumps(
        {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": str(acid),
            "enc_ver": enc_ver,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def build_login_params(username, password, ip, acid, token, n, vtype, enc_ver, action="login"):
    md5 = hmac_md5("", token)
    info_json = build_info_json(username, password, ip, acid, enc_ver)
    info = "{SRBX1}" + srun_base64(xencode(info_json, token))
    checksum = hashlib.sha1(
        (
            token + username
            + token + md5
            + token + str(acid)
            + token + ip
            + token + str(n)
            + token + str(vtype)
            + token + info
        ).encode()
    ).hexdigest()
    return {
        "callback": "jsonp_srun_login",
        "action": action,
        "username": username,
        "password": "{MD5}" + md5,
        "ac_id": str(acid),
        "ip": ip,
        "info": info,
        "chksum": checksum,
        "n": str(n),
        "type": str(vtype),
    }


def parse_jsonp(text):
    body = text.strip()
    if body.startswith("{"):
        return json.loads(body)
    match = re.search(r"^[^(]*\((.*)\)\s*;?$", body, re.S)
    if not match:
        raise ValueError("response is neither JSON nor JSONP")
    return json.loads(match.group(1))


def extract_ip(html):
    patterns = [
        r'id=["\']user_ip["\']\s+value=["\']([^"\']+)["\']',
        r'ip\s*:\s*["\']([^"\']+)["\']\s*,\s*nas\s*:\s*["\']["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.S)
        if match:
            return match.group(1)
    raise ValueError("could not extract IP from portal page; pass --ip")


def extract_acid(html):
    match = re.search(r'acid\s*:\s*["\']([^"\']+)["\']', html)
    if not match:
        raise ValueError("could not extract acid from portal page; pass --acid")
    return match.group(1)


def response_message(data):
    for key in ("suc_msg", "error_msg", "ploy_msg", "error", "res"):
        value = data.get(key)
        if value:
            return str(value)
    return json.dumps(data, ensure_ascii=False)


def online_status(data):
    error = str(data.get("error", "")).lower()
    if error == "ok" or data.get("online_ip"):
        user = data.get("user_name") or data.get("username") or "unknown"
        ip = data.get("online_ip") or data.get("ip") or "unknown-ip"
        return True, f"online: {user} @ {ip}"
    reason = data.get("error_msg") or data.get("error") or data.get("res") or "not online"
    return False, f"offline: {reason}"


class HttpError(RuntimeError):
    pass


class UrllibHttp:
    def __init__(self, timeout=10, debug=False):
        self.timeout = timeout
        self.debug = debug

    def get_text(self, url, params=None):
        query = urllib.parse.urlencode(params or {})
        full_url = url + ("?" + query if query else "")
        request = urllib.request.Request(
            full_url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 SRunLogin/1.0"
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            snippet = exc.read(300).decode("utf-8", "replace")
            raise HttpError(f"HTTP {exc.code} for {url}: {snippet}") from exc
        except urllib.error.URLError as exc:
            raise HttpError(f"request failed for {url}: {exc}") from exc


def portal_base(protocol, host):
    return f"{protocol}://{host.rstrip('/')}"


def normalize_portal_path(path):
    if not path:
        return ""
    return path if path.startswith("/") else "/" + path


def portal_candidate_paths(acid, portal_path=""):
    if portal_path:
        return [normalize_portal_path(portal_path)]
    candidate_acid = DEFAULT_ACID if acid == "auto" else str(acid)
    return [
        "/srun_portal_pc.php",
        f"/srun_portal_pc?ac_id={urllib.parse.quote(candidate_acid)}&theme=bit",
        "/index.html",
        "/",
    ]


def fetch_portal_page(http, protocol, host, acid="auto", portal_path=""):
    base = portal_base(protocol, host)
    errors = []
    for path in portal_candidate_paths(acid, portal_path):
        url = base + path
        try:
            return url, http.get_text(url)
        except HttpError as exc:
            errors.append(str(exc))
    detail = "; ".join(errors[-2:]) if errors else "no portal candidates configured"
    raise HttpError(f"could not reach portal page on {base}: {detail}")


def redact_params(params):
    redacted = dict(params)
    if "password" in redacted:
        redacted["password"] = "<redacted>"
    return redacted


def resolve_portal_context(http, protocol, host, ip, acid, portal_path=""):
    _, page = fetch_portal_page(http, protocol, host, acid, portal_path)
    resolved_ip = ip or extract_ip(page)
    if acid == "auto":
        try:
            resolved_acid = extract_acid(page)
        except ValueError:
            resolved_acid = DEFAULT_ACID
    else:
        resolved_acid = str(acid)
    return resolved_ip, resolved_acid


def get_challenge(http, protocol, host, username, ip):
    text = http.get_text(
        portal_base(protocol, host) + "/cgi-bin/get_challenge",
        {"callback": "jsonp_srun_challenge", "username": username, "ip": ip},
    )
    data = parse_jsonp(text)
    token = data.get("challenge")
    if not token:
        raise ValueError(f"challenge token missing: {text[:200]}")
    return token


def get_online_info(http, protocol, host):
    text = http.get_text(
        portal_base(protocol, host) + "/cgi-bin/rad_user_info",
        {"callback": "jsonp_srun_info"},
    )
    return parse_jsonp(text)


def login(http, protocol, host, username, password, ip, acid, n, vtype, enc_ver, portal_path=""):
    resolved_ip, resolved_acid = resolve_portal_context(http, protocol, host, ip, acid, portal_path)
    token = get_challenge(http, protocol, host, username, resolved_ip)
    params = build_login_params(
        username=username,
        password=password,
        ip=resolved_ip,
        acid=resolved_acid,
        token=token,
        n=n,
        vtype=vtype,
        enc_ver=enc_ver,
        action="login",
    )
    text = http.get_text(portal_base(protocol, host) + "/cgi-bin/srun_portal", params)
    data = parse_jsonp(text)
    return {"data": data, "message": response_message(data), "params": redact_params(params)}


def logout(http, protocol, host, username, ip, acid):
    params = {"callback": "jsonp_srun_logout", "action": "logout", "username": username}
    if ip:
        params["ip"] = ip
    if acid != "auto":
        params["ac_id"] = str(acid)
    text = http.get_text(portal_base(protocol, host) + "/cgi-bin/srun_portal", params)
    data = parse_jsonp(text)
    return {"data": data, "message": response_message(data), "params": redact_params(params)}


def check(http, protocol, host, acid="auto", portal_path=""):
    try:
        data = get_online_info(http, protocol, host)
    except (HttpError, ValueError):
        url, text = fetch_portal_page(http, protocol, host, acid, portal_path)
        return {"message": "online status unavailable; portal reachable", "url": url, "snippet": text[:300]}
    online, message = online_status(data)
    return {"message": message, "online": online, "data": data}


def default_config():
    return {
        "protocol": "http",
        "host": "10.0.0.55",
        "username": "",
        "password": "",
        "acid": "auto",
        "portal_path": "",
        "ip": "",
        "n": "200",
        "type": "1",
        "enc_ver": "srun_bx1",
        "test_url": "http://www.baidu.com/",
    }


ENV_MAP = {
    "SRUN_HOST": "host",
    "SRUN_USERNAME": "username",
    "SRUN_PASSWORD": "password",
    "SRUN_ACID": "acid",
    "SRUN_PORTAL_PATH": "portal_path",
    "SRUN_IP": "ip",
}


def merge_settings(config, env, args):
    settings = default_config()
    settings.update({k: v for k, v in config.items() if v not in (None, "")})
    for env_key, setting_key in ENV_MAP.items():
        if env.get(env_key):
            settings[setting_key] = env[env_key]
    for key, value in args.items():
        if value not in (None, ""):
            settings[key] = value
    return settings


def load_config(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_default_config(path):
    expanded = os.path.expanduser(path)
    os.makedirs(os.path.dirname(expanded), exist_ok=True)
    with open(expanded, "w", encoding="utf-8") as fh:
        json.dump(default_config(), fh, indent=2, ensure_ascii=False)


def add_common_options(parser, include_config=False):
    if include_config:
        parser.add_argument("--config", "-c", default="~/.config/srun-login/config.json")
    parser.add_argument("--protocol", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--username", "-u", default=None)
    parser.add_argument("--password", "-p", default=None)
    parser.add_argument("--acid", default=None)
    parser.add_argument("--portal-path", default=None)
    parser.add_argument("--ip", default=None)
    parser.add_argument("--n", default=None)
    parser.add_argument("--type", dest="vtype", default=None)
    parser.add_argument("--enc-ver", default=None)
    parser.add_argument("--debug", action="store_true")


def build_parser():
    parser = argparse.ArgumentParser(description="Linux SRun4K login helper")
    add_common_options(parser, include_config=True)
    sub = parser.add_subparsers(dest="command", required=True)
    add_common_options(sub.add_parser("login"))
    add_common_options(sub.add_parser("check"))
    add_common_options(sub.add_parser("logout"))
    keepalive_parser = sub.add_parser("keepalive")
    add_common_options(keepalive_parser)
    keepalive_parser.add_argument("--interval", type=int, default=300)
    keepalive_parser.add_argument("--test-url", default=None)
    sub.add_parser("init-config")
    return parser


def require_value(settings, key):
    if not settings.get(key):
        raise SystemExit(f"missing required value: {key}")
    return settings[key]


def http_connectivity_check(test_url, timeout=10):
    try:
        with urllib.request.urlopen(test_url, timeout=timeout) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def run_keepalive(http, settings, interval, test_url):
    while True:
        if not http_connectivity_check(test_url):
            result = login(
                http=http,
                protocol=settings["protocol"],
                host=settings["host"],
                username=require_value(settings, "username"),
                password=require_value(settings, "password"),
                ip=settings.get("ip") or None,
                acid=settings["acid"],
                portal_path=settings.get("portal_path") or "",
                n=settings["n"],
                vtype=settings["type"],
                enc_ver=settings["enc_ver"],
            )
            print(result["message"])
        time.sleep(interval)


def main(argv=None):
    parser = build_parser()
    ns = parser.parse_args(argv)
    config_path = os.path.expanduser(ns.config)
    if ns.command == "init-config":
        save_default_config(config_path)
        print(f"created {config_path}")
        return 0
    arg_settings = {
        "protocol": ns.protocol,
        "host": ns.host,
        "username": ns.username,
        "password": ns.password,
        "acid": ns.acid,
        "portal_path": ns.portal_path,
        "ip": ns.ip,
        "n": ns.n,
        "type": ns.vtype,
        "enc_ver": ns.enc_ver,
    }
    settings = merge_settings(load_config(config_path), os.environ, arg_settings)
    http = UrllibHttp(debug=ns.debug)
    if ns.command == "login":
        result = login(
            http=http,
            protocol=settings["protocol"],
            host=settings["host"],
            username=require_value(settings, "username"),
            password=require_value(settings, "password"),
            ip=settings.get("ip") or None,
            acid=settings["acid"],
            portal_path=settings.get("portal_path") or "",
            n=settings["n"],
            vtype=settings["type"],
            enc_ver=settings["enc_ver"],
        )
    elif ns.command == "logout":
        result = logout(
            http=http,
            protocol=settings["protocol"],
            host=settings["host"],
            username=require_value(settings, "username"),
            ip=settings.get("ip") or None,
            acid=settings["acid"],
        )
    elif ns.command == "check":
        result = check(
            http=http,
            protocol=settings["protocol"],
            host=settings["host"],
            acid=settings["acid"],
            portal_path=settings.get("portal_path") or "",
        )
    elif ns.command == "keepalive":
        run_keepalive(http, settings, ns.interval, ns.test_url or settings["test_url"])
        return 0
    else:
        parser.error(f"unknown command {ns.command}")
    print(result["message"])
    if ns.debug:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HttpError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
