import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "srun.py"


def load_srun():
    spec = importlib.util.spec_from_file_location("srun", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.srun = load_srun()

    def test_custom_base64_matches_reference_alphabet(self):
        self.assertEqual(self.srun.srun_base64("132456"), "9F9x0JHI")

    def test_hmac_md5_uses_empty_password_by_default(self):
        self.assertEqual(
            self.srun.hmac_md5("", "abc123"),
            "ecf123a3f89fd7bf95f57e1664627493",
        )

    def test_info_json_keeps_stable_order(self):
        info = self.srun.build_info_json(
            username="20260001",
            password="secret",
            ip="10.1.2.3",
            acid="8",
            enc_ver="srun_bx1",
        )
        self.assertEqual(
            info,
            '{"username":"20260001","password":"secret","ip":"10.1.2.3","acid":"8","enc_ver":"srun_bx1"}',
        )

    def test_xencode_matches_reference_vector_shape(self):
        encoded = self.srun.xencode(
            '{"username":"201626203044@cmcc","password":"15879684798qq","ip":"10.128.96.249","acid":"1","enc_ver":"srun_bx1"}',
            "e6843f26b8544327a3a25978dd3c5f89e6b745df1732993b88fe082c13a34cb9",
        )
        self.assertIsInstance(encoded, str)
        self.assertGreater(len(encoded), 20)
        self.assertEqual(
            self.srun.srun_base64(encoded)[:8],
            "13GwOQhj",
        )

    def test_build_login_params_uses_srun_field_family(self):
        params = self.srun.build_login_params(
            username="20260001",
            password="secret",
            ip="10.1.2.3",
            acid="8",
            token="abc123",
            n="200",
            vtype="1",
            enc_ver="srun_bx1",
            action="login",
        )
        self.assertEqual(params["action"], "login")
        self.assertEqual(params["username"], "20260001")
        self.assertEqual(params["ac_id"], "8")
        self.assertEqual(params["ip"], "10.1.2.3")
        self.assertEqual(params["n"], "200")
        self.assertEqual(params["type"], "1")
        self.assertTrue(params["password"].startswith("{MD5}"))
        self.assertTrue(params["info"].startswith("{SRBX1}"))
        self.assertRegex(params["chksum"], r"^[0-9a-f]{40}$")


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.srun = load_srun()

    def test_parse_jsonp_object(self):
        self.assertEqual(
            self.srun.parse_jsonp('jsonp123({"challenge":"tok","res":"ok"})'),
            {"challenge": "tok", "res": "ok"},
        )

    def test_parse_jsonp_falls_back_to_raw_json(self):
        self.assertEqual(
            self.srun.parse_jsonp('{"online":true,"username":"20260001"}'),
            {"online": True, "username": "20260001"},
        )

    def test_extract_ip_from_bit_html(self):
        html = '<input id="user_ip" value="10.1.2.3">'
        self.assertEqual(self.srun.extract_ip(html), "10.1.2.3")

    def test_extract_ip_from_js_html(self):
        html = 'ip: "10.2.3.4",\n nas: "",'
        self.assertEqual(self.srun.extract_ip(html), "10.2.3.4")

    def test_extract_acid_from_js_html(self):
        self.assertEqual(self.srun.extract_acid('acid: "8",'), "8")

    def test_response_message_prefers_known_fields(self):
        self.assertEqual(
            self.srun.response_message({"error_msg": "failed", "res": "error"}),
            "failed",
        )


class FakeHttp:
    def __init__(self):
        self.calls = []

    def get_text(self, url, params=None):
        self.calls.append((url, params or {}))
        if url.endswith("/srun_portal_pc.php"):
            return '<input id="user_ip" value="10.1.2.3"><script>acid: "8",</script>'
        if url.endswith("/cgi-bin/get_challenge"):
            return 'jsonp_srun_challenge({"challenge":"abc123","res":"ok"})'
        if url.endswith("/cgi-bin/srun_portal"):
            return 'jsonp_srun_login({"suc_msg":"login ok","res":"ok"})'
        raise AssertionError(url)


class FallbackPortalHttp:
    def __init__(self, srun):
        self.srun = srun
        self.calls = []

    def get_text(self, url, params=None):
        self.calls.append((url, params or {}))
        if url.endswith("/srun_portal_pc.php"):
            raise self.srun.HttpError("HTTP 404 for portal")
        if url.endswith("/srun_portal_pc?ac_id=1&theme=bit"):
            return '<input id="user_ip" value="10.9.8.7"><script>acid: "1",</script>'
        raise AssertionError(url)


class PortalWithoutAcidHttp:
    def __init__(self):
        self.calls = []

    def get_text(self, url, params=None):
        self.calls.append((url, params or {}))
        return '<input id="user_ip" value="10.9.8.7">'


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.srun = load_srun()

    def test_login_flow_calls_expected_endpoints(self):
        http = FakeHttp()
        result = self.srun.login(
            http=http,
            protocol="http",
            host="10.0.0.55",
            username="20260001",
            password="secret",
            ip=None,
            acid="auto",
            n="200",
            vtype="1",
            enc_ver="srun_bx1",
        )
        self.assertEqual(result["message"], "login ok")
        self.assertEqual(http.calls[0][0], "http://10.0.0.55/srun_portal_pc.php")
        self.assertEqual(http.calls[1][0], "http://10.0.0.55/cgi-bin/get_challenge")
        self.assertEqual(http.calls[1][1]["username"], "20260001")
        self.assertEqual(http.calls[1][1]["ip"], "10.1.2.3")
        self.assertEqual(http.calls[2][1]["action"], "login")
        self.assertEqual(http.calls[2][1]["ac_id"], "8")

    def test_resolve_portal_context_falls_back_to_bit_entrypoint(self):
        http = FallbackPortalHttp(self.srun)
        ip, acid = self.srun.resolve_portal_context(
            http=http,
            protocol="http",
            host="10.0.0.55",
            ip=None,
            acid="auto",
            portal_path="",
        )
        self.assertEqual(ip, "10.9.8.7")
        self.assertEqual(acid, "1")
        self.assertEqual(http.calls[0][0], "http://10.0.0.55/srun_portal_pc.php")
        self.assertEqual(http.calls[1][0], "http://10.0.0.55/srun_portal_pc?ac_id=1&theme=bit")

    def test_auto_acid_defaults_to_bit_acid_when_portal_omits_it(self):
        http = PortalWithoutAcidHttp()
        ip, acid = self.srun.resolve_portal_context(
            http=http,
            protocol="http",
            host="10.0.0.55",
            ip=None,
            acid="auto",
            portal_path="",
        )
        self.assertEqual(ip, "10.9.8.7")
        self.assertEqual(acid, "1")

    def test_check_uses_first_reachable_portal_candidate(self):
        http = FallbackPortalHttp(self.srun)
        result = self.srun.check(
            http=http,
            protocol="http",
            host="10.0.0.55",
            acid="auto",
            portal_path="",
        )
        self.assertEqual(result["message"], "portal reachable")
        self.assertEqual(result["url"], "http://10.0.0.55/srun_portal_pc?ac_id=1&theme=bit")

    def test_redact_hides_password_values(self):
        redacted = self.srun.redact_params({"password": "secret", "username": "20260001"})
        self.assertEqual(redacted["password"], "<redacted>")
        self.assertEqual(redacted["username"], "20260001")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.srun = load_srun()

    def test_merge_config_env_args_precedence(self):
        merged = self.srun.merge_settings(
            config={"host": "config-host", "username": "config-user"},
            env={"SRUN_HOST": "env-host"},
            args={"host": "arg-host", "username": None},
        )
        self.assertEqual(merged["host"], "arg-host")
        self.assertEqual(merged["username"], "config-user")

    def test_default_config_template_has_empty_password(self):
        template = self.srun.default_config()
        self.assertEqual(template["host"], "10.0.0.55")
        self.assertEqual(template["password"], "")

    def test_command_options_can_follow_subcommand(self):
        parser = self.srun.build_parser()
        ns = parser.parse_args([
            "login",
            "-u",
            "20260001",
            "-p",
            "secret",
            "--host",
            "10.0.0.55",
        ])
        self.assertEqual(ns.command, "login")
        self.assertEqual(ns.username, "20260001")
        self.assertEqual(ns.password, "secret")
        self.assertEqual(ns.host, "10.0.0.55")

    def test_command_accepts_portal_path_override(self):
        parser = self.srun.build_parser()
        ns = parser.parse_args(["login", "--portal-path", "/srun_portal_pc?ac_id=8&theme=bit"])
        self.assertEqual(ns.portal_path, "/srun_portal_pc?ac_id=8&theme=bit")
