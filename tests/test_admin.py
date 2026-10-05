"""Tests for minivpn-admin (no root needed). Run: python3 -m unittest tests/test_admin.py"""

import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "minivpn")
LICENSE_TOOL = os.path.join(ROOT, "tools", "license-tool")
VENDOR_KEY = os.path.join(ROOT, "vendor", "license-signing.key")

loader = importlib.machinery.SourceFileLoader("minivpn_admin", os.path.join(ROOT, "admin", "minivpn-admin"))
spec = importlib.util.spec_from_loader("minivpn_admin", loader)
ma = importlib.util.module_from_spec(spec)
loader.exec_module(ma)

PASSWORD = "correct horse battery"


class AdminTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.etc = self.tmp.name
        env = mock.patch.dict(os.environ, {"MINIVPN_BIN": BIN})
        env.start()
        self.addCleanup(env.stop)
        with mock.patch("sys.stdin", io.StringIO(PASSWORD + "\n")), mock.patch("sys.stdout", io.StringIO()):
            rc = ma.main(["--etc", self.etc, "init", "--endpoint", "vpn.example.com", "--user", "",
                          "--subnet", "10.20.0.0/24", "--password-stdin"])
        self.assertEqual(rc, 0)
        # Point the control socket somewhere that doesn't exist: "server not running".
        with open(os.path.join(self.etc, "server.conf"), "a") as f:
            f.write(f"control_socket = {self.etc}/no-server.sock\n")
        self.inst = ma.Install(self.etc)
        self.admin = ma.Admin(self.inst, "test")

    def tearDown(self):
        self.tmp.cleanup()


class DeviceTests(AdminTestCase):
    def test_add_assigns_addresses_and_writes_config(self):
        d1, cfg1, note = self.admin.add_device("alice-laptop")
        d2, _, _ = self.admin.add_device("bob-phone")
        self.assertEqual((d1.ip, d2.ip), ("10.20.0.2", "10.20.0.3"))
        self.assertIn("not running", note)
        self.assertIn("server = vpn.example.com:51900", cfg1)
        self.assertIn(f"device_id = {d1.id}", cfg1)
        self.assertIn(f"key = {d1.key}", cfg1)
        self.assertRegex(d1.id, r"^[0-9a-f]{32}$")
        self.assertRegex(d1.key, r"^[0-9a-f]{64}$")
        self.assertNotEqual(d1.key, d2.key)
        mode = os.stat(self.inst.devices_path).st_mode & 0o777
        self.assertEqual(mode, 0o640)

    def test_fixed_ip_and_validation(self):
        d, _, _ = self.admin.add_device("printer", "10.20.0.50")
        self.assertEqual(d.ip, "10.20.0.50")
        for bad in ("10.20.0.50", "10.20.0.1", "10.20.0.255", "10.99.0.5", "nonsense"):
            with self.assertRaises(ma.AdminError):
                self.admin.add_device("x" + str(abs(hash(bad)) % 1000), bad)
        with self.assertRaises(ma.AdminError):
            self.admin.add_device("printer")  # duplicate name
        for bad_name in ("", "has space", "a" * 33, "semi;colon"):
            with self.assertRaises(ma.AdminError):
                self.admin.add_device(bad_name)

    def test_disable_enable_revoke(self):
        self.admin.add_device("alice")
        self.admin.set_status("alice", "disabled")
        self.assertEqual(self.inst.load_devices()[0].status, "disabled")
        self.admin.set_status("alice", "active")
        self.assertEqual(self.inst.load_devices()[0].status, "active")
        self.admin.revoke("alice")
        self.assertEqual(self.inst.load_devices(), [])
        with self.assertRaises(ma.AdminError):
            self.admin.revoke("alice")

    def test_revoked_address_is_reused(self):
        self.admin.add_device("a")
        self.admin.add_device("b")
        self.admin.revoke("a")
        d, _, _ = self.admin.add_device("c")
        self.assertEqual(d.ip, "10.20.0.2")

    def test_community_limit(self):
        for i in range(ma.COMMUNITY_LIMIT):
            self.admin.add_device(f"dev{i}")
        with self.assertRaisesRegex(ma.AdminError, "Community edition"):
            self.admin.add_device("one-too-many")
        self.admin.set_status("dev0", "disabled")  # frees a slot
        self.admin.add_device("replacement")
        with self.assertRaises(ma.AdminError):
            self.admin.set_status("dev0", "active")  # would exceed the limit again

    def test_audit_trail(self):
        self.admin.add_device("alice")
        self.admin.set_status("alice", "disabled")
        self.admin.revoke("alice")
        actions = [e["action"] for e in self.admin.audit_tail()]
        self.assertEqual(actions, ["revoke", "disable", "add"])

    def test_registry_is_readable_by_the_daemon_parser(self):
        """The file the admin writes must be exactly what the C server loads."""
        self.admin.add_device("alice")
        out = subprocess.run([BIN, "license-info", "--license", "/nonexistent"], capture_output=True, text=True)
        self.assertEqual(json.loads(out.stdout)["max_devices"], ma.COMMUNITY_LIMIT)
        line = [l for l in open(self.inst.devices_path) if not l.startswith("#")][0].split()
        self.assertEqual(len(line), 6)
        self.assertEqual(line[3], "active")


class LicenseTests(AdminTestCase):
    def test_garbage_and_forged_licenses_are_rejected(self):
        with self.assertRaisesRegex(ma.AdminError, "not installed"):
            self.admin.install_license("hello world\n")
        forged = ("customer = Mallory\nedition = business\nmax_devices = 9999\nissued = 2026-01-01\n"
                  "expires = 2099-01-01\nlicense_id = LIC-x\nsignature = " + "00" * 64 + "\n")
        with self.assertRaisesRegex(ma.AdminError, "signature"):
            self.admin.install_license(forged)
        self.assertFalse(os.path.exists(self.inst.license_path))

    @unittest.skipUnless(os.path.exists(LICENSE_TOOL) and os.path.exists(VENDOR_KEY), "needs vendor key")
    def test_valid_license_raises_the_limit(self):
        lic = subprocess.run([LICENSE_TOOL, "sign", "--customer", "Acme Corp", "--devices", "8",
                              "--key", VENDOR_KEY], capture_output=True, text=True, check=True, cwd=ROOT).stdout
        info, _ = self.admin.install_license(lic)
        self.assertEqual(info["status"], "valid")
        self.assertEqual(info["max_devices"], 8)
        for i in range(8):
            self.admin.add_device(f"dev{i}")
        with self.assertRaisesRegex(ma.AdminError, "license allows 8"):
            self.admin.add_device("dev8")
        tampered = lic.replace("max_devices = 8", "max_devices = 80")
        with self.assertRaises(ma.AdminError):
            self.admin.install_license(tampered)


class PasswordTests(unittest.TestCase):
    def test_hash_roundtrip(self):
        h = ma.hash_password("s3cret-passphrase")
        self.assertTrue(h.startswith("pbkdf2_sha256$"))
        self.assertTrue(ma.verify_password("s3cret-passphrase", h))
        self.assertFalse(ma.verify_password("wrong", h))
        self.assertFalse(ma.verify_password("x", "garbage"))
        self.assertNotEqual(h, ma.hash_password("s3cret-passphrase"))  # salted


class WebTests(AdminTestCase):
    def setUp(self):
        super().setUp()
        self.state = ma.WebState(self.inst, secure_cookie=False, quiet=True)
        self.httpd = ma.http.server.ThreadingHTTPServer(("127.0.0.1", 0), ma.make_handler(self.state))
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r, data

    def login(self, password=PASSWORD):
        return self.request("POST", "/login", f"username=admin&password={password}",
                            {"Content-Type": "application/x-www-form-urlencoded"})

    def session(self):
        r, _ = self.login()
        self.assertEqual(r.status, 303)
        cookie = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        token = cookie.split(";")[0]
        r, page = self.request("GET", "/", headers={"Cookie": token})
        csrf = re.search(rb'name="csrf" content="([^"]+)"', page).group(1).decode()
        return token, csrf

    def test_login_page_and_auth_required(self):
        r, page = self.request("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Sign in", page)
        self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        r, _ = self.request("GET", "/api/overview")
        self.assertEqual(r.status, 401)

    def test_wrong_password_and_lockout(self):
        for _ in range(ma.WebState.MAX_FAILURES):
            r, page = self.login("nope")
            self.assertEqual(r.status, 401)
            self.assertIn(b"Wrong username or password", page)
        r, page = self.login()  # even the right password is refused while locked out
        self.assertEqual(r.status, 401)
        self.assertIn(b"Too many failed attempts", page)

    def test_dashboard_flow(self):
        token, csrf = self.session()
        r, data = self.request("GET", "/api/overview", headers={"Cookie": token})
        self.assertEqual(r.status, 200)
        ov = json.loads(data)
        self.assertIsNone(ov["server"])
        self.assertEqual(ov["license"]["edition"], "community")

        hdrs = {"Cookie": token, "Content-Type": "application/json"}
        r, _ = self.request("POST", "/api/devices", json.dumps({"name": "web-dev"}), hdrs)
        self.assertEqual(r.status, 403)  # no CSRF token
        r, _ = self.request("POST", "/api/devices", json.dumps({"name": "web-dev"}),
                            {**hdrs, "X-CSRF-Token": "forged"})
        self.assertEqual(r.status, 403)
        r, _ = self.request("POST", "/api/devices", json.dumps({"name": "web-dev"}),
                            {**hdrs, "X-CSRF-Token": csrf, "Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)

        r, data = self.request("POST", "/api/devices", json.dumps({"name": "web-dev"}), {**hdrs, "X-CSRF-Token": csrf})
        self.assertEqual(r.status, 200, data)
        created = json.loads(data)
        self.assertIn("device_id = ", created["config"])

        r, data = self.request("GET", "/api/devices/web-dev/config", headers={"Cookie": token})
        self.assertEqual(r.status, 200)
        self.assertIn('filename="web-dev.conf"', r.getheader("Content-Disposition"))
        self.assertEqual(data.decode(), created["config"])

        r, data = self.request("POST", "/api/devices/web-dev/disable", "{}", {**hdrs, "X-CSRF-Token": csrf})
        self.assertEqual(r.status, 200)
        r, data = self.request("POST", "/api/devices/nobody/revoke", "{}", {**hdrs, "X-CSRF-Token": csrf})
        self.assertEqual(r.status, 400)
        self.assertIn(b"no device named", data)

        r, data = self.request("GET", "/api/overview", headers={"Cookie": token})
        ov = json.loads(data)
        self.assertEqual([d["status"] for d in ov["devices"]], ["disabled"])
        self.assertTrue(any(e["actor"].startswith("web:admin") for e in ov["audit"]))

        r, _ = self.request("POST", "/logout", "{}", {**hdrs, "X-CSRF-Token": csrf})
        self.assertEqual(r.status, 200)
        r, _ = self.request("GET", "/api/overview", headers={"Cookie": token})
        self.assertEqual(r.status, 401)


if __name__ == "__main__":
    unittest.main()
