"""Unit tests for Pi-hole local DNS fetch (mocked HTTP — no live Pi-hole)."""

from __future__ import annotations

import hashlib
import unittest

import httpx

from app.config import PiHoleConfig
from app.pihole import _fetch_v5, _fetch_v6, _loads_pihole_json, fetch_pihole_dns


def _transport(handler):
    return httpx.MockTransport(handler)


class TestPiHoleV5(unittest.TestCase):
    def test_customdns_requires_action_get(self):
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            q = dict(request.url.params)
            seen.append(q)
            if q.get("action") != "get":
                return httpx.Response(200, text="Wrong action")
            if "customdns" in q:
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            ["app.lab.local", "192.168.1.10"],
                            ["plex.lab.local", "192.168.1.10"],
                        ]
                    },
                )
            if "customcname" in q:
                return httpx.Response(200, json={"data": []})
            return httpx.Response(404, text="nope")

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://192.168.1.50/admin", "tok")

        self.assertIsNone(err)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].hostname, "app.lab.local")
        self.assertEqual(records[0].target, "192.168.1.10")
        self.assertTrue(any(s.get("action") == "get" for s in seen))
        self.assertTrue(any("customdns" in s for s in seen))

    def test_auth_failure_is_clear(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Not authorized!")

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://pi.hole/admin", "bad")

        self.assertEqual(records, [])
        self.assertIn("auth failed", (err or "").lower())

    def test_bare_array_is_not_empty_success(self):
        """
        Wrong token / web < 5.11: api.php skips customdns and returns bare [].
        That must be ok=False, never a silent zero.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[])

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://pi.hole/admin", "badtok")

        self.assertEqual(records, [])
        self.assertIsNotNone(err)
        self.assertIn("bare []", err or "")
        self.assertIn("5.11", err or "")

    def test_empty_data_object_is_ok_not_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": []})

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://pi.hole/admin", "tok")

        self.assertEqual(records, [])
        self.assertIsNone(err)

    def test_trailing_empty_array_json_still_parses(self):
        # web 5.11 bug (pi-hole/web#2123)
        raw = '{"data":[["app.lab.local","192.168.1.10"]]}[]'
        data = _loads_pihole_json(raw)
        self.assertEqual(data["data"][0][0], "app.lab.local")

        def handler(request: httpx.Request) -> httpx.Response:
            q = dict(request.url.params)
            if "customdns" in q:
                return httpx.Response(200, text=raw)
            return httpx.Response(200, json={"data": []})

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://pi.hole/admin", "tok")

        self.assertIsNone(err)
        self.assertEqual(len(records), 1)

    def test_plaintext_password_hashed_as_token(self):
        password = "secret"
        inner = hashlib.sha256(password.encode()).hexdigest()
        expected = hashlib.sha256(inner.encode()).hexdigest()
        seen_auth: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            q = dict(request.url.params)
            auth = q.get("auth") or ""
            seen_auth.append(auth)
            if auth != expected:
                # Simulate Pi-hole fall-through on bad auth
                return httpx.Response(200, json=[])
            if "customdns" in q:
                return httpx.Response(
                    200, json={"data": [["nas.home", "10.0.0.5"]]}
                )
            return httpx.Response(200, json={"data": []})

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v5(client, "http://pi.hole/admin", password)

        self.assertIsNone(err)
        self.assertEqual(len(records), 1)
        self.assertIn(expected, seen_auth)


class TestPiHoleV6(unittest.TestCase):
    def test_hosts_and_cname(self):
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/api/auth") and request.method == "POST":
                return httpx.Response(
                    200,
                    json={
                        "session": {
                            "valid": True,
                            "sid": "abc=",
                            "csrf": "csrf=",
                        }
                    },
                )
            if path.endswith("/api/auth") and request.method == "DELETE":
                return httpx.Response(204)
            if path.endswith("/api/config/dns/hosts"):
                return httpx.Response(
                    200,
                    json={
                        "config": {
                            "dns": {
                                "hosts": [
                                    "192.168.1.10 app.lab.local",
                                    "192.168.1.10 plex.lab.local",
                                ]
                            }
                        }
                    },
                )
            if path.endswith("/api/config/dns/cnameRecords"):
                return httpx.Response(
                    200,
                    json={
                        "config": {
                            "dns": {
                                "cnameRecords": ["alias.lab.local,app.lab.local,300"]
                            }
                        }
                    },
                )
            return httpx.Response(404, json={"error": {"message": "not found"}})

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v6(client, "http://192.168.1.50", "secret")

        self.assertIsNone(err)
        hosts = {r.hostname for r in records}
        self.assertIn("app.lab.local", hosts)
        self.assertIn("plex.lab.local", hosts)
        self.assertIn("alias.lab.local", hosts)
        cname = next(r for r in records if r.kind == "cname")
        self.assertEqual(cname.target, "app.lab.local")

    def test_bad_password(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"session": {"valid": False, "sid": None}},
            )

        with httpx.Client(transport=_transport(handler)) as client:
            records, err = _fetch_v6(client, "http://192.168.1.50", "wrong")

        self.assertEqual(records, [])
        self.assertIn("auth failed", (err or "").lower())


class TestFetchIntegration(unittest.TestCase):
    def test_fetch_v5_end_to_end_via_mock(self):
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            # v6 probe — not present
            if "/api/" in path:
                return httpx.Response(404, text="Not Found")
            q = dict(request.url.params)
            if path.endswith("/api.php") and q.get("action") == "get":
                if "customdns" in q:
                    return httpx.Response(
                        200,
                        json={"data": [["nas.home", "10.0.0.5"]]},
                    )
                return httpx.Response(200, json={"data": []})
            return httpx.Response(404)

        transport = _transport(handler)
        real_client = httpx.Client

        def client_factory(*args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            return real_client(*args, verify=False, **kwargs)

        import app.pihole as ph

        orig = ph.httpx.Client
        ph.httpx.Client = client_factory  # type: ignore[misc]
        try:
            result = fetch_pihole_dns(
                PiHoleConfig(url="http://10.0.0.2", version="5"),
                token_override="abc",
                password_override="",
            )
        finally:
            ph.httpx.Client = orig  # type: ignore[misc]

        self.assertTrue(result.ok, result.message)
        self.assertEqual(result.version, "5")
        self.assertEqual(len(result.records), 1)
        self.assertIn("1 local", result.message or "")

    def test_fetch_v5_bare_array_fails_loudly(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "/api/" in request.url.path:
                return httpx.Response(404, text="Not Found")
            return httpx.Response(200, json=[])

        transport = _transport(handler)
        real_client = httpx.Client

        def client_factory(*args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            return real_client(*args, verify=False, **kwargs)

        import app.pihole as ph

        orig = ph.httpx.Client
        ph.httpx.Client = client_factory  # type: ignore[misc]
        try:
            result = fetch_pihole_dns(
                PiHoleConfig(url="http://10.0.0.2", version="5"),
                token_override="deadbeef",
                password_override="",
            )
        finally:
            ph.httpx.Client = orig  # type: ignore[misc]

        self.assertFalse(result.ok)
        self.assertEqual(result.records, [])
        self.assertIn("bare []", result.message or "")

    def test_auto_v6_ignores_leftover_v5_token(self):
        """v6 host + leftover v5 token must not hit customdns/customcname."""
        seen_v5 = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal seen_v5
            path = request.url.path
            if path.endswith("/api/info/version"):
                return httpx.Response(
                    200, json={"version": {"ftl": "6.0"}, "took": 0.01}
                )
            if path.endswith("/api/auth") and request.method == "POST":
                return httpx.Response(
                    200,
                    json={
                        "session": {
                            "valid": True,
                            "sid": "sid=",
                            "csrf": "csrf=",
                        }
                    },
                )
            if path.endswith("/api/auth") and request.method == "DELETE":
                return httpx.Response(204)
            if path.endswith("/api/config/dns/hosts"):
                return httpx.Response(
                    200,
                    json={
                        "config": {
                            "dns": {
                                "hosts": ["192.168.1.10 app.lab.local"],
                            }
                        }
                    },
                )
            if path.endswith("/api.php") or "customdns" in str(request.url):
                seen_v5 = True
                raise ConnectionRefusedError(111, "Connection refused")
            return httpx.Response(404)

        transport = _transport(handler)
        real_client = httpx.Client

        def client_factory(*args, **kwargs):
            kwargs["transport"] = transport
            kwargs.pop("verify", None)
            return real_client(*args, verify=False, **kwargs)

        import app.pihole as ph

        orig = ph.httpx.Client
        ph.httpx.Client = client_factory  # type: ignore[misc]
        try:
            result = fetch_pihole_dns(
                PiHoleConfig(url="http://192.168.1.52:8080/admin/", version="auto"),
                password_override="secret",
                token_override="leftover-v5-token",
            )
        finally:
            ph.httpx.Client = orig  # type: ignore[misc]

        self.assertTrue(result.ok, result.message)
        self.assertEqual(result.version, "6")
        self.assertEqual(len(result.records), 1)
        self.assertFalse(seen_v5, "must not call v5 customdns when v6 detected")


if __name__ == "__main__":
    unittest.main()
