"""Caddyfile placeholder extraction and {$VAR} expansion."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.caddy_routes import (
    expand_caddy_placeholders,
    extract_caddy_placeholders,
    normalize_caddy_env,
    parse_caddyfile,
    parse_env_text,
    read_caddyfile,
)


SAMPLE = """
login.jantz.me {
	tls {
		dns cloudflare dummy
		resolvers 1.1.1.1
	}
	reverse_proxy 192.168.1.50:9000
}

butterfly.jantz.me {
	reverse_proxy /api/* 192.168.1.50:3001
	reverse_proxy * 192.168.1.50:3232
}

cloud.{$MY_DOMAIN} {
	reverse_proxy 192.168.1.50:11000
}

crm.{$MY_DOMAIN} {
	reverse_proxy {$CRM_UPSTREAM}:3999
}

#git.{$MY_DOMAIN} {
#    reverse_proxy gitlab.example.com:8929
#}

other.{$OTHER_DOMAIN} {
	reverse_proxy {env.OTHER_UPSTREAM}
}
"""


class TestCaddyPlaceholders(unittest.TestCase):
    def test_extract_finds_every_live_name_once(self) -> None:
        found = extract_caddy_placeholders(SAMPLE)
        names = [p.name for p in found]
        self.assertEqual(
            names, ["MY_DOMAIN", "CRM_UPSTREAM", "OTHER_DOMAIN", "OTHER_UPSTREAM"]
        )
        self.assertNotIn("git", names)

    def test_extract_ignores_commented_sites_only_vars_still_shared(self) -> None:
        text = "# only.{$HIDDEN}\nlive.{$SHOWN} {\n  reverse_proxy 1.2.3.4:80\n}\n"
        names = [p.name for p in extract_caddy_placeholders(text)]
        self.assertEqual(names, ["SHOWN"])

    def test_expand_uses_defaults_when_unset(self) -> None:
        out = expand_caddy_placeholders("app.{$HOST:example.com}", {})
        self.assertEqual(out, "app.example.com")

    def test_expand_prefers_provided_value(self) -> None:
        out = expand_caddy_placeholders(
            "app.{$HOST:example.com}", {"HOST": "lab.local"}
        )
        self.assertEqual(out, "app.lab.local")

    def test_parse_without_env_skips_placeholder_hosts(self) -> None:
        routes = parse_caddyfile(SAMPLE)
        hosts = {r.hostname for r in routes}
        self.assertIn("login.jantz.me", hosts)
        self.assertIn("butterfly.jantz.me", hosts)
        self.assertNotIn("cloud", hosts)
        self.assertNotIn("crm", hosts)
        self.assertFalse(any("{$" in h for h in hosts))

    def test_parse_expands_all_provided_vars(self) -> None:
        routes = parse_caddyfile(
            SAMPLE,
            env={
                "MY_DOMAIN": "jantz.me",
                "CRM_UPSTREAM": "192.168.1.50",
                "OTHER_DOMAIN": "example.test",
                "OTHER_UPSTREAM": "10.0.0.9:8080",
            },
        )
        by_host = {r.hostname: r.upstream for r in routes}
        self.assertEqual(by_host["cloud.jantz.me"], "192.168.1.50:11000")
        self.assertEqual(by_host["crm.jantz.me"], "192.168.1.50:3999")
        self.assertEqual(by_host["other.example.test"], "10.0.0.9:8080")
        self.assertEqual(by_host["login.jantz.me"], "192.168.1.50:9000")

    def test_star_matcher_is_not_an_upstream(self) -> None:
        routes = parse_caddyfile(SAMPLE)
        butterfly = [r for r in routes if r.hostname == "butterfly.jantz.me"]
        ups = {r.upstream for r in butterfly}
        self.assertEqual(ups, {"192.168.1.50:3001", "192.168.1.50:3232"})
        self.assertNotIn("*", ups)

    def test_parse_env_text(self) -> None:
        env = parse_env_text(
            "TZ=America/Chicago\n"
            "DOCKER_MY_NETWORK=caddy_net\n"
            "MY_DOMAIN=jantz.me\n"
            "# comment\n"
            "export OTHER=foo\n"
        )
        self.assertEqual(
            env,
            {
                "TZ": "America/Chicago",
                "DOCKER_MY_NETWORK": "caddy_net",
                "MY_DOMAIN": "jantz.me",
                "OTHER": "foo",
            },
        )

    def test_normalize_skips_empty_and_bad_keys(self) -> None:
        env = normalize_caddy_env(
            {"MY_DOMAIN": "jantz.me", "BAD-KEY": "x", "EMPTY": "", 1: "n"}
        )
        self.assertEqual(env, {"MY_DOMAIN": "jantz.me"})

    def test_read_caddyfile_warns_when_vars_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "Caddyfile"
            path.write_text(SAMPLE, encoding="utf-8")
            routes, err = read_caddyfile(str(path), env={})
            self.assertTrue(routes)
            self.assertIsNotNone(err)
            self.assertIn("MY_DOMAIN", err or "")
            self.assertIn("OTHER_DOMAIN", err or "")

    def test_read_caddyfile_ok_when_vars_set(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "Caddyfile"
            path.write_text(SAMPLE, encoding="utf-8")
            routes, err = read_caddyfile(
                str(path),
                env={
                    "MY_DOMAIN": "jantz.me",
                    "CRM_UPSTREAM": "192.168.1.50",
                    "OTHER_DOMAIN": "example.test",
                    "OTHER_UPSTREAM": "10.0.0.9:8080",
                },
            )
            self.assertIsNone(err)
            hosts = {r.hostname for r in routes}
            self.assertIn("cloud.jantz.me", hosts)
            self.assertIn("crm.jantz.me", hosts)
            self.assertIn("other.example.test", hosts)


if __name__ == "__main__":
    unittest.main()
