"""Unit tests for DNS page inventory (Pi-hole + Caddy join)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from app.caddy_routes import ProxyRoute, RouteDiscoveryResult
from app.networking import (
    build_caddy_inventory,
    build_dns_inventory,
    hostname_to_container_via_proxy,
)
from app.pihole import DnsRecord, PiHoleResult


class TestDnsInventory(unittest.TestCase):
    def test_hostname_map_uses_proxy_entries_only(self) -> None:
        containers = [
            {
                "name": "grafana",
                "container_id": "abc123",
                "state": "exited",
                "networking": {
                    "mapped": True,
                    "entries": [
                        {
                            "hostname": "grafana.lab",
                            "upstream": "grafana:3000",
                            "source": "caddyfile",
                            "proxy": "caddy",
                            "in_dns": True,
                        }
                    ],
                },
                "pihole_hostnames": ["grafana.lab"],
            },
            {
                "name": "fuzzy-only",
                "container_id": "def456",
                "state": "running",
                "networking": {"mapped": False, "entries": []},
                "pihole_hostnames": ["other.lab"],
            },
        ]
        by_host = hostname_to_container_via_proxy(containers)
        self.assertIn("grafana.lab", by_host)
        self.assertEqual(by_host["grafana.lab"]["name"], "grafana")
        self.assertEqual(by_host["grafana.lab"]["state"], "exited")
        self.assertNotIn("other.lab", by_host)

    @patch("app.networking.collect_host_network_ips", return_value={"10.0.0.2"})
    def test_build_rows_attach_container_or_none(self, _mock_ips) -> None:
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[
                DnsRecord("grafana.lab", "10.0.0.2", "a"),
                DnsRecord("alias.lab", "grafana.lab", "cname"),
                DnsRecord("lonely.lab", "10.0.0.2", "a"),
            ],
        )
        containers = [
            {
                "name": "grafana",
                "container_id": "abc123",
                "state": "running",
                "networking": {
                    "mapped": True,
                    "entries": [
                        {
                            "hostname": "grafana.lab",
                            "upstream": "grafana:3000",
                            "source": "caddyfile",
                            "proxy": "caddy",
                            "in_dns": True,
                        }
                    ],
                },
            }
        ]
        rows = build_dns_inventory(containers, pihole)
        self.assertEqual(len(rows), 3)
        by_hn = {r["hostname"]: r for r in rows}
        self.assertEqual(by_hn["grafana.lab"]["container"], "grafana")
        self.assertEqual(by_hn["grafana.lab"]["type"], "A")
        self.assertEqual(by_hn["grafana.lab"]["port"], 3000)
        self.assertIsNone(by_hn["lonely.lab"]["container"])
        self.assertIsNone(by_hn["lonely.lab"]["port"])
        self.assertEqual(by_hn["alias.lab"]["type"], "CNAME")
        self.assertIsNone(by_hn["alias.lab"]["container"])

    def test_empty_when_pihole_down(self) -> None:
        pihole = PiHoleResult(configured=True, ok=False, message="auth failed")
        rows = build_dns_inventory([], pihole)
        self.assertEqual(rows, [])

    @patch("app.networking.collect_host_network_ips", return_value=set())
    def test_caddy_inventory_lists_discovered_routes(self, _mock_ips) -> None:
        discovery = RouteDiscoveryResult(
            ok=True,
            routes=[
                ProxyRoute(
                    hostname="grafana.lab",
                    upstream="grafana:3000",
                    source="caddyfile",
                ),
                ProxyRoute(
                    hostname="lonely.lab",
                    upstream="lonely:80",
                    source="api",
                ),
            ],
        )
        containers = [
            {
                "name": "grafana",
                "container_id": "abc123",
                "state": "running",
                "networking": {
                    "mapped": True,
                    "entries": [
                        {
                            "hostname": "grafana.lab",
                            "upstream": "grafana:3000",
                            "source": "caddyfile",
                            "proxy": "caddy",
                            "in_dns": True,
                        }
                    ],
                },
            }
        ]
        rows = build_caddy_inventory(containers, discovery)
        self.assertEqual(len(rows), 2)
        by_hn = {r["hostname"]: r for r in rows}
        self.assertEqual(by_hn["grafana.lab"]["container"], "grafana")
        self.assertEqual(by_hn["grafana.lab"]["port"], 3000)
        self.assertEqual(by_hn["grafana.lab"]["source"], "caddyfile")
        self.assertTrue(by_hn["grafana.lab"]["in_dns"])
        self.assertIsNone(by_hn["lonely.lab"]["container"])
        self.assertEqual(by_hn["lonely.lab"]["upstream"], "lonely:80")
        self.assertEqual(by_hn["lonely.lab"]["source"], "api")


if __name__ == "__main__":
    unittest.main()
