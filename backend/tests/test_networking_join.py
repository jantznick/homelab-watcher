"""Unit tests: domain↔container join is port/Caddy/DNS-IP only (no fuzzy names)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from app.caddy_routes import ProxyRoute, RouteDiscoveryResult
from app.networking import (
    build_dns_inventory,
    enrich_networking,
    match_route_to_containers,
)
from app.pihole import DnsRecord, PiHoleResult


def _music_container() -> dict:
    return {
        "name": "navidrome",
        "container_id": "abc123",
        "state": "running",
        "published_ports": ["0.0.0.0:4533->4533/tcp"],
        "labels": {"com.docker.compose.service": "navidrome"},
        "inspect": {
            "NetworkSettings": {
                "Networks": {
                    "lab": {
                        "IPAddress": "172.18.0.10",
                        "Aliases": ["navidrome"],
                        "DNSNames": ["navidrome"],
                    }
                },
                "Ports": {
                    "4533/tcp": [{"HostIp": "0.0.0.0", "HostPort": "4533"}],
                },
            },
            "Config": {"ExposedPorts": {"4533/tcp": {}}},
            "HostConfig": {},
        },
    }


class TestNoFuzzyDomainJoin(unittest.TestCase):
    def test_name_similarity_alone_does_not_attach(self) -> None:
        """music.jantz.me must not attach to a 'music' container by label text."""
        containers = [
            {
                "name": "music",
                "container_id": "m1",
                "state": "running",
                "published_ports": ["0.0.0.0:8080->80/tcp"],
                "labels": {},
                "inspect": {
                    "NetworkSettings": {"Networks": {}, "Ports": {}},
                    "Config": {},
                    "HostConfig": {},
                },
            }
        ]
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[DnsRecord("music.jantz.me", "192.168.1.50", "a")],
        )
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            status = enrich_networking(
                containers,
                proxy_type="caddy",
                discovery=RouteDiscoveryResult(ok=True, routes=[]),
                pihole=pihole,
            )
        self.assertFalse(containers[0].get("pihole_matched"))
        self.assertEqual(containers[0].get("pihole_hostnames"), [])
        self.assertFalse((containers[0].get("networking") or {}).get("mapped"))
        self.assertEqual(status.get("mapped_count"), 0)

    def test_proxy_off_does_not_fuzzy_match(self) -> None:
        containers = [
            {
                "name": "music",
                "container_id": "m1",
                "state": "running",
                "published_ports": [],
                "labels": {},
                "inspect": {
                    "NetworkSettings": {"Networks": {}, "Ports": {}},
                    "Config": {},
                    "HostConfig": {},
                },
            }
        ]
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[DnsRecord("music.jantz.me", "192.168.1.8", "a")],
        )
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            enrich_networking(
                containers,
                proxy_type="none",
                discovery=None,
                pihole=pihole,
            )
        self.assertFalse(containers[0]["pihole_matched"])
        self.assertEqual(containers[0]["pihole_hostnames"], [])

    def test_port_chain_maps_when_dns_hits_host_ip(self) -> None:
        containers = [_music_container()]
        route = ProxyRoute(
            hostname="music.jantz.me",
            upstream="localhost:4533",
            source="caddyfile",
        )
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[DnsRecord("music.jantz.me", "192.168.1.8", "a")],
        )
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            enrich_networking(
                containers,
                proxy_type="caddy",
                discovery=RouteDiscoveryResult(ok=True, routes=[route]),
                pihole=pihole,
            )
        net = containers[0]["networking"]
        self.assertTrue(net["mapped"])
        self.assertEqual(net["entries"][0]["hostname"], "music.jantz.me")
        self.assertTrue(net["entries"][0]["in_dns"])
        self.assertEqual(containers[0]["pihole_hostnames"], ["music.jantz.me"])

    def test_dns_wrong_ip_skips_container_attach(self) -> None:
        containers = [_music_container()]
        route = ProxyRoute(
            hostname="music.jantz.me",
            upstream="localhost:4533",
            source="caddyfile",
        )
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[DnsRecord("music.jantz.me", "192.168.1.50", "a")],
        )
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            enrich_networking(
                containers,
                proxy_type="caddy",
                discovery=RouteDiscoveryResult(ok=True, routes=[route]),
                pihole=pihole,
            )
        self.assertFalse(containers[0]["networking"]["mapped"])
        self.assertEqual(containers[0]["pihole_hostnames"], [])

    def test_match_rejects_domain_label_without_port(self) -> None:
        containers = [_music_container()]
        # Upstream has no port and is not a label on this container
        route = ProxyRoute(hostname="music.jantz.me", upstream="", source="caddyfile")
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            scored = match_route_to_containers(route, containers)
        self.assertEqual(scored, [])

    def test_dns_inventory_container_column_requires_proxy_and_host_ip(self) -> None:
        containers = [
            {
                "name": "navidrome",
                "container_id": "abc123",
                "state": "running",
                "networking": {
                    "mapped": True,
                    "entries": [
                        {
                            "hostname": "music.jantz.me",
                            "upstream": "localhost:4533",
                            "source": "caddyfile",
                            "proxy": "caddy",
                            "in_dns": True,
                        }
                    ],
                },
                # Leftover fuzzy field must be ignored by inventory
                "pihole_hostnames": ["music.jantz.me", "unrelated.lab"],
            }
        ]
        pihole = PiHoleResult(
            configured=True,
            ok=True,
            records=[
                DnsRecord("music.jantz.me", "192.168.1.50", "a"),
                DnsRecord("lonely.lab", "192.168.1.8", "a"),
            ],
        )
        with patch("app.networking.collect_host_network_ips", return_value={"192.168.1.8"}):
            rows = build_dns_inventory(containers, pihole)
        by_hn = {r["hostname"]: r for r in rows}
        # Wrong DNS IP → no container column even if networking entry exists
        self.assertIsNone(by_hn["music.jantz.me"]["container"])
        self.assertIsNone(by_hn["lonely.lab"]["container"])


if __name__ == "__main__":
    unittest.main()
