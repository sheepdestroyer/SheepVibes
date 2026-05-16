import ipaddress

import pytest

from backend.feed_service import _is_safe_ip


class TestIsSafeIp:

    @pytest.mark.parametrize(
        "ip_str, expected",
        [
            # --- IPv4 Valid Public IPs (Safe) ---
            ("8.8.8.8", True),  # Google DNS
            ("1.1.1.1", True),  # Cloudflare DNS
            ("142.250.190.46", True),  # Google
            ("104.244.42.1", True),  # Twitter
            # --- IPv4 Invalid IPs (Unsafe) ---
            ("127.0.0.1", False),  # Loopback
            ("10.0.0.1", False),  # Private (Class A)
            ("172.16.0.1", False),  # Private (Class B)
            ("192.168.1.1", False),  # Private (Class C)
            ("169.254.0.1", False),  # Link-local
            ("224.0.0.1", False),  # Multicast
            ("0.0.0.0", False),  # Unspecified
            ("240.0.0.1", False),  # Reserved
            # --- IPv6 Valid Public IPs (Safe) ---
            ("2001:4860:4860::8888", True),  # Google DNS
            ("2606:4700:4700::1111", True),  # Cloudflare DNS
            # --- IPv6 Invalid IPs (Unsafe) ---
            ("::1", False),  # Loopback
            ("fc00::1", False),  # Unique Local Address (Private)
            ("fd00::1", False),  # Unique Local Address (Private)
            ("fe80::1", False),  # Link-local
            ("ff02::1", False),  # Multicast
            ("::", False),  # Unspecified
        ],
    )
    def test_is_safe_ip(self, ip_str, expected):
        """Test _is_safe_ip correctly identifies safe/unsafe IPs for both IPv4 and IPv6."""
        ip_obj = ipaddress.ip_address(ip_str)
        assert _is_safe_ip(ip_obj) == expected
