import random
import time

import pytest

from tollbooth.blocklist import BLOCKLIST_URL, IPBlocklist, parse_blocklist

SAMPLE = """
# comment
1.0.0.0/24
1.2.3.4
10.0.0.1-10.0.0.50
192.168.1.0/24
2001:db8::1
2001:db8:1::/48
2001:db8:2::1-2001:db8:2::ff
"""


@pytest.fixture
def blocklist():
    bl = IPBlocklist()
    v4, v6 = parse_blocklist(SAMPLE)
    bl._v4_starts = [r[0] for r in v4]
    bl._v4_ends = [r[1] for r in v4]
    bl._v6_starts = [r[0] for r in v6]
    bl._v6_ends = [r[1] for r in v6]
    return bl


class TestParsing:
    def test_v4_single(self):
        v4, _ = parse_blocklist("1.2.3.4")
        assert len(v4) == 1
        assert v4[0][0] == v4[0][1]

    def test_v4_cidr(self):
        v4, _ = parse_blocklist("10.0.0.0/24")
        assert len(v4) == 1
        start, end = v4[0]
        assert end - start == 255

    def test_v4_range(self):
        v4, _ = parse_blocklist("10.0.0.1-10.0.0.50")
        assert len(v4) == 1

    def test_v6_single(self):
        _, v6 = parse_blocklist("2001:db8::1")
        assert len(v6) == 1

    def test_v6_cidr(self):
        _, v6 = parse_blocklist("2001:db8::/32")
        assert len(v6) == 1

    def test_v6_range(self):
        _, v6 = parse_blocklist(
            "2001:db8::1-2001:db8::ff",
        )
        assert len(v6) == 1

    def test_skips_comments_and_empty(self):
        v4, v6 = parse_blocklist("# comment\n\n1.2.3.4")
        assert len(v4) == 1
        assert len(v6) == 0

    def test_skips_invalid(self):
        v4, v6 = parse_blocklist("not-an-ip\n1.2.3.4")
        assert len(v4) == 1

    def test_merges_adjacent(self):
        v4, _ = parse_blocklist(
            "10.0.0.0/24\n10.0.1.0/24",
        )
        assert len(v4) == 1

    def test_merges_overlapping(self):
        v4, _ = parse_blocklist(
            "10.0.0.0/16\n10.0.5.0/24",
        )
        assert len(v4) == 1


class TestLookup:
    def test_v4_cidr_match(self, blocklist):
        assert blocklist.contains("1.0.0.100")

    def test_v4_cidr_miss(self, blocklist):
        assert not blocklist.contains("1.0.1.0")

    def test_v4_single_match(self, blocklist):
        assert blocklist.contains("1.2.3.4")

    def test_v4_single_miss(self, blocklist):
        assert not blocklist.contains("1.2.3.5")

    def test_v4_range_start(self, blocklist):
        assert blocklist.contains("10.0.0.1")

    def test_v4_range_end(self, blocklist):
        assert blocklist.contains("10.0.0.50")

    def test_v4_range_mid(self, blocklist):
        assert blocklist.contains("10.0.0.25")

    def test_v4_range_miss(self, blocklist):
        assert not blocklist.contains("10.0.0.51")

    def test_v6_single_match(self, blocklist):
        assert blocklist.contains("2001:db8::1")

    def test_v6_single_miss(self, blocklist):
        assert not blocklist.contains("2001:db8::2")

    def test_v6_cidr_match(self, blocklist):
        assert blocklist.contains("2001:db8:1::abcd")

    def test_v6_cidr_miss(self, blocklist):
        assert not blocklist.contains("2001:db8:3::1")

    def test_v6_range_match(self, blocklist):
        assert blocklist.contains("2001:db8:2::50")

    def test_v6_range_miss(self, blocklist):
        assert not blocklist.contains("2001:db8:2::100")

    def test_invalid_ip(self, blocklist):
        assert not blocklist.contains("invalid")

    def test_empty_blocklist(self):
        bl = IPBlocklist()
        assert not bl.contains("1.2.3.4")


class TestRuleIntegration:
    def test_blocklist_rule_matches(self, blocklist):
        from tollbooth.engine import Policy, Rule

        policy = Policy(
            rules=[
                Rule(
                    name="blocked",
                    action="challenge",
                    difficulty=8,
                    blocklist=True,
                ),
            ],
        )
        request = {
            "method": "GET",
            "path": "/",
            "query": "",
            "user_agent": "Mozilla/5.0",
            "remote_addr": "1.0.0.100",
            "headers": {},
            "cookies": {},
            "form": {},
        }
        action, diff, _ = policy.evaluate(request, blocklist)
        assert action == "challenge"
        assert diff == 8

    def test_blocklist_rule_skips(self, blocklist):
        from tollbooth.engine import Policy, Rule

        policy = Policy(
            rules=[
                Rule(
                    name="blocked",
                    action="deny",
                    blocklist=True,
                ),
            ],
        )
        request = {
            "method": "GET",
            "path": "/",
            "query": "",
            "user_agent": "Mozilla/5.0",
            "remote_addr": "8.8.8.8",
            "headers": {},
            "cookies": {},
            "form": {},
        }
        action, _, _ = policy.evaluate(request, blocklist)
        assert action == "allow"

    def test_blocklist_rule_no_blocklist(self):
        from tollbooth.engine import Policy, Rule

        policy = Policy(
            rules=[
                Rule(
                    name="blocked",
                    action="deny",
                    blocklist=True,
                ),
            ],
        )
        request = {
            "method": "GET",
            "path": "/",
            "query": "",
            "user_agent": "",
            "remote_addr": "1.0.0.1",
            "headers": {},
            "cookies": {},
            "form": {},
        }
        action, _, _ = policy.evaluate(request, None)
        assert action == "allow"


class TestBenchmark:
    @pytest.fixture
    def large_blocklist(self):
        lines = [f"{i}.{j}.0.0/16" for i in range(1, 51) for j in range(256)]
        bl = IPBlocklist()
        v4, v6 = parse_blocklist("\n".join(lines))
        bl._v4_starts = [r[0] for r in v4]
        bl._v4_ends = [r[1] for r in v4]
        return bl

    def test_lookup_speed(self, large_blocklist):
        ips = [f"{i}.{j}.1.1" for i in range(1, 51) for j in range(0, 256, 10)]
        start = time.perf_counter()
        for ip in ips:
            large_blocklist.contains(ip)
        elapsed = time.perf_counter() - start
        ops = len(ips) / elapsed
        print(f"\n  In-memory: {ops:,.0f} lookups/sec")
        assert ops > 10_000


@pytest.mark.slow
class TestFullDataset:
    @pytest.fixture(scope="class")
    def full_blocklist(self):
        bl = IPBlocklist()
        try:
            bl.load(BLOCKLIST_URL)
        except Exception as e:
            pytest.skip(f"Blocklist download failed: {e}")
        return bl

    def test_load(self, full_blocklist):
        assert len(full_blocklist) > 100_000
        print(
            f"\n  Ranges: {len(full_blocklist):,}"
            f"  (v4={len(full_blocklist._v4_starts):,}"
            f"  v6={len(full_blocklist._v6_starts):,})"
        )

    def test_ipv4_lookup_speed(self, full_blocklist):
        random.seed(42)
        ips = [
            f"{random.randint(0,255)}"
            f".{random.randint(0,255)}"
            f".{random.randint(0,255)}"
            f".{random.randint(0,255)}"
            for _ in range(100_000)
        ]
        start = time.perf_counter()
        hits = sum(full_blocklist.contains(ip) for ip in ips)
        elapsed = time.perf_counter() - start
        ops = len(ips) / elapsed
        print(
            f"\n  In-memory IPv4:"
            f" {ops:,.0f} lookups/sec"
            f"  ({hits:,} hits / {len(ips):,})"
        )
        assert ops > 100_000

    def test_ipv6_lookup_speed(self, full_blocklist):
        random.seed(42)
        ips = [
            f"2001:db8:{random.randint(0,0xffff):x}" f"::{random.randint(0,0xffff):x}"
            for _ in range(10_000)
        ]
        start = time.perf_counter()
        hits = sum(full_blocklist.contains(ip) for ip in ips)
        elapsed = time.perf_counter() - start
        ops = len(ips) / elapsed
        print(
            f"\n  In-memory IPv6:"
            f" {ops:,.0f} lookups/sec"
            f"  ({hits:,} hits / {len(ips):,})"
        )
        assert ops > 50_000
