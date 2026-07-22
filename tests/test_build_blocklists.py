import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_blocklists import build_directory, is_covered_by, parse_list  # noqa: E402


class ParseListTest(unittest.TestCase):
    def test_plain_domains(self):
        blocked, allowed = parse_list("example.com\n# comment\nEXAMPLE.org.\n")
        self.assertEqual(blocked, {"example.com", "example.org"})
        self.assertEqual(allowed, set())

    def test_hosts_format(self):
        blocked, _ = parse_list(
            "0.0.0.0 ads.example.com tracker.example.com # reason\n"
            "127.0.0.1 localhost\n"
        )
        self.assertEqual(blocked, {"ads.example.com", "tracker.example.com"})

    def test_adblock_rules_and_exceptions(self):
        blocked, allowed = parse_list(
            "||ads.example.com^\n"
            "||media.example.org^$third-party\n"
            "@@||allowed.example.com^\n"
            "/unsupported-regex/\n"
        )
        self.assertEqual(blocked, {"ads.example.com", "media.example.org"})
        self.assertEqual(allowed, {"allowed.example.com"})

    def test_dnsmasq_and_urls(self):
        blocked, _ = parse_list(
            "address=/ads.example.com/#\n"
            "server=/metrics.example.net/\n"
            "https://tracking.example.org/path\n"
        )
        self.assertEqual(
            blocked,
            {"ads.example.com", "metrics.example.net", "tracking.example.org"},
        )

    def test_cosmetic_and_malformed_rules_are_ignored(self):
        blocked, allowed = parse_list(
            "example.com##.advert\n"
            "||bad_domain^\n"
            "localhost\n"
            "192.0.2.1\n"
        )
        self.assertEqual(blocked, set())
        self.assertEqual(allowed, set())

    def test_exceptions_cover_subdomains(self):
        exceptions = {"example.com"}
        self.assertTrue(is_covered_by("example.com", exceptions))
        self.assertTrue(is_covered_by("deep.child.example.com", exceptions))
        self.assertFalse(is_covered_by("notexample.com", exceptions))

    def test_local_files_can_mix_formats(self):
        upstream = "\n".join(
            (
                "blocked.example.com",
                "child.allowed.example.com",
                "native-exception.example.com",
            )
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            (directory / "sources.txt").write_text(
                "https://lists.example.test/source\n", encoding="utf-8"
            )
            (directory / "additions.txt").write_text(
                "0.0.0.0 hosts-addition.example.com\n"
                "||adblock-addition.example.com^\n",
                encoding="utf-8",
            )
            (directory / "exceptions.txt").write_text(
                "@@||allowed.example.com^\n"
                "native-exception.example.com\n",
                encoding="utf-8",
            )

            with patch("build_blocklists.fetch", return_value=upstream):
                build_directory(directory, timeout=1)

            result = set(
                (directory / "blocklist.txt").read_text(encoding="utf-8").splitlines()
            )

        self.assertEqual(
            result,
            {
                "blocked.example.com",
                "hosts-addition.example.com",
                "adblock-addition.example.com",
            },
        )


if __name__ == "__main__":
    unittest.main()
