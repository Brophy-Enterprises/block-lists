#!/usr/bin/env python3
"""Build Pi-hole-compatible domain lists from configured upstream lists."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


OUTPUT_NAME = "blocklist.txt"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def normalize_domain(value: str) -> str | None:
    """Return a normalized ASCII domain, or None for unsupported input."""
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(value):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return None


def adblock_domain(rule: str) -> str | None:
    if not rule.startswith("||"):
        return None
    candidate = re.split(r"[\^/$|*]", rule[2:], maxsplit=1)[0]
    return normalize_domain(candidate)


def parse_list(contents: str) -> tuple[set[str], set[str]]:
    """Parse common domain, hosts, dnsmasq, and Adblock list formats."""
    blocked: set[str] = set()
    allowed: set[str] = set()

    for raw_line in contents.splitlines():
        line = raw_line.lstrip("\ufeff").strip()
        if not line or line.startswith(("!", "#", "[")):
            continue

        # Adblock cosmetic and scriptlet filters have no DNS equivalent.
        if any(marker in line for marker in ("##", "#@#", "#$#", "#?#")):
            continue

        if line.startswith("@@"):
            domain = adblock_domain(line[2:])
            if domain:
                allowed.add(domain)
            continue

        domain = adblock_domain(line)
        if domain:
            blocked.add(domain)
            continue

        # dnsmasq forms: address=/example.com/# and server=/example.com/
        if line.startswith(("address=/", "server=/")):
            parts = line.split("/")
            if len(parts) > 1:
                domain = normalize_domain(parts[1])
                if domain:
                    blocked.add(domain)
            continue

        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue

        try:
            ipaddress.ip_address(tokens[0])
        except ValueError:
            # Plain domain lists are the native Pi-hole format. A URL here is
            # treated as a hostname because DNS blocking cannot express paths.
            candidate = tokens[0]
            if candidate.startswith(("http://", "https://")):
                candidate = urlsplit(candidate).hostname or ""
            domain = normalize_domain(candidate)
            if domain:
                blocked.add(domain)
        else:
            for candidate in tokens[1:]:
                domain = normalize_domain(candidate)
                if domain and domain not in {"localhost", "localhost.localdomain"}:
                    blocked.add(domain)

    return blocked, allowed


def read_local_list(path: Path) -> tuple[set[str], set[str]]:
    if not path.exists():
        return set(), set()
    return parse_list(path.read_text(encoding="utf-8"))


def fetch(url: str, timeout: float, attempts: int = 3) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "block-lists-builder/1.0"},
    )
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == attempts:
                raise RuntimeError(f"failed to download {url}: {error}") from error
            time.sleep(attempt)
    raise AssertionError("unreachable")


def source_urls(path: Path) -> list[str]:
    urls = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def is_covered_by(domain: str, suffixes: set[str]) -> bool:
    """Whether domain is equal to or below one of the supplied domains."""
    labels = domain.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels) - 1))


def build_directory(directory: Path, timeout: float) -> tuple[int, int]:
    blocked: set[str] = set()
    allowed: set[str] = set()
    urls = source_urls(directory / "sources.txt")
    if not urls:
        raise RuntimeError(f"{directory / 'sources.txt'} contains no sources")

    for url in urls:
        source_blocked, source_allowed = parse_list(fetch(url, timeout))
        blocked.update(source_blocked)
        allowed.update(source_allowed)
        print(f"  {url}: {len(source_blocked):,} domains")

    additions, _ = read_local_list(directory / "additions.txt")
    exception_domains, exception_allow_rules = read_local_list(
        directory / "exceptions.txt"
    )
    # In an exceptions file, accept both ||example.com^ and the native Adblock
    # allow-list spelling @@||example.com^.
    exceptions = exception_domains | exception_allow_rules

    # Explicit exceptions win over every source and over explicit additions.
    # Treat exception domains as suffixes so ||example.com^ also protects its
    # subdomains when the result is flattened to a plain Pi-hole domain list.
    excluded = allowed | exceptions
    result = {
        domain for domain in blocked | additions if not is_covered_by(domain, excluded)
    }
    output = "".join(f"{domain}\n" for domain in sorted(result))
    (directory / OUTPUT_NAME).write_text(output, encoding="utf-8")
    return len(result), len(exceptions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    root = args.root.resolve()
    source_files = sorted(
        path for path in root.rglob("sources.txt") if ".git" not in path.parts
    )
    if not source_files:
        print(f"No sources.txt files found below {root}", file=sys.stderr)
        return 1

    try:
        for sources_file in source_files:
            directory = sources_file.parent
            print(f"Building {directory.relative_to(root)}/{OUTPUT_NAME}")
            count, exception_count = build_directory(directory, args.timeout)
            print(f"  wrote {count:,} domains ({exception_count:,} explicit exceptions)")
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
