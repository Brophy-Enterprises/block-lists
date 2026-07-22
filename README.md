# Pi-hole block lists

This repository builds consolidated, Pi-hole-compatible domain lists. Every
directory containing a `sources.txt` gets its own generated `blocklist.txt`.

## Directory format

For example, `focus/` contains:

- `sources.txt`: one upstream `https://` list URL per line
- `exceptions.txt`: domains that must not be blocked (optional)
- `additions.txt`: extra domains to block (optional)
- `blocklist.txt`: generated output; do not edit it by hand

Local additions and exceptions may mix plain domains, hosts-file entries, and
Adblock domain rules in the same file. Exceptions accept either
`||example.com^` or `@@||example.com^` and take final precedence if the same
domain is present in both local files. An exception also removes all of that
domain's subdomains from the generated list.

The builder understands these common upstream formats:

- one domain per line (the native Pi-hole format)
- hosts files such as `0.0.0.0 example.com`
- Adblock domain rules such as `||example.com^` and `@@||example.com^`
- dnsmasq rules such as `address=/example.com/#`

Cosmetic filters, regular-expression rules, and URL paths cannot be represented
by a DNS block list and are ignored. For a URL-style entry, only its hostname is
used.

## Automation

[The GitHub Actions workflow](.github/workflows/build-blocklists.yml) rebuilds
the lists:

- after every new commit pushed or merged into `main`
- once per week on Sunday at 13:17 UTC, to discover upstream changes
- whenever it is manually started from the Actions tab

It commits only when generated output actually changes. A failed download makes
the whole run fail so a temporarily incomplete list is never committed.

To build locally (Python 3.10 or newer):

```sh
python scripts/build_blocklists.py
```

Tests do not require network access:

```sh
python -m unittest discover -s tests
```

A separate read-only workflow runs these unit tests on every pull request. It
does not run the builder, download upstream sources, or modify generated files.

## Pi-hole URL

After the generated file has been committed, use its raw GitHub URL in Pi-hole:

```text
https://raw.githubusercontent.com/OWNER/REPOSITORY/main/focus/blocklist.txt
```

Replace `OWNER/REPOSITORY` with this repository's GitHub location. This URL stays
the same when the workflow refreshes the file. The repository must be public for
Pi-hole to fetch this URL without GitHub authentication.
