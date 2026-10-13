# jealous-domain

[![CI](https://github.com/mnnoee/jealous-domain/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-domain/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](CHANGELOG.md)

> Part of the [Jealous Moon](https://github.com/mnnoee) toolkit — offline
> server and domain diagnostics.

Domain diagnostics from independent sources: RDAP/whois, DNS, SSL/TLS and
cross-checks between them. Answers the main questions: "when does the domain
expire?", "when does the certificate expire?", "is DNS in order?".

> [README на русском](README.ru.md) — полная документация.

## Features

- **RDAP/whois**: registration, expiration, registrar, statuses,
  nameservers, abuse contacts (whois fallback for zones without RDAP)
- **DNS**: A/AAAA, MX, NS, TXT, SPF, DMARC, DKIM selectors, PTR,
  NS consistency check
- **SSL/TLS**: full certificate chain, days until expiry, verify results
- **Cross-checks**: "certificate outlives the domain", "certificate expires
  soon but the domain is renewed for long", PTR mismatch, "A record exists
  but port 443 is closed"
- **Section isolation**: one source failing (no network/utility/domain)
  puts `error` in its section, the rest keep working
- **IDN domains**: Cyrillic and other non-ASCII domains (e.g. IDN .рф)
  are converted to punycode for network requests
- JSON export (`--json [PATH]`)

## Install

Not on PyPI yet (planned). Install straight from GitHub:

```bash
pip install git+https://github.com/mnnoee/jealous-domain.git
```

Or run straight from a clone:

```bash
python3 domain_checker.py example.com
```

External utilities (checked via `shutil.which`, a missing one does not break
the rest): `whois`, `dig`, `openssl`.

## Usage

```bash
jealous-domain mnnoee.ru                  # all sections
jealous-domain mnnoee.ru --whois          # RDAP/whois only
jealous-domain mnnoee.ru --dns            # DNS only
jealous-domain mnnoee.ru --dns --ssl      # combined sections
jealous-domain mnnoee.ru --json out.json  # machine-readable report
jealous-domain --help                     # all options
```

## Example report

```log
==================================================
mnnoee.ru
==================================================

--- WHOIS / RDAP ---
  source:      whois
  registered:  2025-04-03
  expires:     2027-04-03 (in 172 days)
  registrar:   REGRU-RU
  statuses:    REGISTERED, DELEGATED, VERIFIED
  NS:          ns1.mnnoee.ru, ns2.mnnoee.ru

--- DNS ---
  A             64.188.94.216
  MX            10 mail.mnnoee.ru
  SPF           v=spf1 ip4:64.188.94.216 -all
  PTR           64.188.94.216 -> mail.mnnoee.ru [ok]
  NS-check  consistent
```

## Ideas & suggestions

Have an idea for the project? Open an issue — suggestions for new report
sections, checks, export formats and integrations are welcome.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
