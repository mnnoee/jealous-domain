"""Константы: версия, дефолты, пороги."""

VERSION = '0.2.0'

CACHE_FILE = '.whois_cache.json'
CACHE_TTL = 7 * 24 * 3600

SSL_PORT = 443
TIMEOUT = 10

SSL_EXPIRY_WARN_DAYS = 30

RDAP_URL = 'https://www.rdap.net/domain/{domain}'

DEFAULT_DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'mail']

ABUSE_KEYS = ('orgabuseemail', 'abuse-mailbox', 'registrar abuse contact email')
ABUSE_FALLBACK_KEYS = ('e-mail',)
