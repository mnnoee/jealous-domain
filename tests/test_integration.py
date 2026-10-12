"""Интеграционные тесты: реальные запросы в сеть (вручную, не в CI).

Запуск:
    pytest -m integration

Домены: собственные (mnnoee.ru, смешнявки.рф — IDN) и сторонние
публичные (google.dev — TLD без классического whois, только RDAP;
github.com — классический вариант).
"""

import os
import shutil
import sys
import unittest

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck import dns, rdap, ssl, whois

OWN_DOMAIN = 'mnnoee.ru'
OWN_IDN = 'смешнявки.рф'          # IDN: уходит в сеть как xn--b1afkhhhz2d6c.xn--p1ai
THIRD_PARTY_RDAP_ONLY = 'google.dev'  # TLD без whois на порту 43 — только RDAP
THIRD_PARTY = 'github.com'

DOMAINS = [OWN_DOMAIN, OWN_IDN, THIRD_PARTY_RDAP_ONLY, THIRD_PARTY]


@pytest.mark.integration
class IntegrationTest(unittest.TestCase):
    def test_rdap_live(self):
        for domain in DOMAINS:
            with self.subTest(domain=domain):
                r = rdap.fetch_rdap(domain, timeout=15)
                self.assertIsNone(r['error'], f"RDAP error для {domain}: {r['error']}")
                self.assertEqual(r['source'], 'rdap')
                self.assertIsNotNone(r['expiration'])
                self.assertTrue(len(r['nameservers']) > 0)

    def test_whois_section_live(self):
        for domain in DOMAINS:
            with self.subTest(domain=domain):
                r = whois.run_whois_section(domain, timeout=15, use_cache=False)
                self.assertIsNone(r['error'], f"whois error для {domain}: {r['error']}")

    @unittest.skipUnless(shutil.which('dig'), 'dig not installed')
    def test_dns_live(self):
        for domain in DOMAINS:
            with self.subTest(domain=domain):
                r = dns.run_dns_section(domain, dkim_selectors=['default'], timeout=15)
                self.assertIsNone(r['error'], f"DNS error для {domain}: {r['error']}")
                self.assertTrue(len(r['a']) > 0, f'A-записей нет у {domain}')

    @unittest.skipUnless(shutil.which('openssl'), 'openssl not installed')
    def test_ssl_live(self):
        for domain in DOMAINS:
            with self.subTest(domain=domain):
                r = ssl.run_ssl_section(domain, port=443, timeout=15)
                self.assertIsNone(r['error'], f"SSL error для {domain}: {r['error']}")
                self.assertTrue(len(r['chain']) > 0, f'цепочки нет у {domain}')
                self.assertTrue(r['verify_ok'], f'цепочка не верифицируется у {domain}')

    def test_idn_punycode_conversion(self):
        # смешнявки.рф конвертируется в punycode на сетевой границе
        from domaincheck.parse_utils import to_ascii
        self.assertEqual(to_ascii(OWN_IDN), 'xn--b1afkhhhz2d6c.xn--p1ai')
        # и RDAP отвечает на punycode-форму
        r = rdap.fetch_rdap(OWN_IDN, timeout=15)
        self.assertIsNone(r['error'], f"RDAP error для {OWN_IDN}: {r['error']}")


if __name__ == '__main__':
    unittest.main()
