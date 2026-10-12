"""Unit-тесты: whois — парсинг текста, кэш, фолбэк."""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck import whois as whois_mod
from domaincheck.whois import parse_whois_text


class ParseWhoisTextTest(unittest.TestCase):
    def _load(self, name):
        with open(os.path.join(FIXTURES, name)) as f:
            return f.read()

    def test_ru_format(self):
        r = parse_whois_text(self._load('whois_example_ru.txt'))
        self.assertIsNotNone(r['registered'])
        self.assertEqual(str(r['registered'])[:4], '2000')
        self.assertIn('REGISTERED', r['statuses'])
        self.assertEqual(r['registrar'], 'RU-CENTER-RU')

    def test_com_format(self):
        r = parse_whois_text(self._load('whois_example_com.txt'))
        self.assertIsNotNone(r['expiration'])
        self.assertEqual(str(r['expiration'])[:4], '2027')
        self.assertIn('clientDeleteProhibited', r['statuses'])
        self.assertTrue(r['dnssec_signed'])

    def test_abuse_parsing(self):
        text = (
            'Registrar: Test Inc.\n'
            'Registrar Abuse Contact Email: abuse@test.com\n'
            'E-mail: fallback@test.com\n'
        )
        r = parse_whois_text(text)
        # vcard 'abuse contact email' — основной, fallback не нужен
        self.assertEqual(r['abuse_contacts'], ['abuse@test.com'])

    def test_abuse_mailbox_key(self):
        r = parse_whois_text('abuse-mailbox: abuse@mail.ru\n')
        self.assertEqual(r['abuse_contacts'], ['abuse@mail.ru'])

    def test_abuse_fallback_when_no_primary(self):
        text = 'E-mail: backup@test.com\n'
        r = parse_whois_text(text)
        self.assertEqual(r['abuse_contacts'], ['backup@test.com'])

    def test_empty_text(self):
        r = parse_whois_text('')
        self.assertIsNone(r['registered'])
        self.assertIsNone(r['expiration'])


class CacheTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = whois_mod.CACHE_PATH
        whois_mod.CACHE_PATH = os.path.join(self._tmpdir, 'cache.json')
        whois_mod._cache = None

    def tearDown(self):
        whois_mod.CACHE_PATH = self._orig_path
        whois_mod._cache = None

    def test_store_and_read(self):
        section = {'source': 'rdap', 'registered': '2000-01-01T00:00:00+00:00'}
        whois_mod._store_raw('mnnoee.ru', 'section', section)
        got = whois_mod._cached_raw('mnnoee.ru', 'section')
        self.assertIsNotNone(got)
        self.assertEqual(got['source'], 'rdap')

    def test_expired_cache_not_read(self):
        age = 8 * 24 * 3600  # > TTL (7 дней)
        cache = {'mnnoee.ru': {'t': time.time() - age, 'section': {'x': 1}}}
        with open(whois_mod.CACHE_PATH, 'w') as f:
            json.dump(cache, f)
        got = whois_mod._cached_raw('mnnoee.ru', 'section')
        self.assertIsNone(got)

    def test_no_cache_file(self):
        got = whois_mod._cached_raw('mnnoee.ru', 'section')
        self.assertIsNone(got)


class RunWhoisSectionTest(unittest.TestCase):
    def test_rdap_success(self):
        body = open(os.path.join(FIXTURES, 'rdap_google_com.json')).read()
        with mock.patch('domaincheck.rdap.http_get', return_value=(body, None)), \
             mock.patch('domaincheck.whois._cached_raw', return_value=None), \
             mock.patch('domaincheck.whois._maybe_store'):
            r = whois_mod.run_whois_section('google.com', timeout=5, use_cache=False)
        self.assertEqual(r['source'], 'rdap')
        self.assertIsNone(r['error'])

    def test_fallback_to_whois_on_404(self):
        with mock.patch('domaincheck.rdap.http_get', return_value=(None, 'HTTP 404')), \
             mock.patch('domaincheck.whois._cached_raw', return_value=None), \
             mock.patch('domaincheck.whois._do_whois', return_value=('registrar: TestR\n', None)), \
             mock.patch('domaincheck.whois._maybe_store'):
            r = whois_mod.run_whois_section('whois-only.tld', timeout=5, use_cache=False)
        self.assertEqual(r['source'], 'whois')
        self.assertIsNone(r['error'])

    def test_cache_used_when_present(self):
        cached = {'source': 'rdap', 'registered': '1995-08-14T04:00:00+00:00'}
        with mock.patch('domaincheck.whois._cached_raw', return_value=cached):
            r = whois_mod.run_whois_section('cached.example', timeout=5, use_cache=True)
        self.assertEqual(r['source'], 'rdap')
        self.assertEqual(r['registered'], '1995-08-14T04:00:00+00:00')


if __name__ == '__main__':
    unittest.main()
