"""Unit-тесты: RDAP — парсинг JSON, обработка ошибок/404."""

import os
import sys
import unittest
from unittest import mock

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck.rdap import _parse_entities, _parse_events, fetch_rdap


class ParseEventsTest(unittest.TestCase):
    def test_registration_and_expiration(self):
        events = [
            {'eventAction': 'registration', 'eventDate': '2000-04-20T13:08:22Z'},
            {'eventAction': 'expiration', 'eventDate': '2027-04-30T21:00:00Z'},
            {'eventAction': 'last changed', 'eventDate': '2023-01-01T12:00:00Z'},
        ]
        reg, exp, ch = _parse_events(events)
        self.assertEqual(str(reg), '2000-04-20 13:08:22+00:00')
        self.assertEqual(str(exp), '2027-04-30 21:00:00+00:00')
        self.assertEqual(str(ch), '2023-01-01 12:00:00+00:00')

    def test_missing_events(self):
        reg, exp, ch = _parse_events([])
        self.assertIsNone(reg)
        self.assertIsNone(exp)
        self.assertIsNone(ch)


class ParseEntitiesTest(unittest.TestCase):
    def test_registrar_and_abuse(self):
        entities = [
            {
                'roles': ['registrar'],
                'vcardArray': ['vcard', [
                    ['version', {}, 'text', '4.0'],
                    ['fn', {}, 'text', 'MarkMonitor Inc.'],
                ]],
                'entities': [
                    {
                        'roles': ['abuse'],
                        'vcardArray': ['vcard', [
                            ['email', {}, 'text', 'abuse@example.com'],
                        ]],
                    }
                ],
            }
        ]
        reg, abuses = _parse_entities(entities)
        self.assertEqual(reg, 'MarkMonitor Inc.')
        self.assertEqual(abuses, ['abuse@example.com'])

    def test_empty_vcard(self):
        reg, abuses = _parse_entities([{'roles': ['registrar'], 'vcardArray': ['vcard', []]}])
        self.assertIsNone(reg)
        self.assertEqual(abuses, [])


class FetchRdapTest(unittest.TestCase):
    def _load(self, name):
        path = os.path.join(FIXTURES, name)
        with open(path) as f:
            return f.read()

    def test_success(self):
        body = self._load('rdap_google_com.json')
        with mock.patch('domaincheck.rdap.http_get', return_value=(body, None)):
            r = fetch_rdap('google.com', timeout=5)
        self.assertIsNone(r['error'])
        self.assertEqual(r['source'], 'rdap')
        self.assertIsNotNone(r['registered'])
        self.assertIn('ns1.google.com', r['nameservers'])
        self.assertEqual(r['registrar'], 'MarkMonitor Inc.')
        self.assertIn('abusecomplaints@markmonitor.com', r['abuse_contacts'])

    def test_404_returns_error(self):
        with mock.patch('domaincheck.rdap.http_get', return_value=(None, 'HTTP 404')):
            r = fetch_rdap('nonexistent.tld', timeout=5)
        self.assertIsNotNone(r['error'])
        self.assertIn('404', r['error'])

    def test_network_error(self):
        with mock.patch('domaincheck.rdap.http_get', return_value=(None, 'URLError')):
            r = fetch_rdap('timeout.example', timeout=5)
        self.assertIn('URLError', r['error'])

    def test_invalid_json(self):
        with mock.patch('domaincheck.rdap.http_get', return_value=('<html>oops</html>', None)):
            r = fetch_rdap('bad.example', timeout=5)
        self.assertIn('not valid JSON', r['error'])


if __name__ == '__main__':
    unittest.main()
