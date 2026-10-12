"""Unit-тесты: утилиты parse_utils (normalize_domain, to_ascii, даты, HTTP)."""

import datetime
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck.parse_utils import (
    days_until,
    http_get,
    normalize_domain,
    parse_dt,
    parse_iso,
    to_ascii,
)

# Домены проекта: mnnoee.ru и смешнявки.рф (IDN, punycode xn--b1afhhhz2d6c.xn--p1ai)
OWN_DOMAIN = 'mnnoee.ru'
OWN_IDN = 'смешнявки.рф'
OWN_IDN_PUNYCODE = 'xn--b1afkhhhz2d6c.xn--p1ai'


class NormalizeDomainTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(normalize_domain(OWN_DOMAIN), OWN_DOMAIN)

    def test_idn_lowercased(self):
        self.assertEqual(normalize_domain('СМЕШНЯВКИ.РФ'), OWN_IDN)

    def test_scheme_stripped(self):
        self.assertEqual(normalize_domain(f'https://{OWN_DOMAIN}/path'), OWN_DOMAIN)

    def test_port_stripped(self):
        self.assertEqual(normalize_domain(f'{OWN_DOMAIN}:8443'), OWN_DOMAIN)

    def test_trailing_dot_stripped(self):
        self.assertEqual(normalize_domain(f'{OWN_DOMAIN}.'), OWN_DOMAIN)


class ToAsciiTest(unittest.TestCase):
    def test_ascii_passthrough(self):
        self.assertEqual(to_ascii(OWN_DOMAIN), OWN_DOMAIN)

    def test_idn_to_punycode(self):
        self.assertEqual(to_ascii(OWN_IDN), OWN_IDN_PUNYCODE)

    def test_idn_uppercase(self):
        self.assertEqual(to_ascii('СМЕШНЯВКИ.РФ'), OWN_IDN_PUNYCODE)

    def test_invalid_returns_as_is(self):
        # пустая метка ломает IDNA-кодирование -> домен как есть
        self.assertEqual(to_ascii('..'), '..')


class ParseDtTest(unittest.TestCase):
    def test_iso_like_format(self):
        dt = parse_dt('2026-08-19 11:11:11')
        self.assertEqual((dt.year, dt.month, dt.day), (2026, 8, 19))

    def test_empty_none(self):
        self.assertIsNone(parse_dt(''))
        self.assertIsNone(parse_dt(None))

    def test_invalid_none(self):
        self.assertIsNone(parse_dt('не-дата'))


class ParseIsoTest(unittest.TestCase):
    def test_z_suffix(self):
        dt = parse_iso('2026-08-19T11:11:11Z')
        self.assertIsNotNone(dt)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_offset(self):
        dt = parse_iso('2026-08-19T11:11:11+03:00')
        self.assertEqual(dt.utcoffset(), datetime.timedelta(hours=3))

    def test_fallback_to_parse_dt(self):
        # не-ISO строка уходит в parse_dt
        self.assertIsNotNone(parse_iso('2026-08-19 11:11:11'))
        self.assertIsNone(parse_iso('мусор'))
        self.assertIsNone(parse_iso(''))


class DaysUntilTest(unittest.TestCase):
    def test_future_positive(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        self.assertGreater(days_until(future), 0)

    def test_past_negative(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=5)
        self.assertLess(days_until(past), 0)

    def test_none(self):
        self.assertIsNone(days_until(None))


class HttpGetTest(unittest.TestCase):
    def test_success(self):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def read(self):
                return b'{"ok": true}'

        with patch('domaincheck.parse_utils.urllib.request.urlopen', return_value=_Resp()):
            body, err = http_get('https://rdap.example/domain/mnnoee.ru')
        self.assertEqual(body, '{"ok": true}')
        self.assertIsNone(err)

    def test_http_error(self):
        import urllib.error
        e = urllib.error.HTTPError('url', 404, 'Not Found', None, None)
        with patch('domaincheck.parse_utils.urllib.request.urlopen', side_effect=e):
            body, err = http_get('https://rdap.example/domain/unknown.tld')
        self.assertEqual(err, 'HTTP 404')

    def test_network_error(self):
        import urllib.error
        with patch('domaincheck.parse_utils.urllib.request.urlopen',
                   side_effect=urllib.error.URLError('no network')):
            body, err = http_get('https://rdap.example/domain/mnnoee.ru')
        self.assertIsNone(body)
        self.assertIn('no network', err)


class RunCmdTest(unittest.TestCase):
    def test_echo(self):
        from domaincheck.parse_utils import run_cmd
        out, err = run_cmd(['echo', 'ok'], timeout=5)
        self.assertEqual(out.strip(), 'ok')
        self.assertIsNone(err)

    def test_missing_utility(self):
        from domaincheck.parse_utils import run_cmd
        out, err = run_cmd(['нет-такой-утилиты-xyz'], timeout=5)
        self.assertFalse(out)
        self.assertIsNotNone(err)


if __name__ == '__main__':
    unittest.main()
