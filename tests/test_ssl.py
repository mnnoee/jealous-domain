"""Unit-тесты: SSL — парсинг s_client, цепочка, verify, ошибки."""

import os
import sys
import unittest
from unittest import mock

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck import ssl

X509_OUT = """subject=CN=mnnoee.ru
issuer=C=US, O=Example Org, CN=Example CA
notBefore=Jul 29 22:10:08 2026 GMT
notAfter=Oct 27 22:17:21 2026 GMT
Certificate:
    Data:
        Signature Algorithm: ecdsa-with-SHA256
    Subject: CN=mnnoee.ru
    Issuer: C=US, O=Example Org, CN=Example CA
"""


def _fake_run(cmd, timeout=10, input_text=None):
    joined = ' '.join(cmd)
    if 's_client' in joined:
        with open(os.path.join(FIXTURES, 'ssl_example_com.txt')) as f:
            return f.read(), None
    return X509_OUT, None


class ParseChainTest(unittest.TestCase):
    def test_chain_from_fixture(self):
        with open(os.path.join(FIXTURES, 'ssl_example_com.txt')) as f:
            raw = f.read()
        chain = ssl._parse_chain(raw, timeout=5)
        self.assertEqual(len(chain), 4)
        self.assertEqual(chain[0]['depth'], 0)
        # фикстура — реальная цепочка example.com (публичные данные)
        self.assertEqual(chain[0]['subject'], 'CN=example.com')
        self.assertIsNotNone(chain[0]['not_after'])
        self.assertIsInstance(chain[0]['days_until_expiry'], int)

    def test_x509_space_eq_normalized(self):
        # openssl части версий печатает 'CN = x' (с пробелами) — парсер нормализует
        out = X509_OUT.replace('subject=CN=mnnoee.ru', 'subject=CN = mnnoee.ru')
        with mock.patch('domaincheck.ssl.run_cmd', return_value=(out, None)):
            info = ssl._parse_x509_cert('-----BEGIN CERTIFICATE-----', timeout=5)
        self.assertEqual(info['subject'], 'CN=mnnoee.ru')
        self.assertEqual(info['issuer'], 'C=US, O=Example Org, CN=Example CA')


class ParseVerifyTest(unittest.TestCase):
    def test_ok(self):
        with open(os.path.join(FIXTURES, 'ssl_example_com.txt')) as f:
            raw = f.read()
        ok, depths = ssl._parse_verify(raw)
        self.assertTrue(ok)
        self.assertEqual(len(depths), 4)
        self.assertTrue(all(d['verify_return'] == 1 for d in depths))

    def test_bad_cert_chain(self):
        raw = (
            'depth=0 CN=example.org\n'
            'verify error:num=10:certificate has expired\n'
            'verify return:0\n'
            'Verify return code: 10 (certificate has expired)\n'
        )
        ok, depths = ssl._parse_verify(raw)
        self.assertFalse(ok)
        self.assertEqual(depths[0]['verify_return'], 0)


class RunSslSectionTest(unittest.TestCase):
    def test_success(self):
        with mock.patch('domaincheck.ssl.run_cmd', side_effect=_fake_run):
            r = ssl.run_ssl_section('mnnoee.ru', port=443, timeout=10)
        self.assertIsNone(r['error'])
        self.assertEqual(len(r['chain']), 4)
        self.assertTrue(r['verify_ok'])
        self.assertIn('-----BEGIN CERTIFICATE-----', r['raw_output'])

    def test_connection_error(self):
        def fail(cmd, timeout=10, input_text=None):
            return ('', 'connect: Connection refused')
        with mock.patch('domaincheck.ssl.run_cmd', side_effect=fail):
            r = ssl.run_ssl_section('closed-host.example', timeout=10)
        self.assertIsNotNone(r['error'])
        self.assertEqual(r['chain'], [])

    def test_missing_openssl(self):
        def missing(cmd, timeout=10, input_text=None):
            return ('', "utility 'openssl' not found in PATH")
        with mock.patch('domaincheck.ssl.run_cmd', side_effect=missing):
            r = ssl.run_ssl_section('mnnoee.ru', timeout=10)
        self.assertEqual(r['error'], "utility 'openssl' not found in PATH")


if __name__ == '__main__':
    unittest.main()
