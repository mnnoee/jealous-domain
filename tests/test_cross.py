"""Unit-тесты: перекрёстные проверки."""

import datetime
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck.cross import run_cross_checks

NOW = datetime.datetime.now(datetime.timezone.utc)


def _iso(days):
    return (NOW + datetime.timedelta(days=days)).isoformat()


def _whois(exp_days):
    return {'expiration': _iso(exp_days), 'error': None}


def _ssl(cert_days, error=None, chain=True):
    s = {'error': error, 'chain': []}
    if chain:
        s['chain'] = [{'not_after': _iso(cert_days), 'days_until_expiry': cert_days}]
    return s


def _dns(a=None, ptr=None, error=None):
    return {'a': a or [], 'ptr': ptr or {}, 'error': error}


class CrossChecksTest(unittest.TestCase):
    def _sevs(self, checks):
        return sorted(c.get('severity') for c in checks)

    def test_cert_after_domain_is_warning(self):
        checks = run_cross_checks(_whois(200), _dns(), _ssl(400))
        msgs = ' '.join(c['message'] for c in checks)
        self.assertIn('бесполезный сертификат', msgs)

    def test_imminent_cert_with_long_domain(self):
        checks = run_cross_checks(_whois(400), _dns(), _ssl(14))
        msgs = ' '.join(c['message'] for c in checks)
        self.assertIn('обновить сертификат', msgs)

    def test_no_warning_for_healthy_cert(self):
        checks = run_cross_checks(_whois(400), _dns(), _ssl(60))
        self.assertEqual([c for c in checks if 'бесполезный' in c['message']], [])

    def test_ptr_mismatch_warning(self):
        dns = _dns(ptr={'93.184.216.34': {'hostname': 'other.net', 'matches_domain': False}})
        checks = run_cross_checks(None, dns, None)
        self.assertEqual(self._sevs(checks), ['warning'])
        self.assertIn('не совпадает', checks[0]['message'])

    def test_ptr_match_info(self):
        dns = _dns(ptr={'93.184.216.34': {'hostname': 'mnnoee.ru', 'matches_domain': True}})
        checks = run_cross_checks(None, dns, None)
        self.assertEqual(self._sevs(checks), ['info'])

    def test_a_record_but_ssl_failed(self):
        dns = _dns(a=['93.184.216.34'])
        ssl = _ssl(0, error='connect: Connection refused', chain=False)
        checks = run_cross_checks(None, dns, ssl)
        self.assertEqual(self._sevs(checks), ['warning'])
        self.assertIn('SSL', checks[0]['message'])

    def test_error_sections_are_skipped(self):
        # все секции с ошибками -> пустые проверки
        checks = run_cross_checks({'error': 'x'}, {'error': 'y'}, {'error': 'z'})
        self.assertEqual(checks, [])

    def test_section_error_skips_cross(self):
        dns = _dns(ptr={'80.0.0.1': {'hostname': 'x.test', 'matches_domain': False}}, error='dig down')
        checks = run_cross_checks(_whois(400), dns, _ssl(60))
        self.assertEqual(checks, [])

    def test_invalid_expiration_ignored(self):
        # некорректный формат даты -> None, проверки не падают
        whois = {'expiration': 'не-дата', 'error': None}
        checks = run_cross_checks(whois, _dns(), _ssl(400))
        self.assertEqual(checks, [])

    def test_none_expiration_ignored(self):
        whois = {'expiration': None, 'error': None}
        checks = run_cross_checks(whois, _dns(), _ssl(400))
        self.assertEqual(checks, [])

    def test_naive_expiration_handled(self):
        # дата без tzinfo — заменяется на UTC, не роняет сравнение;
        # сертификат (400 дн.) живёт дольше naive-домена (100 дн.) -> warning
        naive = (datetime.datetime.now() + datetime.timedelta(days=100)).isoformat()
        whois = {'expiration': naive, 'error': None}
        checks = run_cross_checks(whois, _dns(), _ssl(400))
        self.assertEqual(self._sevs(checks), ['warning'])

    def test_no_chain_no_cert_checks(self):
        # ssl без chain -> cert-vs-domain проверки не запускаются
        checks = run_cross_checks(_whois(200), _dns(), _ssl(400, chain=False))
        self.assertEqual(checks, [])


if __name__ == '__main__':
    unittest.main()
