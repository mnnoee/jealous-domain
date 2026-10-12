"""Unit-тесты: DNS-секция — dig-парсинг, DKIM, SPF, PTR, NS-сверка."""

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck.dns import _parse_mx, _ptr_map, _txt_lines, run_dns_section


class ParseMxTest(unittest.TestCase):
    def test_normal_mx(self):
        self.assertEqual(_parse_mx(['10 mail.mnnoee.ru.', '20 mail2.mnnoee.ru.']), [
            {'priority': 10, 'host': 'mail.mnnoee.ru'},
            {'priority': 20, 'host': 'mail2.mnnoee.ru'},
        ])

    def test_null_mx(self):
        self.assertEqual(_parse_mx(['0 .']), [{'priority': 0, 'host': '.'}])


class TxtLinesTest(unittest.TestCase):
    def test_joined_fragments(self):
        self.assertEqual(_txt_lines(['"v=spf1 " "include:_spf.mnnoee.ru " "~all"']),
                         ['v=spf1 include:_spf.mnnoee.ru ~all'])

    def test_plain(self):
        self.assertEqual(_txt_lines(['v=spf1 -all']), ['v=spf1 -all'])

    def test_duplicates_removed(self):
        self.assertEqual(_txt_lines(['"a"', '"a"', '"b"']), ['a', 'b'])


class _DigMock:
    """Заглушка dig: таблица qname/type -> записи."""

    def __init__(self, table, ptr=None, ns_answers=None, missing=False):
        self.table = table
        self.ptr = ptr or {}
        self.ns_answers = ns_answers or {}
        self.missing = missing

    def _out(self, lines):
        return (lines or '', None)

    def __call__(self, cmd, timeout=10):
        if self.missing:
            return ('', "utility 'dig' not found in PATH")
        args = cmd[2:]
        if args[0].startswith('-x'):
            ip = args[1]
            return self._out(self.ptr.get(ip))
        if args[0].startswith('@'):
            ns = args[0][1:]
            rtype = args[1].upper()
            qname = args[2].lower()
            return self._out(self.ns_answers.get((ns, rtype, qname)))
        rtype = args[0].upper()
        qname = args[-1].lower()
        return self._out(self.table.get((rtype, qname)))


def _mk_table(dns_txt=None, dmarc=None, dkim=None, a=None, aaaa=None, mx=None, ns=None):
    table = {}
    if a is not None:
        table[('A', 'mnnoee.ru')] = '\n'.join(a) + '\n'
    if aaaa is not None:
        table[('AAAA', 'mnnoee.ru')] = '\n'.join(aaaa) + '\n'
    if mx is not None:
        table[('MX', 'mnnoee.ru')] = '\n'.join(mx) + '\n'
    if ns is not None:
        table[('NS', 'mnnoee.ru')] = '\n'.join(ns) + '\n'
    table[('TXT', 'mnnoee.ru')] = dns_txt
    table[('TXT', '_dmarc.mnnoee.ru')] = dmarc
    for sel, rec in (dkim or {}).items():
        table[('TXT', f'{sel}._domainkey.mnnoee.ru')] = rec
    return table


class RunDnsSectionTest(unittest.TestCase):
    def test_basic_records(self):
        table = _mk_table(
            a=['93.184.216.34'],
            aaaa=[],
            mx=['10 mail.mnnoee.ru.'],
            ns=['ns1.mnnoee.ru.', 'ns2.mnnoee.ru.'],
            dns_txt='"v=spf1 -all"\n',
            dmarc='"v=DMARC1; p=reject"\n',
            dkim={'default': '"v=DKIM1; p=MIGf..."\n'},
        )
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=['default'])
        self.assertIsNone(r['error'])
        self.assertEqual(r['a'], ['93.184.216.34'])
        self.assertEqual(r['mx'], [{'priority': 10, 'host': 'mail.mnnoee.ru'}])
        self.assertEqual(r['spf'], 'v=spf1 -all')
        self.assertEqual(r['dmarc'], 'v=DMARC1; p=reject')
        self.assertEqual(r['dkim']['default'], 'v=DKIM1; p=MIGf...')

    def test_null_mx(self):
        table = _mk_table(mx=['0 .'])
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertEqual(r['mx'], [{'priority': 0, 'host': '.'}])

    def test_no_records_is_not_error(self):
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock({})):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertIsNone(r['error'])
        self.assertEqual(r['a'], [])

    def test_missing_dig_utility(self):
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock({}, missing=True)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertEqual(r['error'], "utility 'dig' not found in PATH")

    def test_dkim_absent_selector_is_null(self):
        table = _mk_table(dkim={'s1': None})
        table[('TXT', 'default._domainkey.mnnoee.ru')] = ''
        table[('TXT', 's1._domainkey.mnnoee.ru')] = ''
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=['default', 's1'])
        self.assertIsNone(r['dkim']['default'])
        self.assertIsNone(r['dkim']['s1'])

    def test_ptr_matching(self):
        table = _mk_table(
            a=['93.184.216.34', '10.0.0.1'],
        )
        ptr = {'93.184.216.34': 'mnnoee.ru.\n', '10.0.0.1': 'other.net.\n'}
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table, ptr=ptr)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertTrue(r['ptr']['93.184.216.34']['matches_domain'])
        self.assertFalse(r['ptr']['10.0.0.1']['matches_domain'])

    def test_ns_inconsistency_detected(self):
        table = _mk_table(
            ns=['ns1.mnnoee.ru.', 'ns2.mnnoee.ru.'],
            a=['93.184.216.34'],
        )
        answers = {
            ('ns1.mnnoee.ru', 'A', 'mnnoee.ru'): '93.184.216.34\n',
            ('ns2.mnnoee.ru', 'A', 'mnnoee.ru'): '203.0.113.5\n',
            ('ns1.mnnoee.ru', 'AAAA', 'mnnoee.ru'): '',
            ('ns2.mnnoee.ru', 'AAAA', 'mnnoee.ru'): '',
        }
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table, ns_answers=answers)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertIsNotNone(r['ns_consistency'])
        self.assertFalse(r['ns_consistency']['consistent'])

    def test_ns_consistency_ok(self):
        table = _mk_table(ns=['ns1.mnnoee.ru.', 'ns2.mnnoee.ru.'], a=['93.184.216.34'])
        answers = {
            ('ns1.mnnoee.ru', 'A', 'mnnoee.ru'): '93.184.216.34\n',
            ('ns2.mnnoee.ru', 'A', 'mnnoee.ru'): '93.184.216.34\n',
            ('ns1.mnnoee.ru', 'AAAA', 'mnnoee.ru'): '',
            ('ns2.mnnoee.ru', 'AAAA', 'mnnoee.ru'): '',
        }
        with mock.patch('domaincheck.dns.run_cmd', side_effect=_DigMock(table, ns_answers=answers)):
            r = run_dns_section('mnnoee.ru', dkim_selectors=[])
        self.assertTrue(r['ns_consistency']['consistent'])

    def test_ptr_map_checks_subdomain(self):
        with mock.patch('domaincheck.dns._dig', return_value=(['mail.mnnoee.ru.'], None)):
            res = _ptr_map(['93.184.216.34'], 'mnnoee.ru', timeout=5)
        self.assertTrue(res['93.184.216.34']['matches_domain'])


if __name__ == '__main__':
    unittest.main()
