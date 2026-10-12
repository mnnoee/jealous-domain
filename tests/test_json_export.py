"""Unit-тесты: JSON-экспорт — схема, секции, error-поле."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck.constants import VERSION
from domaincheck.json_export import build_json, write_json_report


def _section(**kwargs):
    base = {
        'source': 'rdap', 'registered': None, 'expiration': None,
        'last_changed': None, 'statuses': [], 'nameservers': [],
        'registrar': None, 'abuse_contacts': [], 'dnssec_signed': None,
        'error': None,
    }
    base.update(kwargs)
    return base


class JsonExportTest(unittest.TestCase):
    def test_schema_shape(self):
        sections = {
            'whois': _section(error=None),
            'dns': {'a': ['93.184.216.34'], 'error': None},
            'ssl': {'chain': [], 'verify_ok': True, 'error': None},
        }
        doc = build_json('mnnoee.ru', sections, [
            {'severity': 'info', 'message': 'x'},
        ])
        self.assertEqual(doc['meta']['version'], VERSION)
        self.assertEqual(doc['meta']['domain'], 'mnnoee.ru')
        self.assertEqual(doc['meta']['sections_run'], ['whois', 'dns', 'ssl'])
        self.assertIn('checked_at', doc['meta'])
        for key in ('whois', 'dns', 'ssl'):
            self.assertIn('error', doc[key])
        self.assertEqual(doc['cross_checks'][0]['severity'], 'info')

    def test_sections_run_matches_selected(self):
        doc = build_json('mnnoee.ru', {'ssl': _section(error='down')})
        self.assertEqual(doc['meta']['sections_run'], ['ssl'])
        self.assertEqual(doc['ssl']['error'], 'down')
        # незапущенные секции не попадают в отчёт
        self.assertNotIn('whois', doc)
        self.assertNotIn('dns', doc)

    def test_empty_cross_checks(self):
        doc = build_json('mnnoee.ru', {})
        self.assertEqual(doc['cross_checks'], [])

    def test_write_json_report(self):
        path = os.path.join(tempfile.mkdtemp(), 'out.json')
        written = write_json_report('mnnoee.ru', {'dns': {'a': [], 'error': None}}, path)
        with open(written) as f:
            data = json.load(f)
        self.assertEqual(data['meta']['domain'], 'mnnoee.ru')
        self.assertEqual(data['dns']['error'], None)


if __name__ == '__main__':
    unittest.main()
