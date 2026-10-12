"""Unit-тесты: CLI — флаги, селекторы, выбор секций."""

import os
import sys
import tempfile
import unittest
from unittest import mock

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from domaincheck import cli


class ParserTest(unittest.TestCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args(['mnnoee.ru'])
        self.assertFalse(args.whois)
        self.assertFalse(args.dns)
        self.assertFalse(args.ssl)
        self.assertEqual(args.ssl_port, 443)
        self.assertEqual(args.timeout, 10)
        self.assertIsNone(args.json)
        self.assertFalse(args.no_cache)

    def test_flags(self):
        args = cli.build_parser().parse_args([
            'mnnoee.ru', '--whois', '--ssl', '--ssl-port', '8443',
            '--timeout', '5', '--json', 'out.json', '--no-cache',
        ])
        self.assertTrue(args.whois)
        self.assertTrue(args.ssl)
        self.assertFalse(args.dns)
        self.assertEqual(args.ssl_port, 8443)
        self.assertEqual(args.timeout, 5)
        self.assertEqual(args.json, 'out.json')
        self.assertTrue(args.no_cache)

    def test_dkim_selectors_repeatable(self):
        args = cli.build_parser().parse_args(
            ['mnnoee.ru', '--dkim-selector', 'google', '--dkim-selector', 's1'])
        self.assertEqual(args.dkim_selectors, ['google', 's1'])

    def test_json_default_path(self):
        args = cli.build_parser().parse_args(['mnnoee.ru', '--json'])
        self.assertEqual(args.json, 'report.json')


class LoadDkimTest(unittest.TestCase):
    def test_default_file(self):
        sels = cli.load_dkim_selectors()
        self.assertIn('default', sels)
        self.assertIn('google', sels)
        self.assertGreater(len(sels), 0)

    def test_custom_file(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'w') as f:
                f.write('# comment\n\ngm\nselector7\n')
            self.assertEqual(cli.load_dkim_selectors(path), ['gm', 'selector7'])
        finally:
            os.unlink(path)


class MainTest(unittest.TestCase):
    def _stub_runners(self):
        def whois(domain, timeout=10, use_cache=True):
            return {'source': 'rdap', 'error': None, 'expiration': None}
        mycli = cli
        mycli.SECTION_RUNNERS = {
            'whois': whois,
            'dns': lambda domain, dkim_selectors=None, timeout=10: {'error': None, 'a': ['1.2.3.4'], 'ptr': {}},
            'ssl': lambda domain, port=443, timeout=10: {'error': None, 'chain': []},
        }

    def test_all_sections_by_default(self):
        calls = {}
        def mk(name):
            def runner(*a, **kw):
                calls[name] = calls.get(name, 0) + 1
                return {'error': None, 'source': 'stub'}
            return runner
        cli.SECTION_RUNNERS = {k: mk(k) for k in ('whois', 'dns', 'ssl')}
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru']), \
             mock.patch('builtins.print'):
            cli.main()
        self.assertEqual(calls, {'whois': 1, 'dns': 1, 'ssl': 1})

    def test_single_section_flag(self):
        calls = {}
        def mk(name):
            def runner(*a, **kw):
                calls[name] = True
                return {'error': None, 'source': 'stub'}
            return runner
        cli.SECTION_RUNNERS = {k: mk(k) for k in ('whois', 'dns', 'ssl')}
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru', '--ssl']), \
             mock.patch('builtins.print'):
            cli.main()
        self.assertEqual(calls, {'ssl': True})

    def test_ssl_port_passed(self):
        seen = {}
        def ssl(domain, port=443, timeout=10):
            seen['port'] = port
            return {'error': None, 'source': 'stub'}
        cli.SECTION_RUNNERS = {'ssl': ssl}
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru', '--ssl', '--ssl-port', '8443']), \
             mock.patch('builtins.print'):
            cli.main()
        self.assertEqual(seen['port'], 8443)

    def test_cross_checks_run_when_two_sections(self):
        dns = {'error': None, 'a': ['93.184.216.34'], 'ptr': {
            '93.184.216.34': {'hostname': 'other.net', 'matches_domain': False}}}
        cli.run_dns_section = lambda domain, dkim_selectors=None, timeout=10: dns
        cli.run_whois_section = lambda domain, timeout=10, use_cache=True: {
            'error': None, 'expiration': None, 'source': 'stub'}
        cli.SECTION_RUNNERS = {
            'whois': cli.run_whois_section,
            'dns': cli.run_dns_section,
        }
        out = []
        def fake_print(text):
            out.append(text)
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru', '--dns', '--whois']), \
             mock.patch('builtins.print', side_effect=fake_print):
            cli.main()
        joined = ' '.join(out)
        self.assertIn('не совпадает', joined)

    def test_json_written(self):
        tmp = tempfile.mkdtemp()
        out_path = os.path.join(tmp, 'report.json')
        cli.SECTION_RUNNERS = {
            'whois': lambda domain, timeout=10, use_cache=True: {
                'error': None, 'source': 'stub'},
        }
        with mock.patch('sys.argv',
                        ['domain_checker.py', 'mnnoee.ru', '--whois', '--json', out_path]), \
             mock.patch('builtins.print'):
            cli.main()
        import json
        with open(out_path) as f:
            doc = json.load(f)
        self.assertEqual(doc['meta']['domain'], 'mnnoee.ru')
        self.assertEqual(doc['meta']['sections_run'], ['whois'])

    def test_all_flag_runs_everything(self):
        calls = {}

        def mk(name):
            def runner(*a, **kw):
                calls[name] = True
                return {'error': None, 'source': 'stub'}
            return runner

        cli.SECTION_RUNNERS = {k: mk(k) for k in ('whois', 'dns', 'ssl')}
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru', '--all']), \
             mock.patch('builtins.print'):
            cli.main()
        self.assertEqual(calls, {'whois': True, 'dns': True, 'ssl': True})

    def test_section_isolation_on_failure(self):
        # падение одной секции не роняет остальные: error в её секции
        def broken(domain, timeout=10, use_cache=True):
            raise RuntimeError('сеть недоступна')

        cli.SECTION_RUNNERS = {
            'whois': broken,
            'dns': lambda domain, dkim_selectors=None, timeout=10: {'error': None, 'a': []},
        }
        out = []
        with mock.patch('sys.argv', ['domain_checker.py', 'mnnoee.ru', '--whois', '--dns']), \
             mock.patch('builtins.print', side_effect=lambda t: out.append(str(t))):
            cli.main()
        joined = ' '.join(out)
        self.assertIn('whois section failed', joined)
        self.assertNotIn('dns section failed', joined)


class LoadDkimMissingFileTest(unittest.TestCase):
    def test_missing_file_falls_back_to_defaults(self):
        from domaincheck.constants import DEFAULT_DKIM_SELECTORS
        selectors = cli.load_dkim_selectors('/нет/такого/файла/selectors.txt')
        self.assertEqual(selectors, list(DEFAULT_DKIM_SELECTORS))

    def test_empty_file_falls_back_to_defaults(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
            f.write('# только комментарий\n\n   \n')
            path = f.name
        try:
            from domaincheck.constants import DEFAULT_DKIM_SELECTORS
            selectors = cli.load_dkim_selectors(path)
            self.assertEqual(selectors, list(DEFAULT_DKIM_SELECTORS))
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
