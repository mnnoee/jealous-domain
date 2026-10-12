"""CLI: argparse, main(). Один флаг на секцию (=> чекбоксы UI)."""

import argparse
import os
import sys

from . import cross, json_export, report
from .constants import DEFAULT_DKIM_SELECTORS, SSL_PORT, TIMEOUT, VERSION
from .dns import run_dns_section
from .parse_utils import normalize_domain
from .ssl import run_ssl_section
from .whois import run_whois_section

_DKIM_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dkim_selectors.txt')

SECTION_RUNNERS = {
    'whois': run_whois_section,
    'dns': run_dns_section,
    'ssl': run_ssl_section,
}


def load_dkim_selectors(path=None):
    """Селекторы DKIM из файла (по одному на строку, # — комментарии)."""
    path = path or _DKIM_FILE
    selectors = []
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                sel = line.split('#', 1)[0].strip()
                if sel:
                    selectors.append(sel)
    except OSError:
        selectors = []
    return selectors or list(DEFAULT_DKIM_SELECTORS)


def build_parser():
    ap = argparse.ArgumentParser(
        description='Диагностика домена: RDAP/whois, DNS, SSL. '
                    'Поведение по умолчанию — все секции.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Примеры:\n'
            '  python3 domain_checker.py example.com                # все секции\n'
            '  python3 domain_checker.py example.com --ssl          # только SSL\n'
            '  python3 domain_checker.py example.com --dns --ssl    # DNS + SSL\n'
            '  python3 domain_checker.py example.com --dkim-selector google --dkim-selector s1\n'
            '  python3 domain_checker.py example.com --json report.json\n'
        ))
    ap.add_argument('--version', action='version',
                    version=f'%(prog)s {VERSION}')
    ap.add_argument('domain', help='домен или хост для диагностики')
    ap.add_argument('--whois', action='store_true', help='секция RDAP/whois')
    ap.add_argument('--dns', action='store_true', help='секция DNS (dig)')
    ap.add_argument('--ssl', action='store_true', help='секция SSL/TLS (openssl)')
    ap.add_argument('--all', action='store_true', help='включить все секции')
    ap.add_argument('--dkim-selector', dest='dkim_selectors', action='append', metavar='NAME',
                    help='селектор DKIM для перебора (можно несколько раз); переопределяет файл списка')
    ap.add_argument('--dkim-file', metavar='PATH',
                    help='файл со списком DKIM-селекторов (по умолчанию dkim_selectors.txt)')
    ap.add_argument('--ssl-port', type=int, default=SSL_PORT, metavar='N',
                    help=f'порт для SSL-секции (по умолчанию {SSL_PORT})')
    ap.add_argument('--timeout', type=float, default=TIMEOUT, metavar='SEC',
                    help=f'таймаут на каждый запрос/подпроцесс, сек (по умолчанию {TIMEOUT})')
    ap.add_argument('--no-cache', action='store_true',
                    help='не использовать кэш RDAP/whois (.whois_cache.json)')
    ap.add_argument('--json', nargs='?', const='report.json', metavar='PATH',
                    help='записать машиночитаемый JSON-отчёт (по умолчанию report.json)')
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()

    domain = normalize_domain(args.domain)
    selected = [k for k in ('whois', 'dns', 'ssl') if getattr(args, k)]
    if args.all:
        selected = list(SECTION_RUNNERS)
    if not selected:  # поведение по умолчанию — все секции
        selected = list(SECTION_RUNNERS)

    dkim_selectors = args.dkim_selectors or load_dkim_selectors(args.dkim_file)

    sections = {}
    for name in SECTION_RUNNERS:
        if name not in selected:
            continue
        runner = SECTION_RUNNERS[name]
        try:
            if name == 'whois':
                sections[name] = runner(domain, timeout=args.timeout, use_cache=not args.no_cache)
            elif name == 'dns':
                sections[name] = runner(domain, dkim_selectors=dkim_selectors, timeout=args.timeout)
            else:
                sections[name] = runner(domain, port=args.ssl_port, timeout=args.timeout)
        except Exception as e:  # изоляция секций: сбой одной не роняет остальные
            sections[name] = {'error': f'{name} section failed: {e}'}

    cross_checks = cross.run_cross_checks(
        sections.get('whois'), sections.get('dns'), sections.get('ssl')) \
        if len(sections) >= 2 else []

    print(report.build_report(domain, sections, cross_checks))

    if args.json:
        path = json_export.write_json_report(domain, sections, args.json, cross_checks)
        print(f'\nJSON-отчёт записан в: {path}', file=sys.stderr)

    if not sections:
        print('Нечего выполнять — включите хотя бы одну секцию или --all', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
