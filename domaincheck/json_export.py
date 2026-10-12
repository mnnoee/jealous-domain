"""JSON-экспорт: машиночитаемый отчёт (как в nginx_parser/strace_parser)."""

import datetime
import json
import os

from .constants import VERSION

SECTION_ORDER = ('whois', 'dns', 'ssl')


def build_json(domain, sections, cross_checks=None):
    """Собрать dict-отчёт: meta + секции + cross_checks.

    sections — dict {'whois': {...}, 'dns': {...}, 'ssl': {...}}.
    Поля секций уже ISO-строки / списки; 'error' в каждой секции обязателен.
    """
    doc = {
        'meta': {
            'version': VERSION,
            'domain': domain,
            'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'sections_run': [k for k in SECTION_ORDER if k in sections],
        },
    }
    for key in SECTION_ORDER:
        if key in sections:
            doc[key] = sections[key]
    doc['cross_checks'] = list(cross_checks or [])
    return doc


def write_json_report(domain, sections, path='report.json', cross_checks=None):
    """Записать report.json (машиночитаемый отчёт), вернуть путь."""
    doc = build_json(domain, sections, cross_checks)
    full = os.path.abspath(path)
    with open(full, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, default=str)
    return full
