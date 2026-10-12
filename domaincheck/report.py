"""Человекочитаемый текстовый отчёт по секциям (RU)."""

import datetime

from .constants import CACHE_FILE


def _days(text):
    """Дней до даты из ISO-строки (или None)."""
    if not text:
        return None
    try:
        dt = datetime.datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return (dt - datetime.datetime.now(datetime.timezone.utc)).days


def _short_date(text):
    if not text:
        return '(нет данных)'
    return text[:10]


def _days_suffix(text):
    d = _days(text)
    if d is None:
        return ''
    return f' (через {d} дн.)'


def report_whois(w):
    lines = ['--- WHOIS / RDAP ---']
    if w.get('error'):
        lines.append(f"  [ошибка] {w['error']}")
        return lines
    lines.append(f"  источник:    {w.get('source', '?')}")
    registered = _short_date(w.get('registered'))
    expiry = _short_date(w.get('expiration'))
    lines.append(f"  регистрация: {registered}")
    lines.append(f"  истекает:    {expiry}{_days_suffix(w.get('expiration'))}")
    lines.append(f"  обновлён:    {_short_date(w.get('last_changed'))}")
    if w.get('registrar'):
        lines.append(f"  регистратор: {w['registrar']}")
    if w.get('dnssec_signed') is not None:
        lines.append(f"  DNSSEC:      {'подписан' if w['dnssec_signed'] else 'не подписан'}")
    if w.get('statuses'):
        lines.append(f"  статусы:     {', '.join(w['statuses'])}")
    if w.get('nameservers'):
        lines.append(f"  NS:          {', '.join(w['nameservers'])}")
    if w.get('abuse_contacts'):
        lines.append(f"  abuse:       {', '.join(w['abuse_contacts'])}")
    return lines


def report_dns(d):
    lines = ['--- DNS ---']
    if d.get('error'):
        lines.append(f"  [ошибка] {d['error']}")
        return lines

    def _recs(key, label):
        v = d.get(key)
        if not v:
            lines.append(f'  {label:<13} (нет записей)')
        else:
            lines.append(f'  {label:<13} {", ".join(v) if isinstance(v, list) else v}')

    _recs('a', 'A')
    _recs('aaaa', 'AAAA')
    if d.get('mx'):
        mx_str = ', '.join(f"{m['priority']} {m['host']}" for m in d['mx'])
        lines.append(f'  {"MX":<13} {mx_str}')
    else:
        lines.append(f'  {"MX":<13} (нет записей)')
    _recs('ns', 'NS')
    for rec in d.get('txt', []):
        lines.append(f'  {"TXT":<13} {rec}')
    if not d.get('txt'):
        lines.append(f'  {"TXT":<13} (нет записей)')
    if d.get('spf'):
        lines.append(f'  {"SPF":<13} {d["spf"]}')
    if d.get('dmarc'):
        lines.append(f'  {"DMARC":<13} {d["dmarc"]}')

    dkim = d.get('dkim') or {}
    found = [(s, r) for s, r in dkim.items() if r]
    no_rec = sum(1 for r in dkim.values() if not r)
    if found:
        for sel, rec in found:
            rec_short = rec if len(rec) <= 60 else rec[:57] + '...'
            lines.append(f'  {"DKIM":<13} {sel} -> {rec_short}')
        lines.append(f'  {"":<13} (без записи: {no_rec})')
    elif dkim:
        lines.append(f'  {"DKIM":<13} (нет записей по {len(dkim)} селекторам)')

    if d.get('ptr'):
        for ip, ptr in sorted(d['ptr'].items()):
            h = ptr.get('hostname')
            if h:
                mark = '[ok]' if ptr.get('matches_domain') else '[!] (не совпадает)'
                lines.append(f'  {"PTR":<13} {ip} -> {h} {mark}')
            else:
                err = ptr.get('error')
                lines.append(f'  {"PTR":<13} {ip} -> (нет PTR)'
                             + (f' [{err}]' if err else ''))

    ns = d.get('ns_consistency')
    if ns:
        state = 'согласованы' if ns.get('consistent') else 'РАССИНХРОН'
        lines.append(f'  {"NS-сверка":<10} {state}')
        for srv, info in ns.get('servers', {}).items():
            if 'a_error' in info:
                lines.append(f'    {srv}: ошибка ({info["a_error"]})')
            elif info.get('aaaa'):
                lines.append(f'    {srv}: A {", ".join(info.get("a", []))}, AAAA {", ".join(info["aaaa"])}')
            else:
                lines.append(f'    {srv}: A {", ".join(info.get("a", []))}')
    return lines


def report_ssl(s):
    lines = [f'--- SSL ({s.get("host")}:{s.get("port")}) ---']
    if s.get('error'):
        lines.append(f"  [ошибка] {s['error']}")
        return lines
    chain = s.get('chain', [])
    lines.append(f'  цепочка: {len(chain)} сертификат(ов)')
    for c in chain:
        subj = c.get('subject') or '(нет subject)'
        exp = c.get('days_until_expiry')
        exp_s = f'— истекает через {exp} дн.' if exp is not None else ''
        lines.append(f'    [{c["depth"]}] {subj}')
        lines.append(f'        issuer:  {c.get("issuer")}')
        lines.append(f'        истекает: {_short_date(c.get("not_after"))} {exp_s}')
        lines.append(f'        алг.:    {c.get("sig_alg")}')
    v = s.get('verify_ok')
    if v is not None:
        lines.append(f'  verify: {"OK" if v else "ПРОБЛЕМА ЦЕПОЧКИ"}')
    return lines


def report_cross(checks):
    if not checks:
        return None
    lines = ['--- Перекрёстные проверки ---']
    for c in checks:
        sev = c.get('severity', 'info')
        mark = {'warning': '[warning]', 'info': '[info]'}.get(sev, f'[{sev}]')
        lines.append(f'  {mark} {c.get("message")}')
    return lines


def build_report(domain, sections, cross_checks=None):
    """Собрать полный текстовый отчёт."""
    lines = ['=' * 50, domain, '=' * 50, '']
    for key in ('whois', 'dns', 'ssl'):
        if key in sections:
            printer = {'whois': report_whois, 'dns': report_dns, 'ssl': report_ssl}[key]
            lines += printer(sections[key])
            lines.append('')
    cross_lines = report_cross(cross_checks or [])
    if cross_lines:
        lines += cross_lines
        lines.append('')
    lines.append(f'* кэш RDAP/whois: {CACHE_FILE} (TTL 7 дней, --no-cache для свежих данных)')
    return '\n'.join(lines)
