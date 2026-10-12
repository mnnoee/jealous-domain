"""DNS-секция: dig-запросы, DKIM-селекторы, SPF-фильтр, PTR, сверка NS."""

import re
import shutil

from .constants import DEFAULT_DKIM_SELECTORS, TIMEOUT
from .parse_utils import run_cmd, to_ascii

_SPF_RE = re.compile(r'^v=spf1', re.IGNORECASE)


def _dig(args, timeout=TIMEOUT):
    """dig +short с таймаутом. Вернёт (список строк, error|None)."""
    out, err = run_cmd(['dig', '+short'] + args, timeout=timeout)
    if err:
        return [], err
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines, None


def _txt_lines(lines):
    """Объединить фрагменты TXT-записи (кавычки) в строку записи."""
    out = []
    for line in lines:
        frags = re.findall(r'"([^"]*)"', line)
        if frags:
            record = ''.join(frags)
        else:
            record = line
        if record and record not in out:
            out.append(record)
    return out


def _strip_dot(s):
    return s.rstrip('.').lower()


def _dig_record(args, timeout=TIMEOUT):
    lines, err = _dig(args, timeout=timeout)
    if err:
        return [], err
    return [_strip_dot(ln) for ln in lines], None


def _dig_one(args, timeout=TIMEOUT):
    """dig +short — единственное значение записи (для dmarc/dkim/spf)."""
    lines, err = _dig(args, timeout=timeout)
    if err:
        return None, err
    records = _txt_lines(lines)
    return records[0] if records else None, None


def _parse_mx(lines):
    mx = []
    for line in lines:
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            host_raw = parts[1].strip()
            # null-MX (RFC 7505): приоритет 0, хост '.' — оставить маркер
            host = '.' if host_raw == '.' else _strip_dot(host_raw)
            mx.append({'priority': int(parts[0]), 'host': host})
        else:
            host = _strip_dot(line)
            if host:
                mx.append({'priority': 0, 'host': host})
    return mx


def _ptr_map(ips, domain, timeout=TIMEOUT):
    """PTR (reverse) для каждого адреса: {ip: {hostname, matches_domain}}."""
    result = {}
    for ip in ips:
        lines, err = _dig(['-x', ip], timeout=timeout)
        if err:
            result[ip] = {'hostname': None, 'matches_domain': False, 'error': err}
            continue
        hostnames = [_strip_dot(ln) for ln in lines]
        result[ip] = {
            'hostname': hostnames[0] if hostnames else None,
            'matches_domain': bool(hostnames) and _matches_domain(hostnames[0], domain),
            'all': hostnames,
        }
    return result


def _matches_domain(hostname, domain):
    return hostname == domain or hostname.endswith('.' + domain)


def _ns_consistency(domain, ns_list, timeout=TIMEOUT):
    """Сверка ответов A/AAAA для домена у каждого NS (детект рассинхрона)."""
    if len(ns_list) < 2:
        return None
    servers = {}
    for ns in ns_list:
        a, a_err = _dig_record(['@' + ns, 'A', domain], timeout=timeout)
        aaaa, aaaa_err = _dig_record(['@' + ns, 'AAAA', domain], timeout=timeout)
        servers[ns] = {}
        if a_err:
            servers[ns]['a_error'] = a_err
        else:
            servers[ns]['a'] = a
        if aaaa_err:
            servers[ns]['aaaa_error'] = aaaa_err
        else:
            servers[ns]['aaaa'] = aaaa
    # согласованность: все A и AAAA без ошибок должны совпадать
    a_sets = [set(v['a']) for v in servers.values() if not v.get('a_error')]
    aaaa_sets = [set(v['aaaa']) for v in servers.values() if not v.get('aaaa_error')]
    errors = [v for v in servers.values() if v.get('a_error') or v.get('aaaa_error')]
    consistent = (len(a_sets) > 0 and len(aaaa_sets) >= 0) and (len(set(map(tuple, map(sorted, a_sets)))) <= 1
                                                                and len(set(map(tuple, map(sorted, aaaa_sets)))) <= 1
                                                                ) and not errors
    return {'consistent': consistent, 'servers': servers}


def run_dns_section(domain, dkim_selectors=None, timeout=TIMEOUT):
    """Собрать DNS-секцию через dig.

    dkim_selectors: список селекторов для _domainkey (по умолчанию
    берётся из дефолтного списка в constants).
    """
    domain = to_ascii(domain)  # IDN -> punycode: dig требует ASCII
    if dkim_selectors is None:
        dkim_selectors = DEFAULT_DKIM_SELECTORS

    base = {
        'a': [],
        'aaaa': [],
        'mx': [],
        'ns': [],
        'txt': [],
        'spf': None,
        'dmarc': None,
        'dkim': {sel: None for sel in dkim_selectors},
        'ptr': {},
        'ns_consistency': None,
        'error': None,
    }

    if not shutil.which('dig'):
        base['error'] = "utility 'dig' not found in PATH"
        return base

    # A / AAAA / MX / NS / TXT
    a_lines, err = _dig_record(['A', domain], timeout=timeout)
    if err:
        base['error'] = err
        return base
    base['a'] = a_lines

    aaaa_lines, err = _dig_record(['AAAA', domain], timeout=timeout)
    if err:
        base['aaaa'] = []
    else:
        base['aaaa'] = aaaa_lines

    mx_lines, err = _dig(['MX', domain], timeout=timeout)
    if err:
        base['mx'] = []
    else:
        base['mx'] = _parse_mx(mx_lines)

    ns_lines, err = _dig_record(['NS', domain], timeout=timeout)
    if err:
        base['ns'] = []
    else:
        base['ns'] = ns_lines

    txt_lines, err = _dig(['TXT', domain], timeout=timeout)
    if err:
        base['txt'] = []
    else:
        base['txt'] = _txt_lines(txt_lines)

    # SPF — из общего TXT
    spf = None
    for rec in base['txt']:
        if _SPF_RE.match(rec):
            spf = rec
            break
    base['spf'] = spf

    # DMARC
    dmarc, _ = _dig_one(['TXT', '_dmarc.' + domain], timeout=timeout)
    base['dmarc'] = dmarc

    # DKIM по селекторам
    for sel in dkim_selectors:
        rec, _ = _dig_one(['TXT', f'{sel}._domainkey.' + domain], timeout=timeout)
        base['dkim'][sel] = rec

    # PTR для каждого A/AAAA
    base['ptr'] = _ptr_map(base['a'] + base['aaaa'], domain, timeout=timeout)

    # Сверка NS
    if len(base['ns']) >= 2:
        base['ns_consistency'] = _ns_consistency(domain, base['ns'], timeout=timeout)

    return base
