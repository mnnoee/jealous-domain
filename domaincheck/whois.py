"""Whois-секция: кэш, RDAP + фолбэк на классический whois, парсинг текста, abuse."""

import json
import os
import re
import time

from . import rdap
from .constants import ABUSE_FALLBACK_KEYS, ABUSE_KEYS, CACHE_FILE, CACHE_TTL
from .parse_utils import parse_iso, run_cmd, to_ascii

CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), CACHE_FILE)
_cache = None

# ключи в whois-тексте — каноническая форма: нижний регистр, без пробелов/дефисов/подчёркиваний
CREATED_KEYS = {'creationdate', 'registrationdate', 'registered', 'created', 'createdon', 'domainrecordactivated'}
EXPIRY_KEYS = {'registryexpirydate', 'registrarregistrationexpirationdate', 'expirationdate', 'expirydate',
               'expires', 'expirationtime', 'paidtill', 'paidtilldate'}
CHANGED_KEYS = {'updateddate', 'lastupdated', 'lastmodified', 'changed', 'modified'}
REGISTRAR_KEYS = {'registrar', 'registrarname', 'sponsoringregistrar'}
STATUS_KEYS = {'domainstatus', 'state', 'status'}
NS_KEYS = {'nameserver', 'nserver'}
DNSSEC_SIGNED_VALUES = {'signeddelegation', 'signed'}


def _normalize_key(key):
    return re.sub(r'[\s_\-]+', '', key).lower()


# нормализованные варианты abuse-ключей (логика как в nginxparse/whois.py)
ABUSE_KEYS_NORM = tuple(_normalize_key(k) for k in ABUSE_KEYS)
ABUSE_FALLBACK_KEYS_NORM = tuple(_normalize_key(k) for k in ABUSE_FALLBACK_KEYS)


def parse_whois_text(text):
    """Распарсить классический whois-вывод в секцию whois.

    == {
        registered, expiration, last_changed: datetime|None,
        registrar, dnssec_signed: str|None / bool|None,
        statuses, nameservers, abuse_contacts: list,
    }
    """
    res = {
        'registered': None,
        'expiration': None,
        'last_changed': None,
        'registrar': None,
        'statuses': [],
        'nameservers': [],
        'abuse_contacts': [],
        'dnssec_signed': None,
    }
    seen_abuse = set()
    fallback = []
    seen_fallback = set()
    for line in text.splitlines():
        m = re.match(r'^\s*([^:]+):\s*(.+?)\s*$', line)
        if not m:
            continue
        key = _normalize_key(m.group(1))
        val = m.group(2).strip()

        if key in CREATED_KEYS and res['registered'] is None:
            res['registered'] = parse_iso(val)
        elif key in EXPIRY_KEYS and res['expiration'] is None:
            res['expiration'] = parse_iso(val)
        elif key in CHANGED_KEYS and res['last_changed'] is None:
            res['last_changed'] = parse_iso(val)
        elif key in REGISTRAR_KEYS and not res['registrar']:
            res['registrar'] = val
        elif key in STATUS_KEYS:
            for st in re.split(r',\s*', val):
                # убираем суффиксы url (https://icann.org/epp#...)
                st = re.sub(r'\s+https?://\S+$', '', st).strip()
                if st and st not in res['statuses']:
                    res['statuses'].append(st)
        elif key in NS_KEYS:
            ns = val.rstrip('.').lower()
            if ns and ns not in res['nameservers']:
                res['nameservers'].append(ns)
        elif key == 'dnssec':
            res['dnssec_signed'] = val.strip().lower() in DNSSEC_SIGNED_VALUES
        elif key in ABUSE_KEYS_NORM:
            if val and val not in seen_abuse:
                seen_abuse.add(val)
                res['abuse_contacts'].append(val)
        elif key in ABUSE_FALLBACK_KEYS_NORM:
            if val and val not in seen_fallback:
                seen_fallback.add(val)
                fallback.append(val)

    if not res['abuse_contacts']:
        res['abuse_contacts'] = fallback
    return res


# ---------------------------------------------------------------------------
# кэш raw-вывода (паттерн nginxparse/whois.py)
# ---------------------------------------------------------------------------

def _load_cache():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_PATH) as f:
                _cache = json.load(f)
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    tmp = CACHE_PATH + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp, CACHE_PATH)
    except OSError:
        pass


def _cached_raw(domain, key, ttl=CACHE_TTL):
    cache = _load_cache()
    entry = cache.get(domain)
    if entry and key in entry and time.time() - entry.get('t', 0) < ttl:
        return entry.get(key)
    return None


def _store_raw(domain, key, value):
    cache = _load_cache()
    entry = cache.setdefault(domain, {'t': time.time()})
    entry['t'] = time.time()
    entry[key] = value
    _save_cache(cache)


def _do_whois(domain, timeout):
    out, err = run_cmd(['whois', to_ascii(domain)], timeout=timeout)
    if err:
        return None, err
    if not out.strip():
        return None, 'whois returned empty output'
    return out, None


# ---------------------------------------------------------------------------
# секция
# ---------------------------------------------------------------------------

def _to_iso(dt):
    return dt.isoformat() if dt else None


def _format_section(d):
    return {
        'source': 'whois',
        'registered': _to_iso(d['registered']),
        'expiration': _to_iso(d['expiration']),
        'last_changed': _to_iso(d['last_changed']),
        'registrar': d['registrar'],
        'statuses': d['statuses'],
        'nameservers': d['nameservers'],
        'abuse_contacts': d['abuse_contacts'],
        'dnssec_signed': d['dnssec_signed'],
        'error': d.get('error'),
    }


def run_whois_section(domain, timeout=10, use_cache=True):
    """Собрать whois-секцию: RDAP -> фолбэк на классический whois.

    Возвращает dict с полями как в JSON-схеме (включая 'error').
    """
    if use_cache:
        cached = _cached_raw(domain, 'section')
        if cached is not None:
            return dict(cached)

    section = _try_rdap(domain, timeout)
    if section['error'] is None:
        _maybe_store(domain, use_cache, section)
        return section

    # фолбэк на классический whois при 404/недоступности RDAP
    section = _try_whois(domain, timeout)
    _maybe_store(domain, use_cache, section)
    return section


def _try_rdap(domain, timeout):
    res = rdap.fetch_rdap(domain, timeout=timeout)
    base = {
        'source': 'rdap',
        'registered': _to_iso(res['registered']),
        'expiration': _to_iso(res['expiration']),
        'last_changed': _to_iso(res['last_changed']),
        'registrar': res['registrar'],
        'statuses': res['statuses'],
        'nameservers': res['nameservers'],
        'abuse_contacts': res['abuse_contacts'],
        'dnssec_signed': res['dnssec_signed'],
    }
    if res['error']:
        base['error'] = res['error']
        return base
    base['error'] = None
    return base


def _try_whois(domain, timeout):
    base = {
        'source': 'whois',
        'registered': None,
        'expiration': None,
        'last_changed': None,
        'registrar': None,
        'statuses': [],
        'nameservers': [],
        'abuse_contacts': [],
        'dnssec_signed': None,
    }
    raw, err = _do_whois(domain, timeout)
    if err:
        base['error'] = err
        return base
    parsed = parse_whois_text(raw)
    parsed['source'] = 'whois'
    parsed['error'] = None
    return _format_section(parsed)


def _maybe_store(domain, use_cache, section):
    if use_cache:
        _store_raw(domain, 'section', section)
