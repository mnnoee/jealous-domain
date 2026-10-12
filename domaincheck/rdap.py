"""RDAP-запрос и парсинг ответа (регистратор, даты, статусы, NS, abuse, DNSSEC)."""

from .constants import RDAP_URL
from .parse_utils import http_get, parse_iso, to_ascii


def _extract_vcard_email(entity):
    """Извлечь email из vcardArray сущности."""
    vc = entity.get('vcardArray')
    if not vc or not isinstance(vc, list) or len(vc) < 2:
        return None
    for line in vc[1]:
        if isinstance(line, list) and len(line) >= 4 and line[0] == 'email':
            val = line[3]
            if val and isinstance(val, str) and val.strip():
                return val.strip()
    return None


def _extract_vcard_fn(entity):
    """Извлечь friendly name (fn) из vcardArray сущности."""
    vc = entity.get('vcardArray')
    if not vc or not isinstance(vc, list) or len(vc) < 2:
        return None
    for line in vc[1]:
        if isinstance(line, list) and len(line) >= 4 and line[0] == 'fn':
            val = line[3]
            if val and isinstance(val, str) and val.strip():
                return val.strip()
    return None


def _parse_events(events):
    """Извлечь даты из events (registration, expiration, last changed)."""
    registered = None
    expiration = None
    last_changed = None
    for ev in events:
        action = ev.get('eventAction', '')
        date_str = ev.get('eventDate')
        dt = parse_iso(date_str)
        if action == 'registration':
            registered = dt
        elif action == 'expiration':
            expiration = dt
        elif action == 'last changed':
            last_changed = dt
    return registered, expiration, last_changed


def _parse_entities(entities):
    """Извлечь регистратора и abuse-контакты из entities."""
    registrar = None
    abuse_contacts = []
    for ent in entities:
        roles = ent.get('roles', [])
        if 'registrar' in roles and not registrar:
            registrar = _extract_vcard_fn(ent)
        if 'abuse' in roles:
            email = _extract_vcard_email(ent)
            if email:
                abuse_contacts.append(email)
        # Abuse может быть и вложенной сущностью внутри registrar
        for sub in ent.get('entities', []):
            sub_roles = sub.get('roles', [])
            if 'abuse' in sub_roles:
                email = _extract_vcard_email(sub)
                if email and email not in abuse_contacts:
                    abuse_contacts.append(email)
    return registrar, abuse_contacts


def fetch_rdap(domain, timeout=10):
    """Запросить RDAP для домена, вернуть секцию RDAP.

    Возвращает dict с полями:
        source, registered, expiration, last_changed,
        statuses, nameservers, registrar, abuse_contacts,
        dnssec_signed, error

    error = None если всё ок, иначе текст ошибки.
    """
    url = RDAP_URL.format(domain=to_ascii(domain))
    body, err = http_get(url, timeout=timeout)

    error_msg = None
    if err:
        # RDAP может вернуть 404 для неизвестных зон -> не ошибка модуля,
        # а сигнал для whois-фолбэка
        if '404' in str(err):
            error_msg = f'RDAP returned 404 for {domain}'
        else:
            error_msg = f'RDAP error: {err}'
        return {
            'source': None,
            'registered': None,
            'expiration': None,
            'last_changed': None,
            'statuses': [],
            'nameservers': [],
            'registrar': None,
            'abuse_contacts': [],
            'dnssec_signed': None,
            'error': error_msg,
        }

    try:
        import json
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {
            'source': None,
            'registered': None,
            'expiration': None,
            'last_changed': None,
            'statuses': [],
            'nameservers': [],
            'registrar': None,
            'abuse_contacts': [],
            'dnssec_signed': None,
            'error': 'RDAP response is not valid JSON',
        }

    events = data.get('events', [])
    registered, expiration, last_changed = _parse_events(events)
    statuses = data.get('status', [])
    nameservers = [ns.get('ldhName', '').lower() for ns in data.get('nameservers', [])]
    registrar, abuse_contacts = _parse_entities(data.get('entities', []))

    sdns = data.get('secureDNS', {})
    dnssec_signed = sdns.get('delegationSigned', False) if sdns else False

    return {
        'source': 'rdap',
        'registered': registered,
        'expiration': expiration,
        'last_changed': last_changed,
        'statuses': statuses,
        'nameservers': nameservers,
        'registrar': registrar,
        'abuse_contacts': abuse_contacts,
        'dnssec_signed': dnssec_signed,
        'error': None,
    }
