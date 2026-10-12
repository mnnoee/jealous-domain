"""Перекрёстные проверки между секциями (без новых запросов)."""

import datetime

from .constants import SSL_EXPIRY_WARN_DAYS

DOMAIN_LONG_HORIZON_DAYS = 90


def _parse_iso(s):
    try:
        dt = datetime.datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        # наивные даты (без зоны) трактуются как UTC — иначе сравнение
        # с aware-датами из SSL-цепочки падает с TypeError
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _days_from_now(dt):
    if dt is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return (dt - now).days


def run_cross_checks(whois, dns, ssl):
    """Сверить данные уже собранных секций.

    whois/dns/ssl — dict секций (или None, если не запущены/ошибка).
    Возвращает список {"severity": ..., "message": ...}.
    """
    checks = []
    if _in_error(whois):
        whois = None
    if _in_error(dns):
        dns = None
    # ssl: НЕ отбрасываем при error — ошибка SSL как раз сигнал для
    # проверки "A есть, а порт закрыт/сервис не слушает"

    # --- сертификат vs домен ---
    if whois and ssl and ssl.get('chain') and not ssl.get('error'):
        domain_exp = _parse_iso(whois.get('expiration'))
        leaf = ssl['chain'][0]
        cert_exp = _parse_iso(leaf.get('not_after'))
        if domain_exp and cert_exp:
            if cert_exp > domain_exp:
                checks.append({
                    'severity': 'warning',
                    'message': f"Сертификат действует дольше, чем домен: домен истекает "
                               f"{_days_from_now(domain_exp)} дн., а сертификат — после него — бесполезный сертификат",
                })
            cert_days = _days_from_now(cert_exp)
            domain_days = _days_from_now(domain_exp)
            if cert_days is not None and domain_days is not None \
                    and 0 <= cert_days < SSL_EXPIRY_WARN_DAYS and domain_days > DOMAIN_LONG_HORIZON_DAYS:
                checks.append({
                    'severity': 'warning',
                    'message': f"Сертификат истекает через {cert_days} дн., а домен продлён "
                               f"на {domain_days} дн. вперёд — обновить сертификат",
                })

    # --- PTR vs A/AAAA ---
    if dns:
        for ip, ptr in sorted(dns.get('ptr', {}).items()):
            hostname = ptr.get('hostname')
            matches = ptr.get('matches_domain')
            if hostname and matches is False:
                checks.append({
                    'severity': 'warning',
                    'message': f"PTR для {ip} указывает на {hostname} — не совпадает с доменом",
                })
            elif hostname and matches:
                checks.append({
                    'severity': 'info',
                    'message': f"PTR для {ip} резолвится в {hostname} — совпадает с доменом",
                })

    # --- A запись есть, а SSL не поднялся ---
    if dns and ssl and ssl.get('error'):
        a_records = dns.get('a', [])
        if a_records:
            joined = ', '.join(a_records)
            checks.append({
                'severity': 'warning',
                'message': f"A-запись есть ({joined}), но SSL подключение "
                           f"не удалось: {ssl['error']}",
            })

    return checks


def _in_error(section):
    """Секция отсутствует или содержит error."""
    if section is None:
        return True
    if isinstance(section, dict) and section.get('error'):
        return True
    return False
