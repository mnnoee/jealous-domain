"""Чистые утилиты: запуск subprocess, проверка утилит, парсинг дат."""

import datetime
import re
import shutil
import subprocess
import urllib.error
import urllib.request

from .constants import TIMEOUT

# ---------------------------------------------------------------------------
# subprocess helpers
# ---------------------------------------------------------------------------

_missing_utils = set()


def _check_utility(name):
    """Проверить наличие утилиты в PATH (однократно)."""
    if name not in _missing_utils and not shutil.which(name):
        _missing_utils.add(name)
    return name not in _missing_utils


def run_cmd(cmd, timeout=TIMEOUT, input_text=None):
    """Запустить команду, вернуть (stdout, error|None).

    Если утилита не найдена — error='utility ... not found in PATH'.
    Если таймаут — error='timeout'.
    Если ненулевой exit — error содержит stderr.
    input_text — строка, подаваемая на stdin (как < /dev/null или echo | cmd).
    """
    util = cmd[0]
    if not shutil.which(util):
        return '', f"utility '{util}' not found in PATH"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout, input=input_text,
        )
        if proc.returncode != 0 and proc.stderr.strip():
            # первая строка stderr у многих утилит — эхо опций ("verify depth is 10"),
            # реальная причина обычно в последней строке
            return proc.stdout, proc.stderr.strip().splitlines()[-1].strip()
        return proc.stdout, None
    except subprocess.TimeoutExpired:
        return '', f"'{util}' timed out after {timeout}s"
    except (FileNotFoundError, OSError) as e:
        return '', str(e)


def http_get(url, timeout=TIMEOUT):
    """GET-запрос через urllib, вернуть (body, error|None).

    При HTTP 4xx/5xx возвращает (body, 'HTTP <code>').
    При таймауте/сетевой ошибке — (None, message).
    """
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': f'domaincheck/{0}', 'Accept': 'application/rdap+json'},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace'), None
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace') if e.fp else ''
        return body, f'HTTP {e.code}'
    except (urllib.error.URLError, OSError) as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# дата / нормализация
# ---------------------------------------------------------------------------

_DATE_FORMATS = [
    '%Y-%m-%dT%H:%M:%S%z',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
    '%d-%b-%Y',
    '%d %b %Y',
    '%Y/%m/%d',
]


def parse_dt(s):
    """Парсинг строки даты в datetime (с offset или UTC)."""
    if not s:
        return None
    s = s.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def parse_iso(s):
    """Парсинг ISO-строки в datetime (RFC 3339, RDAP-стиль)."""
    if not s:
        return None
    s = s.strip()
    # 'Z' -> '+00:00'
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        return datetime.datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return parse_dt(s)


def normalize_domain(raw):
    """Убрать схему, path, порт — оставить чистый домен."""
    d = raw.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0]
    d = d.split(':')[0]
    return d.rstrip('.')


def to_ascii(domain):
    """IDN -> punycode (xn--...): dig, openssl и URL требуют ASCII.

    ASCII-домены возвращаются как есть; при ошибке кодирования — тоже
    (пусть сеть вернёт осмысленную ошибку, а не молчаливую замену).
    """
    try:
        return domain.encode('idna').decode('ascii')
    except UnicodeError:
        return domain


def days_until(dt):
    """Дней до datetime (положительное = ещё не истёк)."""
    if dt is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = dt - now
    return delta.days
