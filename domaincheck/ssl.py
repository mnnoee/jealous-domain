"""SSL/TLS-секция: openssl s_client + x509, цепочка, дни до истечения, verify."""

import datetime
import re

from .parse_utils import run_cmd, to_ascii

PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.DOTALL)
DEPTH_RE = re.compile(r'^depth=(\d+)', re.MULTILINE)
VERIFY_RETURN_RE = re.compile(r'^verify return:(\d+)$', re.MULTILINE)
VERIFY_CODE_RE = re.compile(r'Verify return code:\s*(\d+)')
_SIG_ALG_RE = re.compile(r'^\s*Signature Algorithm:\s*(.+)$', re.MULTILINE)

_DATE_FMT = '%b %d %H:%M:%S %Y %Z'


def _parse_date(s):
    """'Jul 29 22:10:08 2026 GMT' -> datetime(UTC)."""
    if not s:
        return None
    s = re.sub(r'\s+', ' ', s.strip())
    try:
        dt = datetime.datetime.strptime(s, _DATE_FMT)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        return None


def _parse_x509_cert(pem, timeout):
    """Распарсить один сертификат через openssl x509."""
    out, err = run_cmd(
        ['openssl', 'x509', '-noout', '-subject', '-issuer', '-startdate', '-enddate', '-text'],
        timeout=timeout, input_text=pem)
    if err:
        return None
    subject = issuer = sig_alg = None
    not_before = not_after = None
    for m in out.splitlines():
        if m.startswith('subject=') and subject is None:
            subject = m[len('subject='):]
        elif m.startswith('issuer=') and issuer is None:
            issuer = m[len('issuer='):]
        elif m.startswith('notBefore='):
            not_before = _parse_date(m[len('notBefore='):])
        elif m.startswith('notAfter='):
            not_after = _parse_date(m[len('notAfter='):])
        elif m.startswith('Signature Algorithm:') and sig_alg is None:
            sig_alg = m[len('Signature Algorithm:'):].strip()
    sm = _SIG_ALG_RE.search(out)
    if sm and sig_alg is None:
        sig_alg = sm.group(1).strip()
    return {
        'subject': subject,
        'issuer': issuer,
        'not_before': not_before.isoformat() if not_before else None,
        'not_after': not_after.isoformat() if not_after else None,
        'signature_algorithm': sig_alg,
    }


def _parse_chain(raw_output, timeout):
    """Извлечь PEM-блоки из s_client и распарсить каждый x509."""
    chain = []
    blocks = PEM_RE.findall(raw_output)
    for i, pem in enumerate(blocks):
        info = _parse_x509_cert(pem, timeout)
        if not info:
            continue
        not_after = None
        if info['not_after']:
            try:
                not_after = datetime.datetime.fromisoformat(info['not_after'])
            except ValueError:
                pass
        chain.append({
            'depth': i,
            'subject': info['subject'],
            'issuer': info['issuer'],
            'not_before': info['not_before'],
            'not_after': info['not_after'],
            'days_until_expiry': _days_until(not_after),
            'sig_alg': info['signature_algorithm'],
        })
    return chain


def _days_until(dt):
    if dt is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return (dt - now).days


def _parse_verify(raw_output):
    """Verify: (verify_ok, per-depth list)."""
    m = VERIFY_CODE_RE.search(raw_output)
    verify_ok = None
    if m:
        verify_ok = int(m.group(1)) == 0
    depths = []
    for dm in DEPTH_RE.finditer(raw_output):
        d = int(dm.group(1))
        tail = raw_output[dm.end():]
        vm = VERIFY_RETURN_RE.search(tail)
        depths.append({'depth': d, 'verify_return': int(vm.group(1)) if vm else None})
    return verify_ok, depths


def run_ssl_section(host, port=443, timeout=10, verify_depth=10):
    """Собрать SSL-секцию через openssl s_client."""
    host = to_ascii(host)  # IDN -> punycode: openssl и SNI требуют ASCII
    base = {
        'host': host,
        'port': port,
        'chain': [],
        'verify_ok': None,
        'verify_depths': [],
        'raw_output': None,
        'error': None,
    }

    cmd = ['openssl', 's_client', '-connect', f'{host}:{port}',
           '-servername', host, '-verify', str(verify_depth), '-showcerts']
    out, err = run_cmd(cmd, timeout=timeout)
    if err:
        base['error'] = err
        base['raw_output'] = out or None
        return base

    base['raw_output'] = out
    base['chain'] = _parse_chain(out, timeout)
    verify_ok, depths = _parse_verify(out)
    base['verify_ok'] = verify_ok
    base['verify_depths'] = depths

    # verify-строка с 'certificate expired' и т.п. — часть raw_output, не error:
    # наличие цепочки != ошибке подключения, verify_ok уже отражает это.
    return base
