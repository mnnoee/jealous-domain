# jealous-domain

[README in English](README.md)

[![CI](https://github.com/mnnoee/jealous-domain/actions/workflows/ci.yml/badge.svg)](https://github.com/mnnoee/jealous-domain/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](CHANGELOG.md)

> Часть набора инструментов [Jealous Moon](https://github.com/mnnoee) —
> офлайн-диагностики серверов и доменов.

Диагностика домена по четырём независимым источникам: RDAP/whois, DNS, SSL/TLS
и перекрёстные проверки между ними. Собирает данные для ответа на главные вопросы:
«когда истекает домен?», «когда истекает сертификат?», «в порядке ли DNS?».

Самодостаточный CLI-инструмент: пакет чистых функций анализа `domaincheck/`
+ тонкая обёртка `domain_checker.py`.

## Установка

Пока не на PyPI (публикация планируется). Ставится напрямую с GitHub:

```bash
pip install git+https://github.com/mnnoee/jealous-domain.git
```

После установки доступна команда `jealous-domain`. Можно запускать и без
установки — прямо из клона репозитория:

```bash
python3 domain_checker.py mnnoee.ru
```

Требуются внешние утилиты `dig`, `whois`, `openssl` (см. «Зависимости»)
и доступ в сеть.

## Возможности

- **RDAP + whois-фолбэк** (`--whois`):
  - RDAP через `https://www.rdap.net/domain/{домен}` (сам редиректит на
    RDAP-сервер реестра/регистратора; для `.ru` часто 404 -> классический whois);
  - даты регистрации/истечения/обновления, статусы домена, nameservers,
    регистратор, abuse-контакты (vCard в сущностях RDAP), DNSSEC-подпись;
  - парсинг abuse-контактов из whois-текста — та же логика, что в
    `nginx_parser/nginxparse/whois.py` (`abuse-mailbox`, `OrgAbuseEmail`,
    `Registrar Abuse Contact Email`, фолбэк `E-mail`).
- **DNS** (`--dns`): A, AAAA, MX, NS, TXT через `dig +short`; SPF вытаскивается
  из общего TXT; DMARC (`_dmarc`); DKIM по **списку селекторов**
  (см. ниже); PTR для каждого A/AAAA с проверкой «резолвится обратно в тот же
  домен?»; сверка ответов отдельных NS (детект рассинхрона при миграции).
- **SSL/TLS** (`--ssl`): `openssl s_client` -> цепочка сертификатов
  (subject/issuer/даты/алгоритм подписи), **дни до истечения листового
  сертификата**, флаг верификации цепочки (`Verify return code`, `verify return`
  по каждому depth); весь неразобранный вывод — в `raw_output`.
- **Перекрёстные проверки** (всегда, если запущено >=2 секций):
  «сертификат истекает после домена — бесполезный сертификат», «сертификат
  скоро истекает, а домен продлён надолго», PTR-mismatch, «A есть, а порт 443
  закрыт».

> **Важно:** Выводы — эвристика, а не истина. Перекрёстные проверки строятся по
> формальным правилам (даты, наличие записей), и совпадение с условием не
> доказывает проблему. Например, «A есть, а порт 443 закрыт» может означать,
> что сервис просто слушает на другом порту. Прежде чем действовать —
> проверьте вручную.
- **Изоляция секций**: сбой одного источника (нет сети/утилиты/домен не
  резолвится) -> `error` в его секции, остальные работают.
- **IDN-домены**: кириллица и другие не-ASCII домены (например,
  `смешнявки.рф`) конвертируются в punycode (`xn--…`) на сетевой границе —
  `dig`, `openssl` и RDAP получают ASCII-форму, в отчёте домен остаётся
  в читаемом виде.
- **Кэш** RDAP/whois (`.whois_cache.json`, TTL 7 дней), обход через `--no-cache`.
- **Таймауты**: явный на каждый subprocess и HTTP-запрос (`--timeout`, 10 сек)
  — зависший DNS-сервер не повесит весь прогон.

## Зависимости

- Python 3 (только стандартная библиотека).
- Внешние утилиты (проверяются через `shutil.which`; отсутствие одной не роняет
  остальные секции):

  | Утилита     | Зачем                            | Пакет                     |
  |-------------|----------------------------------|---------------------------|
  | `whois`     | фолбэк для RDAP (зоны типа .ru)  | Arch: `pacman -S whois`; Debian/Ubuntu: `apt install whois` |
  | `dig`       | DNS-записи                       | Arch: `pacman -S bind-tools`; Debian/Ubuntu: `apt install dnsutils` |
  | `openssl`   | SSL/TLS-диагностика              | обычно уже установлен; Arch: `pacman -S openssl` |

## Использование

```
jealous-domain mnnoee.ru                    # все секции по умолчанию
jealous-domain mnnoee.ru --whois            # только RDAP/whois
jealous-domain mnnoee.ru --dns              # только DNS
jealous-domain mnnoee.ru --ssl              # только SSL
jealous-domain mnnoee.ru --dns --ssl        # комбинация секций
jealous-domain mnnoee.ru --ssl-port 8443
jealous-domain mnnoee.ru --no-cache
jealous-domain mnnoee.ru --json             # отчёт в report.json
jealous-domain mnnoee.ru --json report.json # отчёт в report.json
jealous-domain --version                      # версия
```

Без установки — так же, но через `python3 domain_checker.py`.

### DKIM-селекторы

DKIM-селектор может называться по-разному (`default`, `google`, `selector1`,
`s1`, …), поэтому модуль **перебирает список**, а не хардкодит один:

- по умолчанию селекторы берутся из файла `dkim_selectors.txt` (по одному на
  строку, `#` — комментарий);
- `--dkim-selector NAME` (можно несколько раз) переопределяет список для
  разового запуска;
- `--dkim-file PATH` — свой файл со списком (пригодится для интеграции с
  дашбордом, где список передаётся конфигом).

### Опции

| Флаг | Описание |
|------|----------|
| `--whois` | секция RDAP/whois |
| `--dns` | секция DNS |
| `--ssl` | секция SSL/TLS |
| `--all` | включить все секции |
| `--dkim-selector NAME` | DKIM-селектор для перебора (повторяемый) |
| `--dkim-file PATH` | файл со списком DKIM-селекторов |
| `--ssl-port N` | порт для SSL-секции (по умолчанию 443) |
| `--timeout SEC` | таймаут на каждый запрос/подпроцесс (по умолчанию 10) |
| `--no-cache` | не использовать кэш RDAP/whois |
| `--json [PATH]` | машиночитаемый отчёт (по умолчанию `report.json`) |

Без флагов запускаются все секции (поведение по умолчанию). Один флаг на
секцию — это будущие чекбоксы UI один-в-один, без промежуточного маппинга.

## JSON-отчёт

Каждая секция имеет поле `error` (`null` = ок, иначе текст). «Пустой список» —
валидный результат (записей такого типа просто нет), а не ошибка.

```json
{
  "meta": {
    "version": "0.1.0",
    "domain": "example.com",
    "checked_at": "2026-09-15T12:00:00+00:00",
    "sections_run": ["whois", "dns", "ssl"]
  },
  "whois": {
    "source": "rdap",
    "registered": "1997-09-15T04:00:00Z",
    "expiration": "2028-09-14T04:00:00Z",
    "last_changed": "2019-09-09T15:39:04Z",
    "registrar": "MarkMonitor Inc.",
    "statuses": ["client delete prohibited"],
    "nameservers": ["ns1.example.com"],
    "abuse_contacts": ["abusecomplaints@markmonitor.com"],
    "dnssec_signed": false,
    "error": null
  },
  "dns": {
    "a": ["93.184.216.34"],
    "aaaa": [],
    "mx": [{"priority": 10, "host": "mail.example.com"}],
    "ns": ["ns1.example.com", "ns2.example.com"],
    "txt": ["v=spf1 -all"],
    "spf": "v=spf1 -all",
    "dmarc": "v=DMARC1; p=reject",
    "dkim": {"google": null, "s1": "v=DKIM1; ..."},
    "ptr": {"93.184.216.34": {"hostname": "example.com", "matches_domain": true}},
    "ns_consistency": {"consistent": true, "servers": {...}},
    "error": null
  },
  "ssl": {
    "host": "example.com",
    "port": 443,
    "chain": [
      {"depth": 0, "subject": "CN=example.com", "issuer": "...",
       "not_before": "...", "not_after": "...", "days_until_expiry": 61,
       "sig_alg": "ecdsa-with-SHA384"}
    ],
    "verify_ok": true,
    "raw_output": "...",
    "error": null
  },
  "cross_checks": [
    {"severity": "info", "message": "PTR для 93.184.216.34 совпадает с доменом"}
  ]
}
```

## Тестирование

- **Юнит-тесты** (по умолчанию, `pytest`): замоканы subprocess/HTTP — сеть не
  нужна, стабильны в CI. Фикстуры только на generic-доменах
  (`example.com`, `example.ru`), никаких реальных клиентских доменов.
- **Интеграционные тесты** (вручную, `pytest -m integration`): реальные запросы
  к example.com (RDAP/DNS/SSL).

```
pytest                 # юниты
pytest -m integration  # интеграции (ходьба в сеть)
pytest -m ""           # всё вместе
```

## Структура

```
domain_checker.py        # тонкая обёртка
domaincheck/             # пакет анализа
  constants.py           # VERSION, дефолты, пороги
  parse_utils.py         # run_cmd (subprocess+таймауты), http_get, даты, нормализация
  rdap.py                # RDAP-запрос + парсинг JSON
  whois.py               # кэш, whois-текст, abuse, оркестрация RDAP->whois
  dns.py                 # dig: записи, DKIM, SPF, DMARC, PTR, сверка NS
  ssl.py                 # openssl s_client + x509: цепочка, verify
  cross.py               # перекрёстные проверки
  report.py              # человекочитаемый отчёт (RU)
  json_export.py         # машиночитаемый отчёт (--json)
  cli.py                 # argparse, main(), выбор секций
dkim_selectors.txt       # список DKIM-селекторов по умолчанию
tests/                   # юнит- + интеграционные тесты, фикстуры
pyproject.toml           # упаковка, версия, pytest, ruff
.github/workflows/ci.yml # CI: матрица 3.9–3.13, lint + тесты + smoke
LICENSE / NOTICE         # GPL-3.0-or-later
CHANGELOG.md             # история изменений
RELEASING.md             # процесс выпуска версий
CONTRIBUTING.md          # как участвовать в разработке
```

## Пример отчёта

```
==================================================
mnnoee.ru
==================================================

--- WHOIS / RDAP ---
  источник:    whois
  регистрация: 2025-04-03
  истекает:    2027-04-03 (через 172 дн.)
  регистратор: REGRU-RU
  статусы:     REGISTERED, DELEGATED, VERIFIED
  NS:          ns1.mnnoee.ru, ns2.mnnoee.ru

--- DNS ---
  A             64.188.94.216
  AAAA          2a01:ecc0:200:5c2::2
  MX            10 mail.mnnoee.ru
  NS            ns1.mnnoee.ru, ns2.mnnoee.ru
  SPF           v=spf1 ip4:64.188.94.216 ip6:2a01:ecc0:200:5c2::2 -all
  DMARC         v=DMARC1; p=reject; ...
  DKIM          mail -> v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEF...
  PTR           64.188.94.216 -> mail.mnnoee.ru [ok]
  NS-сверка  согласованы
```

## Участие в разработке

См. [CONTRIBUTING.md](CONTRIBUTING.md).

## Идеи и предложения

Есть идея, чего не хватает в проекте? Открывайте issue — предложения по новым
секциям отчёта, проверкам, форматам выгрузки и интеграциям приветствуются.

## Лицензия

GPL-3.0-or-later. Подробности — в [LICENSE](LICENSE) и [NOTICE](NOTICE).