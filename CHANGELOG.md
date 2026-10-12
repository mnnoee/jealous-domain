# Changelog

Все заметные изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [0.2.0] — 2026-10-12

### Added
- Упаковка проекта: `pyproject.toml` (PEP 621), установка через
  `pip install jealous-domain` и консольная команда `jealous-domain`.
- Флаг `--version` в CLI.
- **Поддержка IDN-доменов**: кириллица и другие не-ASCII домены
  (например, `смешнявки.рф`) конвертируются в punycode (`xn--…`) перед
  сетевыми запросами (`dig`, `openssl`, RDAP URL); в отчёте домен
  остаётся в читаемом виде.
- Лицензия GPL-3.0-or-later (`LICENSE`, `NOTICE`).
- `CHANGELOG.md` и `CONTRIBUTING.md`.
- Тесты: утилиты `parse_utils` (включая IDN-конверсию), дополнительные
  перекрёстные проверки (наивные/некорректные даты), интеграционные
  тесты на собственных и сторонних доменах.

### Changed
- Версия теперь задаётся в одном месте — `domaincheck/constants.py`
  (`VERSION`); `domaincheck/__init__.py` реэкспортирует её как
  `__version__`, `pyproject.toml` читает через `[tool.setuptools.dynamic]`.
- Конфигурация pytest перенесена из `pytest.ini` в `pyproject.toml`.

### Fixed
- `prog` в argparse больше не зашит жёстко как `domain_checker.py`:
  имя подставляется из фактического способа запуска, поэтому
  `jealous-domain --version` печатает `jealous-domain`, а не
  `domain_checker.py`.
- Сравнение дат в перекрёстных проверках: наивная дата из whois (без
  таймзоны) против aware-даты из SSL-цепочки вызывала `TypeError` —
  теперь наивные даты трактуются как UTC.

## [0.1.0] — 2026-09-15

### Added
- Первый публичный релиз: диагностика домена по трём независимым
  секциям — RDAP/whois (с фолбэком на классический whois), DNS (`dig`:
  A/AAAA/MX/NS/TXT/SPF/DMARC/DKIM/PTR/сверка NS), SSL/TLS
  (`openssl s_client`: цепочка, дни до истечения, verify).
- Перекрёстные проверки между секциями (`cross_checks`).
- Изоляция секций: сбой одной не роняет остальные.
- Кэш RDAP/whois (`.whois_cache.json`, TTL 7 дней), `--no-cache`.
- DKIM по списку селекторов (`dkim_selectors.txt`,
  `--dkim-selector`, `--dkim-file`).
- Машиночитаемый JSON-отчёт (`--json [PATH]`).

[Unreleased]: https://github.com/mnnoee/jealous-domain/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mnnoee/jealous-domain/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mnnoee/jealous-domain/releases/tag/v0.1.0
