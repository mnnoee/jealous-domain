# Участие в разработке

## Как предлагать идеи/фичи

Создайте Issue в репозитории с кратким описанием проблемы и желаемого поведения.

## Как предлагать код

Отправьте Pull Request с описанием изменений. До мержа убедитесь, что:

```bash
# тесты (юниты, без сети)
python -m pytest

# интеграционные тесты — вручную, нужна сеть и утилиты dig/whois/openssl
python -m pytest -m integration

# линтер
ruff check .
```

- Код проходит тесты и линтер
- Описание PR содержит контекст: что было, что стало, зачем
- Новая секция анализа = новый модуль в `domaincheck/` + флаг в `cli.py`,
  а не разрастание существующих файлов

## Структура проекта

```
domain_checker.py        тонкая CLI-обёртка
domaincheck/
  constants.py           VERSION, дефолты, пороги
  parse_utils.py         run_cmd (subprocess+таймауты), http_get, даты
  rdap.py                RDAP-запрос + парсинг JSON
  whois.py               кэш, whois-текст, abuse, оркестрация RDAP->whois
  dns.py                 dig: записи, DKIM, SPF, DMARC, PTR, сверка NS
  ssl.py                 openssl s_client + x509: цепочка, verify
  cross.py               перекрёстные проверки
  report.py              человекочитаемый отчёт (RU)
  json_export.py         машиночитаемый отчёт (--json)
  cli.py                 argparse, main(), выбор секций
tests/                   юнит- (моки) + интеграционные тесты
```

Направление зависимостей одностороннее: `cli -> (rdap, whois, dns, ssl) ->
parse_utils/constants`. Новая фича = новый модуль + секция в отчёте.

## Важно: конфиденциальность доменов

Модуль ходит в сеть (RDAP, DNS, SSL), поэтому в Issue/PR легко случайно
раскрыть домен клиента. **Обязательно** перед публикацией:

- заменяйте реальные домены на `example.com` / `example.ru`
- не прикладывайте вывод `.whois_cache.json` — в нём реальные данные
- в тестах и фикстурах — только generic-домены, никаких реальных клиентских

Юнит-тесты должны работать без сети (моки `subprocess` и `http_get`);
всё, что ходит в сеть, помечается маркером `integration` и по умолчанию
пропускается (`pytest.ini_options.addopts` в `pyproject.toml`).

## Версионирование и релизы

- SemVer: `MAJOR.MINOR.PATCH`. Источник истины — `VERSION` в
  `domaincheck/constants.py`; `pyproject.toml` читает её автоматически,
  руками версию нигде дублировать не нужно.
- Каждое изменение — запись в `CHANGELOG.md` (Keep a Changelog).
- Релиз: обновить `VERSION` -> запись в CHANGELOG -> тег `vX.Y.Z`.
