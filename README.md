# Log Sentinel

> Детектор атак на учётные данные по логам Linux и Windows — на чистом Python, без зависимостей.

Инструмент анализирует журналы аутентификации и находит следы типовых атак:
брутфорс SSH, password spraying, подбор пароля к учётной записи и Kerberoasting.
Для каждой находки формируется алерт с уровнем критичности, доказательствами
(строки логов) и рекомендацией по реагированию — как в работе SOC-аналитика.

*EN: A zero-dependency Python CLI that hunts credential-attack traces in Linux
`auth.log` and Windows Security event exports — SSH brute force, password
spraying, account brute force and Kerberoasting — and reports alerts with
severity, evidence and response recommendations.*

---

## Что детектирует

| Правило | Источник | Логика | Severity |
|---|---|---|---|
| `ssh-brute-force-success` | auth.log | Успешный вход с IP, у которого ≥10 неудачных попыток | CRITICAL |
| `ssh-brute-force` | auth.log | ≥10 failed password с одного IP | HIGH |
| `password-spraying` | Windows 4625 | Один IP → ошибки входа у ≥5 разных учёток | HIGH |
| `kerberoasting` | Windows 4769 | Запрос TGS с RC4 (0x17) для сервисной учётки | HIGH |
| `account-brute-force` | Windows 4625 | ≥10 неудачных входов одной учётки | MEDIUM |

Пороги вынесены в константы в начале `log_sentinel.py` — легко настроить под свой стенд.

## Быстрый старт

```bash
git clone https://github.com/Voobrazhenie21-lab/log-sentinel.git
cd log-sentinel
python log_sentinel.py --auth-log samples/auth.log \
                       --win-events samples/security_events.csv \
                       --json report.json
```

Требования: **Python 3.9+**, сторонних библиотек не нужно.

## Пример вывода

```
[1] (CRITICAL) ВОЗМОЖНАЯ КОМПРОМЕТАЦИЯ: успешный вход «deploy» с атакующего 45.148.10.87
[2] (HIGH) SSH-брутфорс с 45.148.10.87: 14 неудачных попыток
[3] (HIGH) Password spraying с 10.0.30.55: подбор к 6 учётным записям
[4] (HIGH) Признаки Kerberoasting: 2 TGS с RC4 (событие 4769)
[5] (MEDIUM) Брутфорс учётной записи «admin_temp»: 12 неудачных входов (4625)
```

Полный пример отчёта — в `report.json`.

## Формат входных данных

- `--auth-log` — стандартный Linux auth.log / secure;
- `--win-events` — CSV-экспорт событий Windows Security с колонками:
  `EventID, TimeCreated, TargetUserName, IpAddress, ServiceName, TicketEncryptionType`
  (экспортируется из Event Viewer или Wazuh/ELK).

## Структура

```
log-sentinel/
├── log_sentinel.py            # весь инструмент — один файл
├── samples/
│   ├── auth.log               # пример лога SSH с брутфорсом
│   └── security_events.csv    # пример событий Windows 4625/4769
└── report.json                # пример итогового отчёта
```

## Roadmap

- [ ] Парсинг событий 4624 (Type 3) для детекта Pass-the-Hash;
- [ ] Экспорт алертов в формат TheHive (case creation);
- [ ] Детект AS-REP Roasting (событие 4768);
- [ ] Поддержка Sysmon (EventID 1, 3, 10);
- [ ] Модульные тесты (pytest).

## Дисклеймер

Инструмент создан в учебных целях для анализа собственных логов
и изолированных лабораторных стендов.

## Автор

Алексей Жарков — junior-специалист по кибербезопасности (пентест + SOC)
GitHub: [@Voobrazhenie21-lab](https://github.com/Voobrazhenie21-lab) · Telegram: [@Voobrazhenie_20](https://t.me/Voobrazhenie_20)
