# ADR-001: Whitelist-based VPN routing вместо blacklist `*.ru`

**Дата:** 2026-04-07
**Статус:** proposed
**Контекст:** [`threat-model.md`](threat-model.md)
**Зеркало:** оригинал в `~/Projects/10_admin/mikrotik/docs/rkn/architecture-decision-whitelist-vpn.md`. Скопирован сюда для централизации research.

## Проблема

Текущая политика маршрутизации на MikroTik:
- `*.ru` → direct
- всё остальное → VPN exit (US/EU)

Эта политика создаёт **fingerprint «российский пользователь с американским IP»**:
- SIM RU, locale ru_RU, TZ MSK
- IP US (для всего, что не `*.ru`)

Любой anti-fraud SDK или anti-VPN детектор, дёрнувший `ipify.org` / `ipinfo.io` / `my-ip.com` из приложения, видит расхождение и помечает пользователя как «под VPN». Probe-домены попадают в VPN автоматически, потому что не входят в `*.ru`.

## Рассмотренные варианты

### Вариант A: Оставить как есть, добавить explicit direct для probe-доменов
- **+** Минимум изменений.
- **−** Список probe бесконечный, всегда будет утечка для неизвестного probe.
- **−** Любой неизвестный домен по-прежнему палит US IP.
- **−** Anti-fraud SDK обновляют свои probe-эндпоинты — список устаревает.

### Вариант B: Инверсия — direct по умолчанию, VPN по whitelist
- **+** Закрывает T2 структурно: неизвестный домен = direct = RU = консистентно.
- **+** sync-antifilter уже даёт готовый whitelist заблокированных ресурсов.
- **+** Probe-домены автоматически в дефолте, отдельных правил не нужно.
- **−** Любой новый заблокированный сервис не работает, пока не попадёт в antifilter.
- **−** Требует переработки mangle-правил и тестирования.

### Вариант C: Per-app split только на устройстве, роутер не трогать
- **+** Гибко, прицельно.
- **−** Не работает в домашнем Wi-Fi режиме (на устройстве нет VPN — split нечего делать).
- **−** Не покрывает iOS без MDM.
- **−** Нужно вручную поддерживать список приложений на каждом устройстве.

## Решение

**Принять Вариант B** (инверсия дефолта) как основной, **дополнить Вариантом C** (per-app split на устройстве) как defence in depth.

Финальная политика на роутере:

| Приоритет | Источник правила | Действие |
|-----------|------------------|----------|
| 1 | `geoip-probe-direct` (explicit override) | direct |
| 2 | sync-antifilter whitelist (Класс 2) | VPN main exit |
| 3 | manual Класс 3 whitelist (если будет) | VPN clean exit |
| 4 | default | **direct** |

## Последствия

### Положительные
- Probe-детекция geo — снимается структурно.
- Anti-fraud SDK банков видит RU IP для всего, что не в whitelist обхода.
- `*.ru` правило становится не нужно (поглощается дефолтом).
- Поверхность утечки геолокации сжимается с «весь интернет минус `*.ru`» до «список antifilter».

### Отрицательные / риски
- Новый заблокированный сервис требует ручного добавления или ждёт обновления antifilter.
- Нужен тест-набор: после миграции прогнать `curl ipinfo.io` через WG-к-дому и через домашний Wi-Fi, оба должны вернуть RU.
- Убедиться, что DomainMapper / SmartDNS корректно работают с inverted-логикой (резолв должен происходить на роутере для domain-based mangle).

### Миграционные шаги
1. Снять текущие mangle-правила в backup.
2. Создать address-list `vpn-whitelist` из sync-antifilter источников.
3. Создать address-list `geoip-probe-direct` со списком probe-доменов.
4. Переписать mangle: mark-routing для `vpn-whitelist`, override для `geoip-probe-direct`.
5. Удалить старое правило «`*.ru` direct» (становится избыточным).
6. Тест: smoke-tests из [SMOKE_TESTS.md](../../SMOKE_TESTS.md) + проверка ipinfo.io с обоих типов клиентов.
7. Откат: восстановление backup mangle-правил.

## Связанное

- [`threat-model.md`](threat-model.md)
- [`../source-methodology.md`](../source-methodology.md)
- [`router-blueprint.md`](router-blueprint.md)
- [`operator-playbook.md`](operator-playbook.md)
- Mikrotik-side: `~/Projects/10_admin/mikrotik/docs/plans/05_vless-transport-mode-switching.md`
- Mikrotik-side: `~/Projects/10_admin/mikrotik/src/sync-antifilter/`
