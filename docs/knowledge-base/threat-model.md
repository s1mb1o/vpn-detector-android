# Threat Model: Anti-VPN детекция в нашей схеме

**Дата:** 2026-04-07
**Контекст:** Mobile-устройства + домашний MikroTik с VPN-аплинком.
**Зеркало:** этот документ изначально жил в `~/Projects/10_admin/mikrotik/docs/rkn/threat-model.md`. Скопирован сюда чтобы вся research / know-how по теме была в одном месте проекта vpn-detector-android.

## Архитектура (как есть)

```
Phone (WiFi дома)        ─┐
Phone (WG к дому, вне)   ─┼─→ MikroTik ─→ split:
                          │              *.ru        → direct (RU ISP)
                          │              остальное   → VPN exit (US/EU)
```

- На телефоне нет своего внешнего VPN.
- WG к дому только как «вход» в домашнюю сеть, не для обхода напрямую.

## Активы и цели

| # | Цель | Приоритет |
|---|------|-----------|
| G1 | Обход блокировок РФ→мир (YouTube, ChatGPT, …) | high |
| G2 | Не палиться anti-fraud / anti-VPN детекторами в банковских и госприложениях | high |
| G3 | Обход блокировок мир→РФ (сервисы, банящие RU) | medium |
| G4 | Стабильность мобильного интернета в РФ при ТСПУ-блокировках протоколов | high |

## Угрозы

### T1. Системная детекция VPN на устройстве
**Кто видит:** любое приложение через `ConnectivityManager` (Android) / `NEVPNManager` (iOS).
**Что видит:** факт активного туннеля, `tun0`, `TRANSPORT_VPN`.
**Применимо к нам:** только в режиме «телефон вне дома, WG к дому». Дома по Wi-Fi — туннеля на устройстве нет.
**Митигация:** см. M1, M2.

### T2. GeoIP-несоответствие (главная дыра)
**Кто видит:** anti-fraud SDK в приложениях, дёргающие `ipify.org` / `ipinfo.io` / `ip-api.com` / `my-ip.com` и т.п.
**Что видит:** SIM=RU, locale=ru_RU, TZ=MSK, **IP=US** → fingerprint «врёт о геолокации».
**Применимо к нам:** **всегда**, и в Wi-Fi-режиме, и в WG-режиме, потому что дефолт роутера = «всё не-`*.ru` через VPN». Probe-домен попадает в VPN автоматически.
**Митигация:** M3, M4.

### T3. DPI/ТСПУ детекция WireGuard handshake
**Кто видит:** оператор связи / ТСПУ.
**Что видит:** характерный первый пакет WG, MAC, тайминги.
**Применимо к нам:** WG-туннель телефон↔дом и аплинк роутера (если на голом WG/OpenVPN).
**Митигация:** M5.

### T4. Утечка через probe-домены при whitelist-based VPN
**Кто видит:** anti-fraud, дёрнувший probe.
**Что видит:** RU IP, всё консистентно — **угроза снимается**.
Угроза существует только в blacklist-based политике (текущая).

### T5. Сервисы, банящие RU **и** банящие VPN-ASN
**Что видим мы:** сервис недоступен ни напрямую, ни через типичный VPS-выход.
**Митигация:** M6.

## Митигации

### M1. Per-app split на устройстве
Исключить «чувствительные» приложения (банки, госуслуги, маркетплейсы, такси, доставка) из WG-туннеля.
- Android: `Excluded Applications` в AmneziaVPN/WG.
- iOS: Per-App VPN через MDM-профиль.

### M2. Отключение VPN-профиля на телефоне в домашнем Wi-Fi
Автоматизация по SSID: дома Wi-Fi → VPN-профиль off (всё уже делает роутер). Снимает T1 для домашнего сценария.

### M3. Инверсия дефолта на роутере: whitelist-based VPN
**Сейчас:** `*.ru` direct, остальное → VPN.
**Должно быть:** **direct по умолчанию**, VPN — только для явного whitelist (sync-antifilter).
**Эффект:** probe-домены, неизвестные сервисы, anti-fraud endpoints автоматически идут direct → RU IP → консистентно. Снимает T2 без отдельных правил для probe.

### M4. Explicit direct override для probe-доменов
Страховка поверх M3. Address-list `geoip-probe-direct`:
- `*.ipify.org`, `ifconfig.me`, `ifconfig.co`, `ipinfo.io`, `ip-api.com`, `api.myip.com`, `icanhazip.com`, `checkip.amazonaws.com`, `my-ip.com`
- `captive.apple.com`, `connectivitycheck.gstatic.com`
Принудительно direct, даже если домен совпал с whitelist. Перекрывает любой VPN-маршрут.

### M5. Уход с голого WG/OpenVPN на обфусцированные транспорты
- **AmneziaWG** для туннелей телефон↔дом и аплинка роутера.
- **VLESS-Reality** как fallback / основной мобильный транспорт (план [`05_vless-transport-mode-switching.md`](../plans/05_vless-transport-mode-switching.md)).
- OpenVPN/strongvpn — вывести из ротации, оставить только как emergency fallback.

### M6. Отдельный «чистый» exit для Класса 3 (опционально)
Если есть сервисы, банящие и RU, и обычные VPN-ASN — поднять второй exit на residential-IP / нестандартном хостинге, маршрутизировать туда **только** узкий whitelist доменов. Не делать дефолтом.

## Классы трафика (целевая модель)

| Класс | Что | Путь | Geo на выходе |
|-------|-----|------|---------------|
| 1. RU-чувствительный | `*.ru`, банки, госуслуги, probe-домены, captive checks | direct | RU |
| 2. Заблокированный РФ | YouTube, ChatGPT, Instagram, Twitter, … (sync-antifilter) | VPN main exit | US/EU |
| 3. Заблокирован РФ + банит VPN | узкий ручной whitelist | VPN clean exit | residential US |
| 4. Default (всё остальное) | неизвестное | direct | RU |

**Ключевой сдвиг:** дефолт = direct, не VPN.

## Открытые вопросы

- Какие конкретные приложения на наших телефонах активно проверяют GeoIP? Нужен аудит.
- Есть ли реальные сервисы Класса 3, или можно обойтись без второго exit'а?
- Как часто обновлять `geoip-probe-direct` — статический список или подписка?

## Связанные документы

- [`../source-methodology.md`](../source-methodology.md) — анализ методики детекции VPN
- [`adr-001-whitelist-routing.md`](adr-001-whitelist-routing.md) — решение об инверсии дефолта
- [`router-blueprint.md`](router-blueprint.md) — фактическая схема MikroTik (хосты, ASN, hops)
- [`operator-playbook.md`](operator-playbook.md) — пошаговые рецепты для каждого режима
- [`../specs/05_metrics-review.md`](../specs/05_metrics-review.md) — каталог детектируемых метрик
- [`../specs/06_hiding-strategies.md`](../specs/06_hiding-strategies.md) — как снижать score
