# Product

<!-- impeccable:product-schema 1 -->

## Platform
web

## Stack
Confirmed: vanilla JavaScript and Node.js. Node.js 22.13+ with built-in node:sqlite; portable Node deployment build without copying data or credentials.

## Users
Site owner investigating browser fingerprints, network observations and automation signals.

## Product Purpose
Collect the broadest practical set of browser-exposed diagnostics, distinguish server observations, and explain possible signs of bots without claiming universal detection.

## Capabilities and Constraints
Russian interface, dark technical panel with tables (confirmed). Public collection page shows only consent, optional checks and completion status. Parameter values, fingerprint hashes, bot signals, record browsing and JSON export are restricted to the owner admin panel. Public report deletion and public connection-observation endpoints are removed. Permission-gated probes require explicit visitor actions. Unsupported, blocked, failed and timed-out probes remain visible. No external fingerprint services. Reports are saved in owner SQLite only after an explicit choice for each run or a separately confirmed upload. A single-owner admin panel is protected by a random local owner key, server sessions and CSRF checks. All admin fields use the shared help catalogue; the visitor page explains the data categories without showing results. Optional probes never automatically update persisted reports. TLS JA4 and reputation are unavailable unless a trusted edge supplies them. No fingerprint can prove humanity or uniquely identify every device.

## Product Principles
- Values come from measurements; never invent missing values.
- Distinguish evidence from hypotheses and spoofable client reports.
- Explain each automation flag and its false-positive cases.
- Keep optional permissions separate from automatic diagnostics.
# Развёртывание и доступ

Production рассчитан на один VPS: Docker Compose, Caddy с HTTPS и Node без сети через Unix socket. Админ-панель закрыта на публичном origin, доступна только через SSH-туннель на loopback-порт и ключ владельца. Сохранение остаётся добровольным, посетитель не получает чтение/скачивание/удаление отчётов. Production хранит записи по настраиваемому сроку (30 дней по умолчанию); локальный dev не очищает старые записи автоматически. Подробности: DEPLOYMENT.md и SECURITY.md.

