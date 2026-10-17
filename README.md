# 🔬 Engine+ — High-Performance Reverse Engineering Suite & MCP Server in Rust

[![Build & Test](https://img.shields.io/badge/tests-60%2F60%20passing-brightgreen)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Wine-lightgrey)](#)
[![MCP Spec](https://img.shields.io/badge/MCP-2024--11--05-orange)](#)

> **Engine+** — высокопроизводительный, модульный инструмент нового поколения для исследования, реверс-инжиниринга и отладки памяти запущенных программ и игр, а также статического анализа бинарных файлов (ELF / PE).
> Построен с нуля на **Rust**, оснащён встроенным **Model Context Protocol (MCP)** сервером для автономной работы любых AI-агентов (Claude, Cursor, Antigravity, GPT, Ollama).

---

## ⚡ Ключевые возможности

* **Параллельный сканер памяти (Rayon):** Первое и повторные сканирования по всем типам данных (`i8`..`u64`, `f32`, `f64`, wildcards AOB `48 8B ?? C3`, строки) за **~3 миллисекунды** с chunk-буферизацией (512 КБ).
* **AI-Ready MCP Server (23 инструмента):** Стандартный интерфейс JSON-RPC 2.0 (stdio) с токен-оптимизацией (`analyze_structure`), сжатием нулевых блоков и пагинацией.
* **Анализатор структур (ReClass Style):** Автоматическое распознавание VTable, 3D-векторов (`Vector3`), указателей, строк и экспорт готовых структур в **C++**, **Rust** и **C#**.
* **Отладчик и трассировщик (Debugger & Hit Tracer):** 
  * Аппаратные точки останова DR0–DR3 (на запись, чтение, выполнение).
  * Программные точки останова INT3 (0xCC) с гарантированным сохранением исходных байт.
  * Анализатор *«Что пишет в этот адрес?»* с фиксацией регистров процессора и декомпиляцией инструкций через `iced-x86`.
* **Ассемблер, Detour-хуки и патчинг:**
  * Встроенный ассемблер (Intel-синтаксис) и дизассемблер на `iced-x86`.
  * Автоматический расчёт длины инструкций, создание 5-байтовых трамплинов и NOP-filling.
  * Автогенератор AOB-сигнатур с маскированием относительных прыжков/вызовов.
* **Песочница Lua 5.4 и Cheat Engine AutoAssembler:**
  * Строго изолированная среда Lua 5.4 (без доступа к ОС и диску) с биндингами Core API.
  * Поддержка скриптов Cheat Engine (`[ENABLE]` / `[DISABLE]`, `alloc`, `labels`).
* **Многоуровневый Pointer Scanner:** Поиск стабильных цепочек указателей (`module.exe + 0x1000 -> +0x20 -> +0xF8`) с динамическим вычислением в реальном времени.
* **Непрерывный Speed Hack:** Машина состояний масштабирования времени с непрерывной математикой и генерацией инъекционных скриптов перехвата `clock_gettime` (Linux) и `QueryPerformanceCounter` (Windows).

---

## 🚀 Быстрая установка

### Автоматическая установка в `~/.local/bin` (Linux):
```bash
./install.sh
```

### Ручная сборка через Cargo:
```bash
# Релизная сборка бинарника
cargo build --release --bin engine-plus

# Установка в систему через Cargo
cargo install --path crates/engine-cli --bin engine-plus
```

---

## 🖥️ Использование

### 1. Интерактивная консоль (REPL):
```bash
engine-plus console
```
В консоли доступны команды:
```text
engine-plus> ps [filter]                  # Список запущенных процессов
engine-plus> attach <pid>                 # Подключение к процессу игры
engine-plus> scan 100 i32                 # Поиск начального значения (здоровье 100)
engine-plus> next 85                      # Фильтрация после получения урона
engine-plus> whatwrites <addr> [size]     # "Что пишет в этот адрес?" (Hit Tracer)
engine-plus> reclass <addr> [size] [name] # Восстановление класса/структуры
engine-plus> export <addr> [size] [cpp|rust|csharp] # Экспорт структуры в код
engine-plus> ptrscan <addr> [depth] [off] # Поиск статических цепочек указателей
engine-plus> ptrresolve <mod> <off> [...] # Разрешение адреса по цепочке
engine-plus> speedhack 2.0                # Включение спидхака (ускорение 2x)
engine-plus> aa <script>                  # Выполнение AutoAssembler скрипта
```

### 2. Подключение как MCP-сервер к AI (Cursor, Claude, Antigravity):
Запуск MCP-сервера по протоколу stdio:
```bash
engine-plus --mcp
```

Конфигурация для AI-клиентов (`claude_desktop_config.json` / `~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "engine-plus": {
      "command": "engine-plus",
      "args": ["--mcp"]
    }
  }
}
```

---

## 📖 Руководства и документация

* 📘 [Пошаговый гайд по реверсингу для ИИ на примере Assault Cube](./docs/AI_REVERSING_GUIDE.md)
* 🗺️ [Дорожная карта проекта (ROADMAP.md)](./docs/ROADMAP.md)
* 💉 [Инъекция кода и перехват функций (CODE_INJECTION.md)](./docs/CODE_INJECTION.md)
* 🌐 [Кроссплатформенность и поддержка Wine/Proton (CROSS_PLATFORM.md)](./docs/CROSS_PLATFORM.md)
* 📜 [Песочница Lua 5.4 и AutoAssembler (SCRIPTING_LUA.md)](./docs/SCRIPTING_LUA.md)

---

## 🛠️ Архитектура крейтов

```
crates/
├── engine-pal       # Process Access Layer: абстракции ОС (Linux, Windows, Wine/Proton)
├── engine-core      # Ядро: параллельный сканер (Rayon), дизассемблер, ReClass, Pointer Scanner
├── engine-script    # Изолированная песочница Lua 5.4 и Cheat Engine AutoAssembler
├── engine-mcp       # Model Context Protocol сервер (23 инструмента для нейросетей)
└── engine-cli       # Главный бинарник 'engine-plus': REPL, консольные утилиты и MCP
```

---

## 🧪 Верификация и тесты

```bash
# 1. Запуск всех 60 тестов рабочего пространства
cargo test --workspace

# 2. Проверка кросс-компиляции под Windows
cargo check --target x86_64-pc-windows-gnu -p engine-pal -p engine-core

# 3. Проверка качества кода (0 ворнингов)
cargo clippy --all-targets -- -D warnings
```

---

## 📜 Лицензия
MIT License (c) 2026 Yarick.
