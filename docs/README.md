# 🔬 Engine+ — Современный Cheat Engine на Rust

> **Engine+** — мощный инструмент для реверс-инжиниринга, отладки и анализа процессов и файлов.
> Построен на Rust с нуля с современным UI, AI-интеграцией через MCP и модульной архитектурой.

---

## 📋 Содержание документации

| Документ | Описание |
|---|---|
| [ROADMAP.md](./ROADMAP.md) | **Детальный пошаговый план разработки (14 этапов с точным порядком)** |
| [COMPETITORS_ANALYSIS.md](./COMPETITORS_ANALYSIS.md) | **Анализ аналогов (Cheat Engine, PINCE, memflow, x64dbg, ReClass, Ghidra)** |
| [EGUI_GUIDE.md](./EGUI_GUIDE.md) | **Руководство по современному IDE-интерфейсу на egui, egui_dock и Catppuccin** |
| [SCRIPTING_LUA.md](./SCRIPTING_LUA.md) | **Скриптовая подсистема Lua (Песочница, Zero-dependency, полный API)** |
| [TABLE_FORMAT_SPEC.md](./TABLE_FORMAT_SPEC.md) | **Спецификация формата таблиц .ept и конвертер с Cheat Engine (.ct)** |
| [CODE_INJECTION.md](./CODE_INJECTION.md) | **Низкоуровневая инъекция кода, выделение памяти и 5-байтовые трамплины** |
| [CROSS_PLATFORM.md](./CROSS_PLATFORM.md) | **Мультиплатформенность: Linux (sudo), Windows (Admin), Proton/Wine, WOW64** |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Системная архитектура, модули, слои абстракции PAL |
| [CORE_FEATURES.md](./CORE_FEATURES.md) | Полный список функционала (память, отладка, сканирование) |
| [UI_DESIGN.md](./UI_DESIGN.md) | Дизайн интерфейса, панели, layout, UX, горячие клавиши |
| [MCP_INTEGRATION.md](./MCP_INTEGRATION.md) | Стандартный MCP-сервер, подключение любой модели/агента, экономия токенов |
| [STEALTH_SYSTEM.md](./STEALTH_SYSTEM.md) | Низкоуровневое взаимодействие, 4 уровня скрытности |
| [DRIVER_PLAN.md](./DRIVER_PLAN.md) | План разработки kernel-драйвера (LKM / Windows KMDF) |
| [TECH_STACK.md](./TECH_STACK.md) | Технологический стек и зависимости |
| [QUESTIONS.md](./QUESTIONS.md) | Открытые вопросы и архитектурные решения |

---

## 🎯 Миссия проекта

Создать **открытый, модульный и расширяемый** инструмент для reverse engineering и runtime-анализа программ, который:

1. **Превосходит Cheat Engine** по функционалу и юзабилити
2. **Интегрирует AI** для автоматического анализа структур, паттернов и кода
3. **Работает скрытно** через множественные backend-ы (usermode, kernel driver, hypervisor)
4. **Выглядит как современная IDE** с панелями, темами и горячими клавишами
5. **Расширяется через плагины** и скрипты (Lua, WASM)

---

## 🏗️ Ключевые принципы

- **Rust-first** — безопасность памяти, производительность, zero-cost abstractions
- **Модульность** — каждая подсистема заменяема (backend, UI, scripting)
- **Backend-agnostic** — единый API, разные способы доступа к процессу
- **AI-native** — MCP-сервер из коробки, экономия токенов через кэширование
- **Cross-platform** — Linux в первую очередь, Windows через абстракции

---

## 🖥️ Кодовое имя

**Engine+** (engine_plus)

> Название подчёркивает, что это не клон, а эволюция концепции Cheat Engine
> с добавлением AI, современного UI и модульной архитектуры.

---

## 🚀 Быстрый старт (будущее)

```bash
# Сборка
cargo build --release

# Запуск GUI
./target/release/engine-plus

# Запуск MCP-сервера
./target/release/engine-plus --mcp

# Запуск CLI
./target/release/engine-plus-cli attach --pid 1234
```

---

## 📜 Лицензия

TBD — обсуждается (MIT / GPL / Proprietary)
