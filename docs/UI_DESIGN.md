# 🖥️ UI Design — Дизайн интерфейса Engine+

## Концепция

Интерфейс Engine+ построен по принципу **IDE/VS Code** — модульные панели,
которые пользователь может перемещать, изменять размер и группировать в табы.

> [!IMPORTANT]
> UI должен быть интуитивным для тех, кто знаком с Cheat Engine, 
> но при этом предоставлять мощность IDE-подобного интерфейса.

---

## Layout — Основной макет

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Menu Bar   [File] [Edit] [View] [Process] [Scan] [Debug] [Tools] [AI]│
├─────────────────────────────────────────────────────────────────────────┤
│  Toolbar  [▶ Attach] [⏸ Pause] [⏹ Stop] [🔍 Scan] [🐛 Debug] [⚡Speed]│
├────────┬────────────────────────────────────────────┬───────────────────┤
│        │                                            │                   │
│  Side  │          Main Workspace Area               │   Inspector       │
│  Bar   │                                            │   Panel           │
│        │  ┌──────┬──────┬──────┐                    │                   │
│ [📋]   │  │ Hex  │ Disa │ Stru │   ← Tabs          │  ┌─────────────┐  │
│ [🔍]   │  └──────┴──────┴──────┘                    │  │ Data        │  │
│ [🐛]   │  ┌──────────────────────────────────────┐  │  │ Inspector   │  │
│ [📁]   │  │                                      │  │  │             │  │
│ [🧩]   │  │     Hex View / Disassembly /         │  │  │ i8:  127    │  │
│ [🤖]   │  │     Structure View / etc.            │  │  │ u16: 32767  │  │
│ [⚙️]   │  │                                      │  │  │ i32: ...    │  │
│        │  │                                      │  │  │ f32: 3.14   │  │
│        │  │                                      │  │  │ ptr: 0x...  │  │
│        │  │                                      │  │  │ str: "abc"  │  │
│        │  └──────────────────────────────────────┘  │  └─────────────┘  │
│        │                                            │                   │
│        │                                            │  ┌─────────────┐  │
│        │                                            │  │ Properties  │  │
│        │                                            │  │             │  │
│        │                                            │  │ Address:    │  │
│        │                                            │  │ Module:     │  │
│        │                                            │  │ Section:    │  │
│        │                                            │  │ Protection: │  │
│        │                                            │  └─────────────┘  │
├────────┴────────────────────────────────────────────┴───────────────────┤
│                        Bottom Panel (resizable)                         │
│  ┌──────┬──────┬──────┬──────┬──────┐                                   │
│  │ Scan │ Table│ Cons │ Log  │ AI   │  ← Tabs                          │
│  └──────┴──────┴──────┴──────┴──────┘                                   │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  Address     │ Value  │ Previous │ Type │ Description            │    │
│  │  0x7F01A000  │ 100    │ 95       │ i32  │ Player Health          │    │
│  │  0x7F01A004  │ 100    │ 100      │ i32  │ Player Max Health      │    │
│  │  0x7F01A008  │ 50     │ 45       │ i32  │ Player Mana            │    │
│  └──────────────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────────────┤
│  Status Bar: [Process: game.exe (PID:1234)] [Backend: Usermode]        │
│              [Scan: 1,234 results] [Memory: 2.1 GB mapped] [AI: idle]  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Панели (Panels)

### Side Bar — Боковая панель

Иконочная навигация, как в VS Code. Каждая иконка открывает свою панель:

| Иконка | Панель | Описание |
|--------|--------|----------|
| 📋 | **Process List** | Список процессов, выбор целевого |
| 🔍 | **Scanner** | Настройки сканирования, параметры |
| 🐛 | **Debugger** | Breakpoints, watch, call stack |
| 📁 | **File Explorer** | Обзор файлов игры, открытие PE/ELF |
| 🧩 | **Structures** | Библиотека определённых структур |
| 🤖 | **AI Assistant** | Чат с AI, история анализов |
| ⚙️ | **Settings** | Настройки приложения |

---

### Main Workspace — Основная рабочая область

Табы с основным контентом. Несколько видов:

#### Hex View

```
┌─ Hex Editor: game.exe+0x01A3B4C0 ──────────────────────────────────────┐
│                                                                         │
│  Offset     00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  ASCII  │
│  ──────────────────────────────────────────────────────────────────────  │
│  01A3B4C0   48 8B 05 A7  12 3C 00 48  89 44 24 20  E8 7B 02 00  H..§.< │
│  01A3B4D0  ▐64 00 00 00▐ 64 00 00 00  32 00 00 00  00 00 80 3F  d...d.. │
│  01A3B4E0   00 00 00 00  48 A3 01 7F  00 00 00 00  FF FF FF FF  ....H£. │
│  01A3B4F0   01 00 00 00  00 00 C0 42  00 00 48 43  00 00 00 00  ......B │
│                                                                         │
│  ▐ Highlighted: 0x01A3B4D0..0x01A3B4D3 ▐                               │
│  Selection: 4 bytes = 100 (i32) = 100.0 (f32)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Disassembly View

```
┌─ Disassembly: game.exe — main+0x42 ────────────────────────────────────┐
│                                                                         │
│  Address        Bytes              Instruction           Comment         │
│  ──────────────────────────────────────────────────────────────────────  │
│  0x140001000    55                 push rbp                              │
│  0x140001001    48 89 E5           mov rbp, rsp                          │
│  0x140001004    48 83 EC 30        sub rsp, 0x30                         │
│  0x140001008    48 8B 0D A1 2F..   mov rcx, [rip+0x2FA1]  ; g_player    │
│● 0x14000100F    8B 41 10           mov eax, [rcx+0x10]    ; health ←BP  │
│  0x140001012    83 F8 00           cmp eax, 0                            │
│  0x140001015    7E 15           ┌─ jle 0x14000102C        ; → dead      │
│  0x140001017    FF C8           │  dec eax                               │
│  0x140001019    89 41 10        │  mov [rcx+0x10], eax    ; save health │
│  0x14000101C    ...             │  ...                                   │
│  0x14000102C    ...             └► ; death handler                      │
│                                                                         │
│  [Functions ▼] [Xrefs ▼] [Goto: ___________] [Follow] [Back]           │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Structure View

```
┌─ Structure: Player (0x01A3B4C0) ────────────────────────────────────────┐
│                                                                         │
│  Offset  Size  Type        Name          Value        AI Confidence     │
│  ──────────────────────────────────────────────────────────────────────  │
│  +0x00   8     *VTable     vtable_ptr    0x7F401020   ████████░░ 85%    │
│  +0x08   4     i32         id            42           ████████░░ 80%    │
│  +0x0C   4     padding     —             00 00 00 00  █████████░ 90%    │
│  +0x10   4     f32         pos_x         123.45       ██████████ 95%    │
│  +0x14   4     f32         pos_y         67.89        ██████████ 95%    │
│  +0x18   4     f32         pos_z         10.00        ██████████ 95%    │
│  +0x1C   4     i32         health        100          █████████░ 90%    │
│  +0x20   4     i32         max_health    100          ████████░░ 85%    │
│  +0x24   4     i32         mana          50           ████████░░ 80%    │
│  +0x28   8     *Entity     target        0x01B3C4D0   ███████░░░ 70%    │
│  +0x30   64    [u8;64]     name          "PlayerOne"  ██████████ 95%    │
│  +0x70   4     u32         flags         0x0000001F   ███████░░░ 70%    │
│                                                                         │
│  [🤖 AI Analyze] [📋 Copy as C] [📋 Copy as Rust] [💾 Save] [↻ Refresh]│
└─────────────────────────────────────────────────────────────────────────┘
```

---

### Bottom Panel — Нижняя панель

#### Scan Results Tab

```
┌─ Scan Results ──────────────────────────────────────────────────────────┐
│  Scan #3: Exact Value = 100 (i32) | Found: 1,234 results | ◄ Undo     │
│                                                                         │
│  ☐ Address        Current  Previous  Module           Section           │
│  ☑ 0x7F01A000     100      95        game.exe         .data             │
│  ☑ 0x7F01A004     100      100       game.exe         .data             │
│  ☐ 0x7F23B100     100      100       libsystem.so     .bss              │
│  ☐ 0x7F45C200     100      102       game.exe         .data             │
│                                                                         │
│  [→ Add Selected to Table] [→ Add All] [New Scan] [Next Scan]          │
│                                                                         │
│  Value: [________] Type: [i32 ▼] Scan: [Exact ▼]  [🔍 First Scan]     │
│                                                    [🔍 Next Scan]      │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Cheat Table Tab

```
┌─ Cheat Table: my_game.ept ──────────────────────────────────────────────┐
│                                                                         │
│  ⊞ ☐ 🔑 Description          Address                 Type  Value       │
│  ├─ ☑ F1  Player Stats                                                  │
│  │  ├─ ☑ F2  Health           "game.exe"+1A3B4C0→+10  i32   100 🔒     │
│  │  ├─ ☑ F3  Max Health       "game.exe"+1A3B4C0→+14  i32   100 🔒     │
│  │  └─ ☐     Mana             "game.exe"+1A3B4C0→+18  i32   50         │
│  ├─ ☐     Enemy Stats                                                   │
│  │  └─ ...                                                               │
│  └─ ☐ F5  [Script] God Mode   —                       —     OFF        │
│                                                                         │
│  🔒 = Frozen | 🔑 = Hotkey assigned                                     │
│  [+ Add] [- Remove] [📝 Edit] [▶ Enable All] [⏹ Disable All]          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Console Tab

```
┌─ Console (Lua) ─────────────────────────────────────────────────────────┐
│  Engine+ Console v0.1.0                                                 │
│  Type 'help' for commands, 'api' for API reference                      │
│                                                                         │
│  > local hp_addr = scan.first_exact(100, "i32")                         │
│  Found 1234 results                                                     │
│  > scan.next_exact(100)                                                 │
│  Narrowed to 3 results                                                  │
│  > print(memory.read_i32(hp_addr[1]))                                   │
│  100                                                                    │
│  > memory.write_i32(hp_addr[1], 9999)                                   │
│  Written 4 bytes to 0x7F01A000                                          │
│  > _                                                                    │
│                                                                         │
│  [Lua ▼] [Clear] [Save Script] [Load Script]                           │
└─────────────────────────────────────────────────────────────────────────┘
```

#### AI Chat Tab

```
┌─ AI Assistant ──────────────────────────────────────────────────────────┐
│                                                                         │
│  🤖 AI: Я проанализировал структуру по адресу 0x01A3B4C0.              │
│     Это похоже на объект класса Player:                                  │
│     - VTable pointer указывает на 23 виртуальные функции               │
│     - Поля pos_x/y/z (f32) расположены рядом — типичный паттерн       │
│     - Строка "PlayerOne" по смещению +0x30 подтверждает                 │
│     Хотите, чтобы я проанализировал VTable подробнее?                   │
│                                                                         │
│  👤 You: Да, покажи виртуальные функции и попробуй                     │
│          определить их назначение                                        │
│                                                                         │
│  🤖 AI: Анализирую VTable по адресу 0x7F401020...                      │
│     ▓▓▓▓▓▓▓▓▓░░░░░ 60% — чтение функций...                            │
│                                                                         │
│  [Type message...________________________] [Send] [📎 Attach Context]   │
│  Tokens used this session: 2,340 / budget: 10,000                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Inspector Panel — Правая панель

### Data Inspector

Автоматическая интерпретация выделенных байтов во всех возможных типах:

```
┌─ Data Inspector ────────────┐
│  Selected: 4 bytes          │
│  at 0x01A3B4D0              │
│  Bytes: 64 00 00 00         │
│  ──────────────────────     │
│  i8:     100                │
│  u8:     100                │
│  i16 LE: 100                │
│  i16 BE: 25600              │
│  i32 LE: 100         ← ★   │
│  i32 BE: 1677721600         │
│  i64 LE: ...                │
│  f32 LE: 1.401298e-43       │
│  f64 LE: ...                │
│  Hex:    0x64               │
│  Binary: 01100100 ...       │
│  ASCII:  "d..."             │
│  UTF-8:  "d..."             │
│  UTF-16: "搀..."            │
│  ──────────────────────     │
│  ★ = Most likely type       │
└─────────────────────────────┘
```

### Properties Panel

Контекстная информация о текущем элементе:

```
┌─ Properties ────────────────┐
│  Address:     0x01A3B4D0    │
│  Module:      game.exe      │
│  Section:     .data         │
│  Protection:  RW-           │
│  Region:      0x01A3B000    │
│  Region Size: 0x1000        │
│  Page State:  Committed     │
│  Allocation:  Private       │
│  ──────────────────────     │
│  Xrefs TO (3):              │
│   0x140001008  mov rcx,...  │
│   0x14000203A  lea rdx,...  │
│   0x14000540C  cmp [rdi],...│
│  ──────────────────────     │
│  Xrefs FROM (1):            │
│   → 0x7F401020 (vtable)    │
└─────────────────────────────┘
```

---

## Цветовая схема и темы

### Встроенные темы

| Тема | Описание |
|------|----------|
| **Engine+ Dark** | Тёмная тема по умолчанию (как VS Code Dark+) |
| **Engine+ Light** | Светлая тема |
| **Hacker** | Зелёный на чёрном, матричный стиль |
| **Cheat Engine Classic** | Стилизация под классический CE |
| **Monokai** | Популярная тема из Sublime Text |
| **Custom** | Полностью настраиваемая пользователем |

### Цветовое кодирование памяти

```
🟦 Синий    — Code (executable) секции
🟩 Зелёный  — Data (read/write) секции
🟨 Жёлтый   — Read-only data секции
🟧 Оранжевый — Stack
🟪 Фиолетовый — Heap
🟥 Красный  — Guard pages / No access
⬜ Серый    — Free / Unmapped
```

---

## Горячие клавиши (по умолчанию)

### Глобальные

| Клавиша | Действие |
|---------|----------|
| `Ctrl+P` | Command palette (как в VS Code) |
| `Ctrl+Shift+P` | Список процессов |
| `Ctrl+G` | Go to address |
| `Ctrl+F` | Find in current view |
| `Ctrl+H` | Find and replace (hex editor) |
| `Ctrl+Tab` | Switch tabs |
| `Ctrl+1..9` | Switch to panel |
| `F11` | Fullscreen |

### Сканирование

| Клавиша | Действие |
|---------|----------|
| `Ctrl+N` | New scan |
| `Ctrl+Enter` | Next scan |
| `Ctrl+Z` | Undo scan |
| `Ctrl+A` | Add all results to table |

### Отладка

| Клавиша | Действие |
|---------|----------|
| `F5` | Continue / Attach debugger |
| `Shift+F5` | Stop debugging |
| `F7` | Step into |
| `F8` | Step over |
| `Ctrl+F8` | Step out |
| `F4` | Run to cursor |
| `F9` | Toggle breakpoint |
| `Ctrl+F9` | Conditional breakpoint |

### Hex Editor

| Клавиша | Действие |
|---------|----------|
| `Ctrl+G` | Go to address |
| `Ctrl+C` | Copy bytes |
| `Ctrl+Shift+C` | Copy as... (format menu) |
| `Space` | Toggle hex/ASCII edit mode |
| `Ctrl+B` | Bookmark address |

---

## Адаптивный layout

### Режимы рабочего пространства (Workspace Presets)

Предустановленные конфигурации панелей:

| Preset | Описание | Панели |
|--------|----------|--------|
| **Scanner** | Фокус на сканировании | Scan panel + Results + Table |
| **Debugger** | Фокус на отладке | Disasm + Registers + Stack + Watch |
| **Reverser** | Фокус на реверсе | Disasm + Hex + Structures + AI |
| **Minimal** | Минимальный | Только Table + Scan |
| **Custom** | Пользовательский | Любая конфигурация |

### Split View

- Горизонтальное / вертикальное разделение
- До 4 одновременных view
- Синхронизация адресов между view (опционально)

---

## Технология UI

### Вариант 1: egui (рекомендуемый)

**Плюсы:**
- Чистый Rust, без зависимостей от C/C++
- Immediate mode — проще в разработке
- Встроенный рендеринг (wgpu/glow)
- Отличная документация
- Быстрый прототипирование

**Минусы:**
- Менее "нативный" внешний вид
- Ограниченные возможности кастомизации виджетов

### Вариант 2: iced

**Плюсы:**
- Elm-архитектура, чистый дизайн
- Более "нативный" вид
- Хорошая типизация

**Минусы:**
- Менее зрелый
- Сложнее для динамических layout-ов

### Вариант 3: Tauri + Web UI

**Плюсы:**
- Максимально гибкий UI (React/Vue/Svelte)
- Привычные web-инструменты
- Легко делать красивый интерфейс

**Минусы:**
- Overhead от web-движка
- Сложнее интеграция с Rust-ядром
- Большой размер приложения

> [!TIP]
> **Рекомендация**: Начать с `egui` для быстрого прототипа, 
> при необходимости перейти на `Tauri` для финального UI.
> egui позволит быстро получить рабочий продукт.
