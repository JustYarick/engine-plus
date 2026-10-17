# ⚙️ Core Features — Основной функционал Engine+

## Обзор

Engine+ предоставляет полный набор инструментов для runtime-анализа процессов,
статического анализа файлов и автоматизированного реверс-инжиниринга.

---

## 1. 🔍 Memory Scanner — Сканирование памяти

Самый важный и часто используемый компонент.

### Типы сканирования

| Тип | Описание | Примеры |
|-----|----------|---------|
| **Exact Value** | Точное совпадение | `100`, `3.14`, `"Hello"` |
| **Changed / Unchanged** | Изменилось / не изменилось | Между двумя сканами |
| **Increased / Decreased** | Увеличилось / уменьшилось | Для отслеживания здоровья и т.п. |
| **Increased by / Decreased by** | Изменение на конкретное значение | `+10`, `-5` |
| **Between** | В диапазоне | `100..200` |
| **Unknown Initial** | Неизвестное начальное значение | Первый скан сохраняет всё |
| **AOB (Array of Bytes)** | Поиск паттерна байт | `48 8B 05 ?? ?? ?? ?? 48 89` |
| **String** | Поиск строк | UTF-8, UTF-16, ASCII |
| **Regex** | Регулярные выражения в памяти | Для сложных паттернов |
| **Fuzzy Float** | Нечёткое сравнение float | С epsilon-погрешностью |
| **Custom Expression** | Пользовательское выражение | `value > 50 && value < 200` |

### Типы данных

```
Byte (i8/u8)          — 1 байт
Short (i16/u16)       — 2 байта  
Int (i32/u32)         — 4 байта
Long (i64/u64)        — 8 байта
Float (f32)           — 4 байта
Double (f64)          — 8 байта
String (UTF-8/16)     — переменная длина
Array of Bytes        — переменная длина
Pointer (usize)       — 4/8 байт
Custom Struct         — пользовательский размер
SIMD (f32x4, f64x2)  — 16/32 байта
```

### Возможности сканера

- **Multi-threaded scan** — параллельное сканирование по регионам
- **Scan history** — undo/redo сканирований
- **Scan alignment** — выравнивание по 1/2/4/8 байт
- **Region filter** — сканирование только определённых регионов
- **Writable only** — только записываемые страницы
- **Executable only** — только исполняемые (для поиска кода)
- **Module filter** — сканирование только в определённых модулях
- **Результаты в реальном времени** — live-обновление найденных значений
- **Group scan** — поиск нескольких связанных значений одновременно

### Продвинутые режимы

```rust
pub struct ScanConfig {
    pub value_type: ValueType,
    pub scan_type: ScanType,
    pub alignment: usize,
    pub region_filter: RegionFilter,
    pub max_results: Option<usize>,
    pub thread_count: usize,
    pub fast_scan: bool,          // Skip small regions
    pub pause_during_scan: bool,  // Pause target process
    pub endianness: Endianness,   // Big/Little endian
}
```

---

## 2. 🐛 Debugger — Отладчик

Полнофункциональный отладчик, интегрированный в интерфейс.

### Breakpoints

| Тип | Описание | Реализация |
|-----|----------|------------|
| **Software BP** | INT3 (0xCC) | Замена инструкции |
| **Hardware BP** | DR0-DR3 | Через debug-регистры |
| **Memory BP** | На чтение/запись | Guard pages / HW watchpoints |
| **Conditional BP** | С условием | `rax > 100 && [rbp-0x10] == 42` |
| **Log BP** | Логирование без остановки | Запись значений при срабатывании |
| **Count BP** | Счётчик срабатываний | Для профилирования |

### Stepping

- **Step Into** — шаг внутрь вызова (F7)
- **Step Over** — шаг через вызов (F8)  
- **Step Out** — выход из функции (Ctrl+F8)
- **Run to Cursor** — выполнение до курсора (F4)
- **Run to Return** — выполнение до RET
- **Reverse Step** — обратный шаг (через запись состояний)

### Watch expressions

```
Отслеживание произвольных выражений:
- Значения регистров:    rax, rbx, rsp, rip
- Значения в памяти:     [rsp+0x20], [rax*8+rbx]
- Вычисляемые:           rax + rbx * 2
- Dereferencing:          *[rsp+0x10] as *Player
- Вложенные:             player.health, entity.pos.x
```

### Trace / Record

- **Instruction trace** — запись всех выполненных инструкций
- **Call trace** — запись стека вызовов
- **Memory trace** — запись всех обращений к памяти
- **Time travel debugging** — воспроизведение с любого момента (планируется)

---

## 3. 📝 Disassembler / Assembler

### Disassembler

- **Архитектуры**: x86, x86_64, ARM, AArch64
- **Синтаксис**: Intel, AT&T (переключаемый)
- **Дополнительно**:
  - Автоматическое определение функций
  - Cross-reference analysis (xrefs)
  - Комментарии пользователя
  - Подсветка переходов (branch arrows)
  - Inline-отображение строк и констант
  - Подсветка изменённых байт
  - Отображение виртуальных/физических адресов

### Assembler (Inline)

- Сборка инструкций прямо в интерфейсе
- Auto-complete для инструкций
- Multi-line assembler (патч-скрипты)
- Автоматический расчёт relative jumps
- NOP-fill при замене инструкций меньшего размера

```
Пример inline-ассемблирования:
  [Original]  mov eax, [rbx+0x10]      → 8B 43 10
  [Patched]   mov eax, 0x64            → B8 64 00 00 00
                                          90 (NOP fill)
```

---

## 4. 🧩 Structure Dissector — Анализ структур

### Ручной режим

- Визуальный hex-view с возможностью определять поля
- Drag-and-drop типов на байты
- Группировка и вложенные структуры
- Генерация C/Rust кода структуры
- Сравнение нескольких экземпляров одной структуры

### AI-режим (через MCP)

- Автоматическое определение типов полей
- Эвристический анализ паттернов (vtable, pointers, floats)
- Сравнение с известными структурами (SDK, game engines)
- Именование полей на основе использования
- Рекурсивный анализ вложенных указателей

```rust
pub struct FieldAnalysis {
    pub offset: usize,
    pub size: usize,
    pub inferred_type: InferredType,
    pub confidence: f64,           // 0.0 - 1.0
    pub suggested_name: String,
    pub evidence: Vec<Evidence>,   // Почему так решили
    pub references: Vec<u64>,      // Кто ссылается на это поле
}

pub enum InferredType {
    Integer { signed: bool, size: usize },
    Float { size: usize },
    Pointer { target_type: Option<Box<InferredType>> },
    VTablePtr { class_name: Option<String> },
    String { encoding: StringEncoding },
    Array { element_type: Box<InferredType>, count: usize },
    Padding,
    BitField { bits: Vec<BitFieldEntry> },
    Enum { variants: Vec<(i64, String)> },
    Unknown,
}
```

---

## 5. 🔗 Pointer Scanner — Сканер указателей

Поиск стабильных цепочек указателей до целевого адреса.

### Возможности

- **Multi-level scan** — поиск цепочек до N уровней глубины
- **Max offset** — ограничение смещения на каждом уровне
- **Rescan** — повторная проверка после перезапуска
- **Pointer map** — визуализация графа указателей
- **Merge results** — объединение результатов нескольких сканирований
- **Export** — экспорт в формат CE pointer map

```
Пример результата:
  "game.exe"+0x01A3B4C0 → +0x10 → +0x48 → +0x100 = Target (HP)
  "game.exe"+0x01A3B4C0 → +0x10 → +0x48 → +0x104 = Target+4 (MaxHP)
```

---

## 6. 📂 File Analyzer — Статический анализ файлов

Анализ исполняемых файлов без запуска.

### PE (Windows)

- Заголовки (DOS, NT, Optional)
- Секции (.text, .data, .rdata, .rsrc)
- Import/Export таблицы
- Relocation таблицы
- TLS callbacks
- Debug информация
- Resources
- .NET metadata (если CLR)
- Rich header analysis
- Digital signatures

### ELF (Linux)

- Program/Section headers
- Symbol tables (.symtab, .dynsym)
- Dynamic linking info
- DWARF debug info
- GOT/PLT analysis
- RELRO analysis
- Stack canary detection

### Общее

- Entropy analysis (обнаружение упакованных секций)
- String extraction с классификацией
- Crypto constant detection (AES S-boxes, etc.)
- Вложенные файлы (overlay, resources)
- YARA-правила сканирование

---

## 7. ⏱️ Speed Hack — Управление временем

Изменение скорости выполнения целевого процесса.

### Методы

| Метод | Описание | Стабильность |
|-------|----------|-------------|
| **API Hook** | Перехват GetTickCount, QueryPerformanceCounter, clock_gettime | Высокая |
| **RDTSC Hook** | Перехват инструкции RDTSC | Средняя |
| **Timer Multiplier** | Множитель возвращаемого времени | Высокая |

### Возможности

- Плавная регулировка скорости (0.1x — 100x)
- Отдельное управление для разных таймеров
- Горячие клавиши для быстрого переключения
- Профили скорости

---

## 8. 📊 Cheat Table Manager — Управление таблицами

### Формат таблиц

Собственный формат `.ept` (Engine+ Table) на основе JSON/MessagePack:

```json
{
  "version": "1.0",
  "game": "Example Game",
  "process": "game.exe",
  "entries": [
    {
      "description": "Health",
      "address": "\"game.exe\"+0x01A3B4C0 -> +0x10 -> +0x48 -> +0x100",
      "type": "i32",
      "frozen": false,
      "freeze_value": null,
      "hotkey": "F1",
      "group": "Player Stats",
      "scripts": []
    }
  ],
  "scripts": [
    {
      "name": "God Mode",
      "language": "lua",
      "code": "...",
      "hotkey": "F5",
      "enabled": false
    }
  ],
  "structures": [...],
  "notes": "..."
}
```

### Совместимость

- Импорт Cheat Engine `.ct` файлов
- Экспорт в CE-формат
- Shared tables (онлайн-библиотека, опционально)

---

## 9. 🔧 Дополнительные инструменты

### Process List

- Иерархическое дерево процессов
- Иконки процессов
- Информация: PID, modules, threads, memory usage
- Поиск и фильтрация
- Отслеживание новых процессов

### Module Inspector

- Список загруженных модулей
- Base address, size, path
- Exports/Imports browser
- Section viewer

### Thread Manager

- Список потоков с состоянием
- Suspend/Resume потоков
- Stack trace для каждого потока
- Thread priority управление

### Memory Map

- Визуальная карта памяти процесса
- Цветовое кодирование: код, данные, стек, куча
- Права доступа (R/W/X)
- Module boundaries

### Hex Editor

- Классический hex-view с интерактивным редактированием
- Data inspector (множество интерпретаций выделенных байт)
- Bookmarks
- Diff view (сравнение двух дампов)
- Copy as (C array, Rust array, Lua byte table, hex string)
- Goto address
- Follow pointer

### Lua Console

- REPL с доступом к API движка
- Auto-complete
- Syntax highlighting
- Script history
- Script manager

---

## 10. 📡 Сетевые инструменты (планируется)

### Packet Sniffer

- Перехват сетевых пакетов процесса
- Фильтрация и поиск
- Декодирование известных протоколов
- Replay пакетов

### API Monitor

- Перехват системных вызовов
- Win32 API trace
- Socket operations logging
- File I/O monitoring
