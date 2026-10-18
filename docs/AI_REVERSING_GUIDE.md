# Пошаговое руководство по реверс-инжинирингу для AI-агентов и разработчиков (Engine+)

Данный документ — это практическое руководство по подключению и использованию **Engine+** через **MCP (Model Context Protocol)** или **интерактивную консоль (REPL)** для исследования и модификации игр в реальном времени.

В качестве примера используется шутер **Assault Cube v1.3.0.2** (установлен в `~/games/`).

---

## 1. Подключение Engine+ как MCP-сервера к ИИ

Engine+ полностью поддерживает спецификацию **Model Context Protocol (MCP)** от `2024-11-05` по транспорту `stdio`.

### Конфигурация для AI-клиентов:
Добавьте следующий блок в конфигурационный файл вашего ИИ-клиента:

#### **Claude Desktop** (`~/.config/Claude/claude_desktop_config.json` на Linux):
```json
{
  "mcpServers": {
    "engine-plus": {
      "command": "/home/yarick/.local/bin/engine-plus",
      "args": ["--mcp"]
    }
  }
}
```

#### **Cursor IDE** (`~/.cursor/mcp.json`):
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

#### **Antigravity / OpenCode**:
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

## 2. Справочник инструментов MCP (23 Tools)

| Категория | Инструмент MCP | Описание |
| :--- | :--- | :--- |
| **Управление** | `process_list` | Поиск запущенных процессов с фильтрацией по имени и cmdline. |
| | `process_attach` | Подключение к процессу по PID. |
| | `process_detach` | Отключение от текущего процесса. |
| | `process_info` | Архитектура (x86_32 / x86_64), статус подключения, память. |
| **Память** | `memory_regions` | Карта памяти процесса (RWX регионы, модули, куча, стек). |
| | `memory_read` | Чтение типизированных значений (`i32`, `f32`, `string`) или raw hex. |
| | `memory_write` | Запись значений или сырых байт в память процесса. |
| | `memory_allocate` | Выделение виртуальной памяти (RWX) под кодкейвы и трамплины. |
| | `memory_free` | Освобождение выделенной памяти. |
| **Сканирование** | `memory_scan` | Быстрый параллельный сканер: первое сканирование (`first`) и фильтрация (`next`: `exact`, `increased`, `decreased`, `changed`, `unchanged`). |
| | `pointer_scan` | Многоуровневый Pointer Scanner: находит статические цепочки `module + Offset1 -> Offset2 -> Target`. |
| | `pointer_resolve` | Вычисление текущего адреса и значения по цепочке указателей. |
| **Код и Ассемблер** | `disassemble` | Дизассемблирование инструкций x86/x64 через `iced-x86`. |
| | `assemble` | Компиляция текстовых мнемоник в опкоды (машинный код). |
| | `code_patch` | Патчинг инструкций или запись NOP в память на лету. |
| | `hook_install` | Установка 5-байтового Detour-хука (трамплина) с переносом затираемых инструкций в Code Cave. |
| | `pattern_generate` | Генерация устойчивых сигнатур (AOB) с wildcard-масками (`??`) на адреса прыжков/вызовов. |
| | `find_xrefs` | Поиск перекрёстных ссылок (вызовов `call`, прыжков `jmp`, обращений `lea`) на адрес или функцию. |
| **Структуры** | `struct_reconstruct` | ReClass-анализатор: автоматическое распознавание vtable, vector3, указателей, строк, int, float. |
| | `struct_export` | Экспорт распознанной структуры в чистый код C++, Rust или C#. |
| | `struct_rename_field`| Переименование поля в структуре (например `field_0x00F8` -> `health`). |
| **Отладчик** | `debug_find_what_writes`| Движок «Что пишет в этот адрес?»: находит инструкции и сохраняет регистры. |
| | `debug_breakpoint_set`| Установка программных (`INT3`) или аппаратных (`DR0-DR3`) точек останова на запись/чтение/выполнение. |
| | `debug_get_registers` | Снимок регистров процессора (RAX..R15, RIP, EFLAGS: CF, ZF, SF, OF). |
| | `debug_pause` / `resume`| Заморозка / возобновление выполнения потоков процесса. |
| | `debug_step` | Пошаговое выполнение одной инструкции (Single Step). |
| **Скрипты и Спидхак**| `script_execute` | Исполнение безопасных Lua 5.4 скриптов с доступом к Core Memory API. |
| | `auto_assemble` | Выполнение Cheat Engine AutoAssembler скриптов (`[ENABLE]`, `[DISABLE]`, `alloc`, `labels`). |
| | `speedhack_set` | Непрерывное масштабирование скорости игры (например, `2.0` для 2x). |
| | `speedhack_generate_script` | Генерация скрипта перехвата системного таймера (`clock_gettime` / `QPC`). |

---

## 3. Мастер-класс: Пошаговый реверсинг игры (Assault Cube)

### Шаг 1. Запуск игры и поиск процесса
1. Запустите игру:
   ```bash
   /home/yarick/games/assaultcube.sh
   ```
2. ИИ-агент ищет процесс:
   ```json
   // Tool: process_list
   { "filter": "linux_64_client" }
   ```
   *Результат: PID `349709`, Arch `x64`.*
3. Присоединение:
   ```json
   // Tool: process_attach
   { "pid": 349709 }
   ```

---

### Шаг 2. Поиск здоровья игрока через Memory Scanner
1. Начальное здоровье в Assault Cube равно **100**. Запускаем первое сканирование:
   ```json
   // Tool: memory_scan
   {
     "mode": "first",
     "value": "100",
     "value_type": "i32"
   }
   ```
   *Сканер вернёт адреса (занимает ~3 мс благодаря Rayon).*
2. В игре получаем урон (например, кидаем под ноги гранату или ловим пулю бота — здоровье стало **79**).
3. Запускаем повторный скан:
   ```json
   // Tool: memory_scan
   {
     "mode": "next",
     "filter_mode": "exact",
     "value": "79",
     "value_type": "i32"
   }
   ```
4. Повторяем до тех пор, пока не останется 1 точный адрес (допустим, `0x7FFF5412A0F8`).

---

### Шаг 3. Определение структуры игрока и смещений (Hit Tracer)
Узнаем, какая инструкция ассемблера уменьшает здоровье при ранении:
```json
// Tool: debug_find_what_writes
{
  "address": "0x7FFF5412A0F8",
  "size": 4,
  "duration_ms": 1000
}
```
*Ответ анализатора:*
```
Found write hit:
  Instruction: sub dword ptr [rbx+0xF8], eax
  Address:     0x0000000000452A18
  Hits:        1
  Registers:
    RBX = 0x00007FFF5412A000  (Base Player Entity Pointer!)
    EAX = 21                  (Damage amount)
```

**Критически важный вывод для реверсера:**
* Смещение здоровья в объекте игрока: **`+0x00F8`** (248 байт от начала структуры `Player`).
* Адрес начала структуры игрока: `0x7FFF5412A000`.

---

### Шаг 4. Реконструкция структуры объекта (ReClass Style)
Изучаем весь объект игрока (координаты, патроны, броню, vtable):
```json
// Tool: struct_reconstruct
{
  "address": "0x7FFF5412A000",
  "size": 384,
  "class_name": "PlayerEntity"
}
```
*Анализатор мгновенно распознает:*
* `+0x0000`: `VTable` -> указатель на таблицу виртуальных функций в секции кода.
* `+0x0004`: `Vector3` -> координаты X, Y, Z игрока в 3D мире.
* `+0x00F8`: `Int32` -> Здоровье (`health`).
* `+0x00FC`: `Int32` -> Броня (`armor`).
* `+0x0150`: `Int32` -> Патроны текущего оружия (`primary_ammo`).

Экспортируем готовый класс в код C++:
```json
// Tool: struct_export
{
  "address": "0x7FFF5412A000",
  "size": 384,
  "language": "cpp",
  "class_name": "PlayerEntity"
}
```

---

### Шаг 5. Поиск статического указателя (Pointer Scanner)
Чтобы адрес здоровья не терялся при перезапуске игры или смене карты, находим базовый статический указатель:
```json
// Tool: pointer_scan
{
  "target_address": "0x7FFF5412A0F8",
  "max_depth": 3,
  "max_offset": 4096
}
```
*Результат:*
```json
{
  "paths_found": 1,
  "paths": [
    {
      "expression": "linux_64_client+0x1D2458 -> +0xF8",
      "module": "linux_64_client",
      "base_offset": "0x1D2458",
      "offsets": ["0xF8"]
    }
  ]
}
```

Проверяем вычисление адреса в реальном времени:
```json
// Tool: pointer_resolve
{
  "module_name": "linux_64_client",
  "base_offset": "0x1D2458",
  "offsets": ["0xF8"]
}
```
*Результат: Возвращает точный текущий адрес здоровья и значение `79`!*

---

### Шаг 6. Создание читов (AutoAssembler и Патчи)

#### 1. Бессмертие (God Mode):
Нейтрализуем инструкцию нанесения урона по адресу `0x452A18`:
```json
// Tool: auto_assemble
{
  "script": "[ENABLE]\n0x452A18:\n  nop\n  nop\n  nop\n[DISABLE]\n0x452A18:\n  sub dword ptr [rbx+0xF8], eax\n"
}
```
*После выполнения скрипта здоровье игрока перестает уменьшаться при любых попаданиях!*

#### 2. Бесконечные патроны через скрипт Lua:
```json
// Tool: script_execute
{
  "code": "local base = memory.read_u64(0x400000 + 0x1D2458)\nmemory.write_i32(base + 0x150, 999)\nreturn 'Ammo locked to 999'"
}
```

#### 3. Ускорение игры (Speed Hack):
```json
// Tool: speedhack_set
{
  "multiplier": 2.5
}
```

---

## 4. Использование через интерактивный REPL (`engine-plus console`)

Если вы работаете в терминале вручную:
```bash
engine-plus console
```
Команды в консоли:
```
engine-plus> ps client
engine-plus> attach <PID>
engine-plus [linux_64_client:PID]> scan 100 i32
engine-plus [linux_64_client:PID]> next 85
engine-plus [linux_64_client:PID]> whatwrites 0x7FFF5412A0F8 4
engine-plus [linux_64_client:PID]> ptrscan 0x7FFF5412A0F8 3
engine-plus [linux_64_client:PID]> reclass 0x7FFF5412A000 256 PlayerEntity
engine-plus [linux_64_client:PID]> export 0x7FFF5412A000 256 cpp PlayerEntity
engine-plus [linux_64_client:PID]> speedhack 2.0
```

---
*Документация сгенерирована для Engine+ v0.1.0-alpha.*
