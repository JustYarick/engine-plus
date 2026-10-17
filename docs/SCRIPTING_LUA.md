# 📜 Скриптовая подсистема Lua (Engine+ Scripting)

В качестве единственного встроенного языка скриптов для **Engine+** выбран **Lua 5.4** (через крейт `mlua` с флагом `vendored`).

---

## 1. Почему именно Lua (и почему исключён Python)

1. **Безопасность (100% изоляция в песочнице):**
   Чит-таблицы скачиваются из интернета от других пользователей. В Python невозможно надёжно запретить вредоносный код (обход через `import os`, интроспекцию и вызовы системных функций). В Lua опасные модули (`os`, `io`, `package.loadlib`, `debug`) отключаются на уровне инициализации виртуальной машины за одну строчку кода: `lua.sandbox(true)`. Пользователь может запускать любые чужие таблицы без риска заражения ПК.
2. **Нулевые зависимости и размер:**
   Lua статически вкомпилирован в бинарник (`vendored`), увеличивая его размер всего на **~350 КБ**. Не требуется установка системных пакетов `python-dev`, библиотек DLL или привязки к конкретным версиям рантайма.
3. **Отсутствие GIL и микросекундный запуск:**
   В отличие от Python, у Lua **нет Global Interpreter Lock**. Каждая таблица или таймер может иметь свой изолированный легковесный инстанс VM (~40 КБ RAM), запускающийся за микросекунды и исполняющийся в любом потоке.
4. **Стандарт комьюнити:**
   Весь существующий опыт геймхакинга и Cheat Engine построен на синтаксисе Lua.

---

## 2. Архитектура интеграции с Rust (`engine-script`)

```
┌─────────────────────────────────────────────────────────────┐
│                      Engine+ Core (Rust)                    │
│                 Arc<RwLock<EngineSession>>                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
               [mlua bindings (Zero-Copy FFI)]
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Песочница Lua 5.4 VM                      │
│                                                             │
│  Разрешено:                                 Заблокировано:  │
│  ├── table, string, math, utf8              ├── os.execute  │
│  ├── memory.* (доступ к процессу игры)      ├── io.* (диск) │
│  ├── scanner.* (быстрый поиск)              ├── package.*   │
│  ├── debugger.* (точки останова)            └── debug.*     │
│  ├── table_ui.* (управление GUI таблицей)                   │
│  └── hook.* (перехват функций)                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Полная спецификация Lua API

Скрипты получают доступ к глобальному объекту `engine`, содержащему модули:

### 3.1. Модуль `memory` (Работа с памятью игры)

```lua
-- Чтение базовых типов
local hp = memory.read_i32(0x140001000)
local coord_x = memory.read_f32("game.exe+0x20A4")
local name = memory.read_string(0x7FFF0040, 32, "utf8")
local raw_bytes = memory.read_bytes(0x140001000, 16) -- возвращает таблицу чисел

-- Запись
memory.write_i32(0x140001000, 9999)
memory.write_f32("game.exe+0x20A4", 123.45)
memory.write_bytes(0x140001000, {0x90, 0x90, 0x90}) -- NOP patch

-- Выделение и защита памяти в процессе игры
local allocated_addr = memory.alloc(4096, "rwx") -- выделение новой страницы
memory.protect(0x140001000, 64, "rwx")          -- смена прав доступа
memory.free(allocated_addr)
```

### 3.2. Модуль `scanner` (Сканирование памяти)

```lua
-- Поиск сигнатуры байт с маской (AOB)
local results = scanner.aob_scan("48 8B 05 ?? ?? ?? ?? 48 89")
for _, addr in ipairs(results) do
    print(string.format("Найдена сигнатура по адресу: 0x%X", addr))
end

-- Программный запуск сканирования
local scan = scanner.create_scan({
    type = "i32",
    alignment = 4,
    writable_only = true
})
local count = scan:first("100")
scan:next("decreased")
local addresses = scan:get_results(10) -- первые 10 адресов
```

### 3.3. Модуль `debugger` и `hook` (Перехваты и отладка)

```lua
-- Установка аппаратного брейкпоинта на запись
debugger.set_breakpoint("game.exe+0x54A0", "write", function(context)
    print("Инструкция пишет в здоровье!")
    print("RAX = " .. string.format("0x%X", context.rax))
    print("RIP = " .. string.format("0x%X", context.rip))
    
    -- Можно на лету подменить регистр!
    context.rax = 0
    return true -- true = продолжить выполнение
end)

-- Создание Inline Hook (перенаправление функции на наш шеллкод)
hook.inline_hook("game.exe+0x54A0", {
    code = [[
        mov eax, 0x64       ; всегда 100 здоровья
        mov [rcx+0x10], eax
        ret
    ]]
})
```

### 3.4. Модуль `auto_assemble` (Аналог AutoAssembler из CE)

Поддерживает привычный для комьюнити формат скриптов активации/деактивации:

```lua
auto_assemble([[
[ENABLE]
alloc(newmem, 2048)
label(returnhere)
label(originalcode)

newmem:
mov [rbx+0x18], (int)9999 ; Inf Ammo
originalcode:
mov eax, [rbx+0x18]
jmp returnhere

"game.exe"+0x1024A:
jmp newmem
nop
returnhere:

[DISABLE]
"game.exe"+0x1024A:
mov eax, [rbx+0x18]
dealloc(newmem)
]])
```

### 3.5. Модуль `table_ui` (Интеграция с графическим интерфейсом)

```lua
-- Создание записи в таблице читов
local entry = table_ui.add_entry({
    description = "Бесконечное здоровье",
    address = "game.exe+0x20A4",
    type = "i32",
    frozen = true,
    freeze_value = 100,
    hotkey = "Ctrl+NUMPAD1"
})

-- Создание таймера для периодических действий
local timer = table_ui.create_timer(100, function()
    -- вызывается каждые 100 миллисекунд
    local cur_hp = memory.read_i32(0x140001000)
    if cur_hp and cur_hp < 50 then
        memory.write_i32(0x140001000, 100)
    end
end)
```

---

## 4. Обработка ошибок и аварийные выходы
- Если скрипт пользователя зациклится (`while true do end`), Rust-контроллер прерывает исполнение через инструкционный хук `lua.set_hook` по тайм-ауту (по умолчанию **3 секунды**).
- Ошибки компиляции и рантайма выводятся в красивый встроенный лог/консоль GUI с указанием номера строки и подсветкой кода.
