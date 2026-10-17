# 📊 Спецификация формата чит-таблиц Engine+ (`.ept`)

Чит-таблицы в **Engine+** сохраняются в открытом формате `.ept` (Engine+ Table) на базе **JSON** (или компактного бинарного **MessagePack** для релизных сборок).

Также Engine+ имеет **встроенный двусторонний конвертер Cheat Engine `.ct` <-> `.ept`**.

---

## 1. Схема формата `.ept` (JSON Schema)

```json
{
  "$schema": "https://engine-plus.dev/schemas/ept-v1.json",
  "version": "1.0",
  "meta": {
    "title": "My Game Mega Table",
    "author": "Yarick",
    "target_process": "game.exe",
    "architecture": "x86_64",
    "created_at": "2026-10-17T17:00:00Z",
    "notes": "Активируйте God Mode перед загрузкой уровня."
  },
  "records": [
    {
      "id": "rec_001",
      "description": "Основные характеристики игрока",
      "type": "group",
      "children": [
        {
          "id": "rec_002",
          "description": "Здоровье (HP)",
          "address": "\"game.exe\"+0x01A3B4C0",
          "offsets": ["0x10", "0x48", "0x100"],
          "value_type": "i32",
          "display_format": "decimal",
          "is_pointer": true,
          "frozen": false,
          "freeze_value": 100,
          "hotkey": {
            "key": "F1",
            "action": "toggle_freeze"
          },
          "value_dropdown": null
        },
        {
          "id": "rec_003",
          "description": "Класс персонажа",
          "address": "\"game.exe\"+0x01A3B4C0",
          "offsets": ["0x10", "0x48", "0x108"],
          "value_type": "i32",
          "value_dropdown": [
            { "value": 0, "label": "Воин" },
            { "value": 1, "label": "Маг" },
            { "value": 2, "label": "Лучник" }
          ]
        }
      ]
    }
  ],
  "scripts": [
    {
      "id": "scr_001",
      "name": "God Mode (Infinite Health)",
      "language": "lua",
      "enabled": false,
      "hotkey": "NUMPAD1",
      "code": "auto_assemble([[\n[ENABLE]\nalloc(newmem, 2048)\n...\n[DISABLE]\ndealloc(newmem)\n]])"
    }
  ],
  "structures": [
    {
      "name": "PlayerEntity",
      "size": 256,
      "fields": [
        { "offset": "0x00", "name": "vtable", "type": "pointer" },
        { "offset": "0x10", "name": "pos_x", "type": "f32" },
        { "offset": "0x14", "name": "pos_y", "type": "f32" },
        { "offset": "0x18", "name": "pos_z", "type": "f32" },
        { "offset": "0x1C", "name": "health", "type": "i32" }
      ]
    }
  ]
}
```

---

## 2. Поддержка типов данных в записях

Таблица поддерживает все стандартные типы значений:
- Целые числа: `i8`, `u8`, `i16`, `u16`, `i32`, `u32`, `i64`, `u64`.
- Числа с плавающей точкой: `f32`, `f64`.
- Массивы байт: `aob` (с масками `??`).
- Строки: `string` (кодировки `utf8`, `utf16_le`, `ascii`, с опцией `zero_terminated` или фиксированной длиной).
- Битовые флаги: `bitfield` (биты от 0 до 31).

---

## 3. Совместимость с Cheat Engine (`.ct`)

Файлы `.ct` в Cheat Engine представляют собой XML-документ со специфическими тегами: `<CheatTable>`, `<CheatEntries>`, `<CheatEntry>`, `<Offsets>`, `<LuaScript>`.

### Конвертер в Engine+:
1. **Импорт `.ct`:**
   - Парсит XML-дерево.
   - Преобразует теги `<Offset>` в массив смещений цепочки указателей `offsets`.
   - Конвертирует AutoAssembler скрипты в обёртку `auto_assemble([[ ... ]])` на Lua.
   - Восстанавливает иерархию папок и записей.
2. **Экспорт в `.ct`:**
   - Сохраняет таблицу в валидный XML, который может быть открыт в официальном Cheat Engine.
