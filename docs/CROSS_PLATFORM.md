# Кроссплатформенность (Cross-Platform Architecture)

Engine+ проектируется как **полноценно мультиплатформенный инструмент**. В отличие от Cheat Engine, который исторически привязан к Windows API и Lazarus, архитектура Engine+ разделяет логику движка и платформозависимый доступ к операционной системе.

---

## 1. Слой абстракции: Process Access Layer (PAL)

Ядро программы (`engine-core`), сканер, эвристики и графический интерфейс оперируют только абстрактным Rust-трейтом:

```rust
pub trait ProcessAccessLayer: Send + Sync {
    fn attach(&mut self, pid: ProcessId) -> Result<()>;
    fn detach(&mut self) -> Result<()>;
    
    fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>>;
    fn write_memory(&self, address: u64, data: &[u8]) -> Result<()>;
    
    fn query_regions(&self) -> Result<Vec<MemoryRegion>>;
    fn enumerate_modules(&self) -> Result<Vec<ModuleInfo>>;
    fn enumerate_threads(&self) -> Result<Vec<ThreadInfo>>;
    
    fn set_breakpoint(&mut self, address: u64, bp_type: BreakpointType) -> Result<BreakpointId>;
    fn remove_breakpoint(&mut self, id: BreakpointId) -> Result<()>;
    
    fn stealth_level(&self) -> StealthLevel;
}
```

---

## 2. Реализация под конкретные ОС

### 2.1. Linux
- **Чтение/Запись:**
  - `process_vm_readv` / `process_vm_writev` — самый быстрый юзермодный путь (zero-copy в ядре).
  - `/proc/<pid>/mem` — альтернативный файловый дескриптор.
  - `Direct Syscalls` (ассемблерный вызов номера сисколла минуя glibc) для обхода хуков.
- **Карта памяти:** парсинг `/proc/<pid>/maps`.
- **Модули и потоки:** `/proc/<pid>/task/`, ELF-заголовки загруженных `.so`.
- **Отладка:** `ptrace` (PTRACE_ATTACH, PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_GETREGS).
- **Стелс ядро:** LKM драйвер `engine_plus.ko`.

### 2.2. Windows (С правами Администратора)
Engine+ запускается с правами Администратора (UAC Run as Administrator), что позволяет:
- **Активация привилегий отладки:** Автоматический запрос `SeDebugPrivilege` через `AdjustTokenPrivileges`, открывающий полный доступ `PROCESS_ALL_ACCESS` к любым процессам в системе.
- **Чтение/Запись:**
  - Стандартный путь: `OpenProcess(PROCESS_ALL_ACCESS)` + `ReadProcessMemory` / `WriteProcessMemory`.
  - Скрытный путь (Stealth): Прямые сисколлы ядра NT (`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtOpenProcess`) минуя `kernel32.dll` и EDR-хуки.
- **Карта памяти:** `VirtualQueryEx` (обход цепочек страниц памяти).
- **Модули и потоки:** `CreateToolhelp32Snapshot`, `EnumProcessModulesEx`, чтение PEB (Process Environment Block).
- **Отладка:** `DebugActiveProcess`, управление контекстом потока через `GetThreadContext`/`SetThreadContext` (аппаратные точки останова DR0–DR3).
- **Стелс ядро:** Установка и запуск KMDF-драйвера `.sys` через Service Control Manager.

### 2.3. Игры под Wine / Proton (Linux / Steam Deck)
Огромная часть игр на Linux запускается через Proton/Wine.
- Игра для Windows (`game.exe`) внутри Linux работает как стандартный нативный Linux-процесс.
- Engine+ умеет:
  1. Читать процесс как Linux-процесс через `process_vm_readv` и `/proc/<pid>/mem`.
  2. Автоматически транслировать PE-заголовки Windows и адреса виртуальных модулей (`game.exe+0x1000`), сопоставляя их с mmap-страницами Wine.
  3. Работать со Steam Deck и портативными консолями.

*(Примечание: Поддержка macOS исключена из скоупа проекта и не планируется).*

---

## 3. Поддержка 32-bit (x86) и 64-bit (x86_64 / WOW64)

Многие старые и инди-игры скомпилированы под 32-битную архитектуру. Engine+ автоматически определяет разрядность целевого процесса:
- **Размер указателей:** 4 байта для x86, 8 байт для x86_64.
- **Дизассемблер `iced-x86`:** Автоматически переключает режим декодирования (16-bit, 32-bit или 64-bit).
- **Регистры процессора:** В 32-битном процессе отображаются `EAX`, `EBX`, `ESP`, `EIP` вместо 64-битных `RAX`, `RSP`, `RIP`.
- **На Windows (WOW64):** Использование `IsWow64Process`, чтение PEB32 и перечисление 32-битных модулей через `LIST_MODULES_32BIT`.

---

## 4. Пауза и заморозка процесса во время сканирования

Чтобы значения в памяти не менялись во время длительного сканирования (race conditions), движок предоставляет опцию **«Pause target process during scan»**:
- **Linux:** Сигналы `kill(pid, SIGSTOP)` перед началом чтения и `kill(pid, SIGCONT)` сразу после завершения.
- **Windows:** Нативные вызовы `NtSuspendProcess(handle)` и `NtResumeProcess(handle)`.

---

## 5. Запуск с повышенными привилегиями (`sudo` / `root`)

В Engine+ принято проектное решение: инструмент запускается с правами суперпользователя (`sudo engine-plus` на Linux и «Запуск от имени администратора» на Windows).

### Преимущества запуска с `sudo` на Linux:
1. **Обход Yama `ptrace_scope`:** Ограничения системной безопасности (`kernel.yama.ptrace_scope`) автоматически перестают действовать. Engine+ получает неограниченное право присоединяться (`ptrace`) к процессам любых пользователей.
2. **Прямой доступ к памяти:** Файл `/proc/<pid>/mem` и сисколл `process_vm_readv` работают без ограничений безопасности ядра.
3. **Загрузка Kernel-драйвера:** Позволяет беспрепятственно загружать модуль ядра (`insmod engine_plus.ko`) для ring0 стелс-режима.
4. **Управление памятью:** Возможность переводить память процесса в защищённые режимы (`PROT_READ | PROT_WRITE | PROT_EXEC`) без запретов SELinux/AppArmor в типичных конфигурациях.

---

## 6. Схема компиляции и условных флагов в Cargo

```
crates/engine-pal/
├── src/
│   ├── lib.rs
│   ├── traits.rs           # Общий PAL-интерфейс
│   ├── os/
│   │   ├── linux/          # #[cfg(target_os = "linux")]
│   │   │   ├── process_vm.rs
│   │   │   ├── proc_mem.rs
│   │   │   └── ptrace.rs
│   │   └── windows/        # #[cfg(target_os = "windows")]
│   │       ├── winapi.rs
│   │       └── ntdll_syscalls.rs
```

Благодаря Rust компилятор проверяет код под каждую платформу, собирая нативный, быстрый бинарник без лишних зависимостей.
