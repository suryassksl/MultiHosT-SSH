# MultiHost SSH

A modern, dark-themed Tkinter desktop tool that runs the same SSH commands on dozens of Linux hosts at once and shows colour-coded results per host.

> Built with `paramiko` for SSH, `concurrent.futures` for parallelism, `tkinter` for the UI, `openpyxl` for Excel export, and PBKDF2-SHA256 for the admin lock.

---

## Highlights

- **Run any list of commands on any list of hosts** — concurrently, with a configurable worker pool.
- **Two auth methods** — password or SSH key (RSA, Ed25519, ECDSA, DSS), with optional key passphrase.
- **Sudo handled automatically** — passwords are injected safely via `printf '%s\n' <pw> | sudo -S -p ''`, escaped with `shlex.quote()`.
- **Per-host result cards** — collapsible, colour-coded (green = success, red = failure), with the original commands and their full output.
- **Retry only failed hosts** — one click re-runs against the failure subset.
- **Broadcast mode** — fire a single ad-hoc command at the hosts already connected, without re-typing them.
- **Imports/exports** — load hosts from TXT/CSV; export results to TXT or styled Excel (.xlsx).
- **Persistent presets** — saved command lists, host groups, and the last-used session (passwords are *never* persisted).
- **Admin lock for code editing** — the source `.py` is set read-only at startup; click the 🔒 button and enter a password (PBKDF2-HMAC-SHA256, 200k iterations, 32-byte salt) to unlock.
- **Tooltips on every control** — hover for plain-English help.
- **Keyboard shortcuts** — `Ctrl+Enter` execute, `Esc` stop, `Ctrl+L` clear results.

---

## Screenshots / quick tour

```
┌─ MultiHost SSH ────────────────────────────────────────────┐
│ HOSTS         CREDENTIALS         COMMANDS                 │
│ ┌──────────┐  ┌──────────────┐    ┌──────────────────────┐ │
│ │ 10.0.1.1 │  │ user: ...    │    │ hostname             │ │
│ │ 10.0.1.2 │  │ pw:   ●●●●●● │    │ uptime               │ │
│ │ 10.0.1.3 │  │ port: 22     │    │ df -h                │ │
│ └──────────┘  └──────────────┘    └──────────────────────┘ │
│                                                            │
│              ▶ EXECUTE COMMANDS                            │
│  STOP  RETRY  CLEAR             SAVE  COPY  EXCEL  TXT     │
├────────────────────────────────────────────────────────────┤
│ 📡 Ready when you are                                      │
│ ① auth  ② hosts  ③ commands → click EXECUTE                │
└────────────────────────────────────────────────────────────┘
© 2026 MultiHost SSH • Crafted with ♥ by SURYA SSK • sl.suryassk@outlook.com
```

---

## Installation

### Option A — Run from source (developer mode)

```bash
# 1. Install Python 3.9+ from https://python.org (with "Add to PATH")
# 2. Install dependencies
python -m pip install -r requirements.txt

# 3. Launch
python multi_host_executor.py
```

On Windows you can simply double-click **`run_executor.bat`** — it auto-installs missing packages and launches the app.

### Option B — Build a standalone `.exe` (no Python needed for end users)

```bash
# Windows
build_exe.bat

# Or manually on any OS:
python -m pip install pyinstaller
python -m PyInstaller --noconfirm MultiHostExecutor.spec
```

The bundled executable lands in `dist/MultiHostExecutor.exe` — single file, no console window, ~37 MB.

---

## Dependencies

Pinned in **`requirements.txt`**:

| Package | Version | Why |
|---|---|---|
| `paramiko` | ≥ 3.0.0 | Pure-Python SSH client. Handles transport, key exchange, auth, channel I/O, and key file parsing. |
| `openpyxl` | ≥ 3.0.0 | Writes styled `.xlsx` exports with coloured headers and per-host sheets. |

**Stdlib modules used** (no install needed):

| Module | Used for |
|---|---|
| `tkinter`, `tkinter.ttk` | Native cross-platform GUI |
| `tkinter.messagebox`, `filedialog`, `simpledialog` | Standard dialogs |
| `threading`, `queue` | Background SSH workers, thread-safe UI updates |
| `concurrent.futures.ThreadPoolExecutor` | Bounded parallel SSH connections |
| `socket` | Network errors / DNS resolution |
| `json` | Persistence files (presets, groups, session, admin) |
| `csv` | Host list import |
| `os`, `sys` | File paths, frozen-exe detection |
| `shlex` | Safe shell quoting for sudo password injection |
| `hashlib`, `secrets` | PBKDF2-HMAC-SHA256 admin password hashing |
| `datetime` | Timestamps in results |
| `webbrowser` | Click-to-email link in footer |

---

## Architecture

The whole app is a single file (`multi_host_executor.py`) split into clearly-labelled sections. Top-level classes:

### Persistence (JSON files in `~`)

| Class | Stores | File |
|---|---|---|
| `CommandPresetManager` | named command lists | `~/.ssh_executor_presets.json` |
| `HostGroupManager` | named host lists | `~/.ssh_executor_host_groups.json` |
| `SessionConfigManager` | last-used username, hosts, commands, key path (**no passwords**) | `~/.ssh_executor_session.json` |
| `AdminAuthManager` | admin password hash + salt + iteration count | `~/.ssh_executor_admin.json` (mode 600) |

### UI components

| Class | Role |
|---|---|
| `Theme` | All colour constants (purple/cyan/pink dark theme) and shared paddings |
| `StunningHeader` | Animated gradient header with logo, title, version badge, status dot |
| `ColorfulSectionHeader` | Coloured pill heading for each form section |
| `ModernButton` / `StyledButton` | Custom buttons with hover-colour interpolation and glow animations |
| `HostResultCard` | Collapsible per-host result card with success/failure styling |
| `Tooltip` | Lightweight hover tooltip used on every input/button |
| `AdminLoginDialog` | Modal dialog for setting / entering the admin password |

### Core logic

| Class | Role |
|---|---|
| `SSHExecutor` | One SSH session per host: connect, run commands, capture output, handle sudo, surface typed errors. Cancellation force-closes the active client. |
| `MultiHostExecutorApp` | Main Tk application. Owns the form, the worker thread, the result queue, and the `ThreadPoolExecutor`. |

### Execution flow

1. User fills in credentials, hosts, commands.
2. `validate_inputs()` checks ports/timeouts/concurrency and that auth fields are populated.
3. `execute_commands()` spawns a background thread (`run_execution`) that submits one task per host into a `ThreadPoolExecutor`.
4. Each `SSHExecutor.execute_commands()` runs the full command list inside one channel using a marker (`__OUTPUT_MARKER_98765__`) to split per-command output.
5. Results are pushed onto a `queue.Queue`; the main thread drains it via `root.after()` and updates the matching `HostResultCard`.
6. On Stop, `MultiHostExecutorApp.stop_execution()` calls `cancel()` on every active `SSHExecutor`, which closes the underlying paramiko client to drop blocking I/O instantly.

---

## Security model

| Concern | How it's handled |
|---|---|
| Sudo password injection | `printf '%s\n' <pw> | sudo -S -p '' <cmd>`; the password is `shlex.quote()`-escaped — safe against backticks, `$()`, `!`, etc. |
| Password storage | SSH passwords are **never written to disk**. They live only in memory for the duration of the session. |
| Admin password | PBKDF2-HMAC-SHA256, 200,000 iterations, 32-byte random salt, timing-safe verification with `secrets.compare_digest`. Stored at `~/.ssh_executor_admin.json` (chmod 600 on POSIX). |
| Source-file lock | When an admin password is configured, the `.py` file's owner write bit is stripped at startup via `os.chmod`. Only the Admin button (after correct password) restores write permission. |
| Bare `except:` | None — every `except` catches a specific exception or `Exception`, so `KeyboardInterrupt` / `SystemExit` propagate. |
| Cancel-while-hung | `SSHExecutor.cancel()` closes the active paramiko client; `as_completed()` then unblocks immediately. |

> ⚠️ Host-key verification is currently `AutoAddPolicy` (accept-on-first-use). Suitable for managed lab environments; for hostile networks add a known_hosts policy.

### Reset a forgotten admin password

Delete `~/.ssh_executor_admin.json` (Windows: `C:\Users\<you>\.ssh_executor_admin.json`). Next launch the file is re-locked only after you set a new password via the 🔒 button.

---

## Repository layout

```
MultiHostExecutor/
├── multi_host_executor.py     # The whole application (~3000 LOC)
├── requirements.txt           # Runtime Python dependencies
├── MultiHostExecutor.spec     # PyInstaller config (one-file, windowed)
├── run_executor.bat           # Quick launch (Windows, dev mode)
├── build_exe.bat              # Build the standalone .exe (Windows)
├── README.md                  # This file
├── CLAUDE.md                  # Notes for Claude Code (architectural cheat-sheet)
└── .gitignore
```

Local state files (created at runtime, **not** in git):

```
~/.ssh_executor_presets.json
~/.ssh_executor_host_groups.json
~/.ssh_executor_session.json
~/.ssh_executor_admin.json
```

---

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Enter` / `Ctrl+E` | Execute |
| `Esc` | Stop running execution |
| `Ctrl+L` | Clear results |
| `Enter` (in broadcast box) | Send broadcast command |

---

## Roadmap / known gaps

- Replace `AutoAddPolicy` with a proper known-hosts gate (MITM hardening).
- Add a per-future timeout in `as_completed()` so a single hung worker can't delay the queue forever.
- Optional: allow piping a per-host command list from a CSV instead of running the same list on each.

---

## Author

**SURYA SSK** — sl.suryassk@outlook.com

If you spot a bug or have an idea, open an issue on GitHub.

---

## License

This project is provided as-is for educational and operational use. Add a license file (`LICENSE`) before redistributing.
