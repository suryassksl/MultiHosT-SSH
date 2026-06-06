# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MultiHostExecutor is a Tkinter-based GUI application for executing SSH commands on multiple Linux hosts simultaneously. It's a single-file Python application (~3000 lines) with a modern, colorful dark-themed interface.

## Development Commands

### Running the Application
```bash
# Using the batch file (recommended on Windows)
./run_executor.bat

# Direct Python execution
python multi_host_executor.py
```

### Building Standalone Executable
```bash
# Using the batch file
./build_exe.bat

# Manual build
pip install pyinstaller
pyinstaller --onefile --windowed --name "MultiHostExecutor" multi_host_executor.py
```

The executable will be created in the `dist/` directory.

### Installing Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
- `paramiko>=3.0.0` - SSH connections and authentication
- `openpyxl>=3.0.0` - Excel export functionality
- `tkinter` - GUI framework (included with Python)

## Architecture

### Single-File Design
The entire application is in `multi_host_executor.py` for simplicity and easy distribution. Main components:

**Manager Classes** (handle persistence):
- `CommandPresetManager` - Saves/loads command presets to `~/.ssh_executor_presets.json`
- `HostGroupManager` - Saves/loads host groups to `~/.ssh_executor_host_groups.json`
- `SessionConfigManager` - Saves/loads session config to `~/.ssh_executor_session.json` (excludes passwords)

**UI Components**:
- `Theme` - Color constants for the modern gradient UI (purple/blue theme)
- `StunningHeader` - Animated gradient header with title
- `ColorfulSectionHeader` - Section headers for UI organization
- `ModernButton` / `StyledButton` - Custom styled buttons with hover effects
- `HostResultCard` - Collapsible cards showing per-host command results

**Core Logic**:
- `SSHExecutor` - Handles SSH connections, command execution, and sudo password handling
  - Supports password auth and SSH key auth (RSA, Ed25519, ECDSA, DSS)
  - Automatic sudo password injection
  - Configurable connection timeout and concurrent connection limits
- `MultiHostExecutorApp` - Main application class containing the Tkinter GUI and orchestration logic
  - Thread pool for concurrent SSH connections
  - Queue-based result handling
  - Export to TXT and Excel formats

### Execution Flow
1. User enters credentials (password or SSH key path) and hosts
2. User enters commands (newline-separated)
3. On "Execute", app spawns thread pool with configurable max workers
4. Each host gets SSHExecutor instance that:
   - Establishes SSH connection
   - Executes commands sequentially
   - Handles sudo password injection automatically
   - Returns combined output or error
5. Results populate UI as HostResultCards (green=success, red=failure)
6. Failed hosts can be retried with "Retry Failed" button

### Key Features Implementation
- **Multi-host execution**: Uses `ThreadPoolExecutor` for concurrent SSH connections
- **Sudo support**: Detects sudo commands and injects password via channel input
- **Session persistence**: Saves last-used config (username, hosts, commands, SSH key path) but never passwords
- **Import/Export**: Supports TXT/CSV for hosts, TXT/Excel for results
- **Broadcast mode**: Re-executes on previously successful hosts without re-entering them

## Development Notes

### UI Theme
The application uses a custom dark theme with gradient colors. All color constants are in the `Theme` class. The header uses an animated gradient effect that cycles through 5 colors.

### Threading Model
- Main thread handles Tkinter UI
- Worker threads handle SSH connections via ThreadPoolExecutor
- Results passed back via `queue.Queue` and processed by `process_result_queue()` running on main thread via `after()`

### Configuration Files
All config files use JSON format and are stored in the user's home directory with dot-prefixes for Unix-style hidden files.

### SSH Key Support
The app searches `~/.ssh/` for common key types when "Browse SSH Keys" is clicked. Supported formats: RSA, Ed25519, ECDSA, DSS (both with and without .pub extension).

### PyInstaller Notes
The `--windowed` flag is used to prevent console window. The `--onefile` flag bundles everything into a single executable. Multiple `.spec` files exist from previous builds but are not actively used.
