# WiFi TUI

A cross-platform terminal user interface for discovering and listing nearby WiFi networks.

## Features

- Real-time WiFi network scanning
- Signal strength visualization with bars
- Channel and security protocol display
- Keyboard navigation
- Built-in log viewer for debugging

## Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/wifi-tui
```

## Controls

| Key | Action |
|-----|--------|
| `r` | Refresh/rescan networks |
| `j` / `↓` | Move selection down |
| `k` / `↑` | Move selection up |
| `l` | Toggle log panel |
| `q` / `Esc` | Quit |

## Platform Support

| Platform | Implementation | Status |
|----------|---------------|--------|
| macOS | `system_profiler SPAirPortDataType` | ✅ Working |
| Linux | `nmcli` (NetworkManager) / `iw` fallback | ✅ Implemented |
| Windows | `wlanapi.dll` raw FFI | ✅ Implemented |

### Linux Notes

The Linux scanner uses two methods:

1. **nmcli** (preferred) - Works without root on systems with NetworkManager
2. **iw** (fallback) - Requires root privileges (`sudo wifi-tui`)

Most desktop distributions (Ubuntu, Fedora, etc.) have NetworkManager pre-installed.

### Windows Notes

The Windows scanner uses raw FFI to the Native WiFi API (`wlanapi.dll`):

- No external crates required (demonstrates FFI skills)
- RAII wrapper ensures proper handle cleanup
- Retrieves SSID, BSSID, channel, signal strength, and security type
- Works on Windows 7 and later

## Architecture

```
src/
├── main.rs           # Entry point, event loop
├── app.rs            # Application state
├── ui.rs             # Ratatui rendering
├── lib.rs            # Library exports
└── scanner/
    ├── mod.rs        # Scanner trait, types
    ├── macos.rs      # macOS: system_profiler
    ├── linux.rs      # Linux: nmcli / iw
    └── windows.rs    # Windows: wlanapi.dll (planned)
```

### Design Decisions

**Why not CoreWLAN on macOS?**

CoreWLAN requires Location Services permission, which is problematic for CLI tools:
- CLI tools can't reliably trigger the permission dialog
- They inherit permissions from the parent terminal app
- Most terminals don't have Location permission by default

See [ffi.md](./ffi.md) for detailed documentation.

**Why system_profiler?**

`system_profiler SPAirPortDataType` provides WiFi network information without requiring Location Services or root access.

## Dependencies

Only three crates as required:
- `ratatui` - TUI framework
- `crossterm` - Terminal backend
- `tracing` / `tracing-subscriber` - Structured logging

## Testing the Scanner

To test WiFi scanning without the TUI:

```bash
cargo run --bin scan-test
```

Example output:
```
WiFi available: true
Interface: en0

Found 4 networks:

  ████ | Ch:  2 |  -50 dBm | WPA2 | MyNetwork
  ███░ | Ch:  6 |  -65 dBm | WPA2 | CoffeeShop
  ██░░ | Ch:  3 |  -76 dBm | WPA2 | Neighbor
  █░░░ | Ch: 11 |  -85 dBm | Open | FreeWiFi
```

## Requirements

### macOS
- macOS 10.15+ (Catalina or later)
- WiFi hardware enabled

### Linux
- NetworkManager (for non-root scanning) or `iw` package
- WiFi hardware enabled

### Windows
- Windows 7 or later
- WLAN AutoConfig service running (default on Windows)
- WiFi hardware enabled

### All Platforms
- Rust 1.70+
