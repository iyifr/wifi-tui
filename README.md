# WiFi TUI

A cross-platform terminal user interface for discovering and listing nearby WiFi networks.

![WiFi TUI Demo](https://normal.t3.storage.dev/wifi-tui2.gif)

> **Development OS:** macOS 14 (Sonoma) on a 2019 MacBook Pro

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

| Key         | Action                  |
| ----------- | ----------------------- |
| `r`         | Refresh/rescan networks |
| `j` / `↓`   | Move selection down     |
| `k` / `↑`   | Move selection up       |
| `l`         | Toggle log panel        |
| `q` / `Esc` | Quit                    |

## Platform Support

| Platform | Implementation                           | Status         |
| -------- | ---------------------------------------- | -------------- |
| macOS    | `system_profiler SPAirPortDataType`      | ✅ Working     |
| Linux    | `nmcli` (NetworkManager) / `iw` fallback | ✅ Implemented |
| Windows  | `wlanapi.dll` raw FFI                    | ✅ Implemented |

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
    └── windows.rs    # Windows: wlanapi.dll
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

## Unsafe Code & FFI

### Windows: Raw FFI to wlanapi.dll

The Windows implementation (`src/scanner/windows.rs`) uses raw FFI to the Native WiFi API. This was chosen to demonstrate FFI skills without relying on external crates like `windows-sys`.

**Safety measures implemented:**

1. **RAII Handle Management** - `WlanHandle` wrapper ensures `WlanCloseHandle` is always called via `Drop`, even on error paths

2. **Memory Management** - All Windows-allocated memory (`WLAN_INTERFACE_INFO_LIST`, `WLAN_AVAILABLE_NETWORK_LIST`, `WLAN_BSS_LIST`) is freed with `WlanFreeMemory` before returning

3. **Pointer Validation** - Return codes checked before dereferencing pointers; `ERROR_SUCCESS` required

4. **Struct Layout** - All structs use `#[repr(C)]` with field order matching [official Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/)

**API functions used:**

- `WlanOpenHandle` / `WlanCloseHandle` - Connection lifecycle
- `WlanEnumInterfaces` - Discover wireless adapters
- `WlanScan` - Trigger fresh network scan
- `WlanGetAvailableNetworkList` - Get visible networks
- `WlanGetNetworkBssList` - Get BSSID and channel info

### macOS & Linux: No Unsafe Code

Both macOS and Linux implementations use safe Rust only, spawning system commands (`system_profiler`, `nmcli`, `iw`) and parsing their text output. See [ffi.md](./ffi.md) for why CoreWLAN FFI was abandoned on macOS.

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

  ████ | 2.4GHz |  -50 dBm | WPA2 | MyNetwork
  ███░ |  5GHz  |  -65 dBm | WPA2 | CoffeeShop
  ██░░ | 2.4GHz |  -76 dBm | WPA2 | Neighbor
  █░░░ | 2.4GHz |  -85 dBm | Open | FreeWiFi
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

## Future Improvements

- **Connect to networks** - Allow users to select a network and connect directly from the TUI
- **Password input** - Secure text input for entering WPA/WPA2/WPA3 credentials
- **Forget networks** - Remove saved network profiles
- **Network details view** - Expandable panel showing BSSID, exact channel, PHY mode, and more
- **Auto-refresh** - Configurable automatic rescanning interval
- **Signal history graph** - Track signal strength over time for selected network
