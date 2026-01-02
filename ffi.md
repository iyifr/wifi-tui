# macOS WiFi Scanning: FFI Challenges and Solutions

This document explains why this project uses `system_profiler` instead of CoreWLAN for WiFi scanning on macOS.

## The CoreWLAN Problem

### What is CoreWLAN?

CoreWLAN is Apple's Objective-C framework for WiFi operations. It provides a clean API for:
- Scanning for nearby networks
- Getting network details (SSID, BSSID, signal strength, security)
- Connecting to networks

### The Location Services Requirement

Starting with **macOS 10.15 (Catalina)**, Apple added a privacy restriction:

> CoreWLAN requires Location Services permission to return network SSIDs and BSSIDs.

This is because WiFi MAC addresses (BSSIDs) can be used to determine physical location via databases like WiGLE. Apple considers this privacy-sensitive data.

**Without Location Services permission:**
- `CWInterface.scanForNetworksWithName()` returns network objects
- But `CWNetwork.ssid` returns `nil` (null)
- And `CWNetwork.bssid` returns `nil` (null)
- Only signal strength and channel are available

### Why This Breaks CLI Tools

Location Services permission on macOS is designed for GUI applications:

1. **Permission Dialog**: macOS shows a system dialog asking users to grant permission
2. **Dialog Requirements**: The dialog only appears for apps with:
   - A valid `Info.plist` with `NSLocationUsageDescription`
   - An active NSApplication instance (GUI context)
   - Proper code signing (preferably with Apple Developer certificate)

3. **CLI Tool Problem**: Command-line tools:
   - Don't have an NSApplication context
   - Inherit permissions from their parent terminal app
   - Terminal apps (Terminal.app, iTerm2, Ghostty, etc.) don't request location by default
   - There's no reliable way to trigger the permission dialog

### What I Tried

1. **Embedding Info.plist in binary**: Used `#[link_section = "__TEXT,__info_plist"]` to embed the plist
2. **Creating an .app bundle**: Wrapped the CLI in a proper macOS application bundle
3. **Initializing NSApplication**: Created a GUI context before requesting permission
4. **Code signing**: Ad-hoc signed the binary
5. **Running CFRunLoop**: Allowed the system to process the permission dialog

**Result**: None of these reliably triggered the permission dialog for a CLI tool. The permission would show as "Not Determined" even after multiple attempts.

### The Terminal Permission Problem

Even if we could request permission for our app, there's another issue:

- CLI tools run **inside** a terminal application
- macOS grants permissions to the **terminal app**, not the CLI tool
- Users would need to grant Location Services permission to Terminal.app or their IDE
- Most users don't have their terminal in Location Services
- There's no "+ button" to manually add apps on my Mac (2019 Macbook pro)

## The airport Command (Deprecated, Non-functional)

### What is airport?

`airport` is a command-line tool bundled with macOS at:
```
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
```

### The Problem

On **macOS 14 (Sonoma) and later**, the `airport` command is completely non-functional:

```bash
$ airport -s
WARNING: The airport command line tool is deprecated and will be removed in a future release.
For diagnosing Wi-Fi related issues, use the Wireless Diagnostics app or wdutil command line tool.
```

It outputs only the deprecation warning with **no actual network data**. This makes it unusable.

### wdutil (Requires Root)

Apple suggests `wdutil` as a replacement:

```bash
sudo wdutil info    # Current connection info
sudo wdutil dump    # Detailed WiFi state
```

However:
- `wdutil` requires `sudo` (root access)
- It only shows current connection info, not nearby networks
- Not suitable for a user-facing TUI application

## The Solution: system_profiler

### What is system_profiler?

`system_profiler` is Apple's system information tool. The `SPAirPortDataType` data type provides WiFi information including nearby networks.

### Usage

```bash
system_profiler SPAirPortDataType
```

### Output Format

```
Wi-Fi:
      Interfaces:
        en0:
          ...
          Current Network Information:
            MyNetwork:
              PHY Mode: 802.11ac
              Channel: 40 (5GHz, 80MHz)
              Security: WPA2 Personal
              Signal / Noise: -62 dBm / -94 dBm
          Other Local Wi-Fi Networks:
            CoffeeShop:
              PHY Mode: 802.11
              Channel: 6 (2GHz, 40MHz)
              Security: WPA2 Personal
              Signal / Noise: -72 dBm / -94 dBm
```

### Advantages

1. **No Location Services required**
2. **Works from any terminal** without special permissions
3. **Shows nearby networks** in "Other Local Wi-Fi Networks" section
4. **Already installed** on all macOS systems
5. **Still supported** on macOS 14+

### Disadvantages

1. **Slower**: Takes 2-3 seconds to run
2. **No BSSID**: Doesn't show MAC addresses of access points
3. **Text parsing**: Requires careful parsing of indented text output
4. **May change**: Output format could change in future macOS versions

## Summary

| Approach | Works? | Why/Why Not |
|----------|--------|-------------|
| CoreWLAN direct | ❌ | Requires Location Services |
| CoreWLAN + embedded plist | ❌ | CLI tools can't trigger dialog |
| CoreWLAN + .app bundle | ❌ | Dialog still doesn't appear reliably |
| CoreWLAN + Terminal permission | ⚠️ | Works if user manually grants, but UX is poor |
| airport command | ❌ | Deprecated and non-functional on macOS 14+ |
| wdutil | ❌ | Requires sudo, only shows current connection |
| system_profiler | ✅ | Works without special permissions |

**Conclusion**: The `system_profiler SPAirPortDataType` command is the most practical solution for a CLI/TUI WiFi scanner on macOS. It works without special permissions and shows both the current network and nearby networks.
