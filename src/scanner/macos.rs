//! macOS WiFi Scanner Implementation using system_profiler
//!
//! This module implements WiFi scanning using the `system_profiler` command.
//!
//! # Why not CoreWLAN?
//!
//! CoreWLAN (Apple's Objective-C WiFi framework) requires Location Services
//! permission on macOS 10.15+. This creates significant UX problems for CLI tools:
//! - CLI tools inherit permissions from their parent terminal app
//! - Terminal apps don't appear in Location Services by default
//! - There's no reliable way to trigger the permission dialog for CLI tools
//! - Even with an .app bundle, the permission flow is problematic
//!
//! # Why not airport?
//!
//! The `airport` command is deprecated and completely non-functional on macOS 14+.
//! It only outputs a deprecation warning with no actual data.
//!
//! # The system_profiler solution
//!
//! `system_profiler SPAirPortDataType` provides WiFi network information including
//! nearby networks. It's slower than CoreWLAN but works without Location Services.
//!
//! See ffi.md in the project root for detailed documentation on these issues.

use std::process::Command;

use tracing::info;

use super::{NetworkInfo, ScanError, ScanResult, SecurityType, WiFiScanner};

pub struct MacOSScanner {
    interface_name: Option<String>,
}

impl MacOSScanner {
    pub fn new() -> Self {
        // Try to detect the WiFi interface name
        let interface_name = detect_wifi_interface();

        if let Some(ref name) = interface_name {
            info!(interface = %name, "macOS WiFi scanner initialized");
        }

        Self { interface_name }
    }
}

/// Detect the WiFi interface name (usually en0 or en1)
fn detect_wifi_interface() -> Option<String> {
    let output = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut lines = stdout.lines().peekable();
    while let Some(line) = lines.next() {
        if line.contains("Wi-Fi") || line.contains("AirPort") {
            if let Some(device_line) = lines.next() {
                if let Some(device) = device_line.strip_prefix("Device: ") {
                    return Some(device.trim().to_string());
                }
            }
        }
    }

    Some("en0".to_string())
}

/// Parse security type from system_profiler output
fn parse_security(security_str: &str) -> SecurityType {
    let s = security_str.to_uppercase();
    if s.contains("WPA3") && s.contains("ENTERPRISE") {
        SecurityType::WPA3Enterprise
    } else if s.contains("WPA3") {
        SecurityType::WPA3Personal
    } else if s.contains("WPA2") && s.contains("ENTERPRISE") {
        SecurityType::WPA2Enterprise
    } else if s.contains("WPA2") {
        SecurityType::WPA2Personal
    } else if s.contains("WPA") && s.contains("ENTERPRISE") {
        SecurityType::WPA2Enterprise
    } else if s.contains("WPA") {
        SecurityType::WPA
    } else if s.contains("WEP") {
        SecurityType::WEP
    } else if s.is_empty() || s.contains("NONE") || s.contains("OPEN") {
        SecurityType::Open
    } else {
        SecurityType::Unknown(security_str.to_string())
    }
}

/// Parse channel from string like "40 (5GHz, 80MHz)" or "2 (2GHz, 20MHz)"
fn parse_channel(channel_str: &str) -> u8 {
    // Extract the first number
    channel_str
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse signal strength from string like "-62 dBm / -94 dBm"
fn parse_signal(signal_str: &str) -> i32 {
    // Extract the first number (signal, not noise)
    signal_str
        .split('/')
        .next()
        .and_then(|s| {
            s.trim()
                .replace("dBm", "")
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(-100)
}

impl WiFiScanner for MacOSScanner {
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>> {
        info!("Starting WiFi scan using system_profiler");

        let output = Command::new("system_profiler")
            .arg("SPAirPortDataType")
            .output()
            .map_err(|e| ScanError::CommandFailed(format!("Failed to run system_profiler: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScanError::CommandFailed(format!("system_profiler failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut networks = Vec::new();
        let mut in_other_networks = false;
        let mut in_current_network = false;

        // Track network properties as we parse
        let mut ssid: Option<String> = None;
        let mut channel: u8 = 0;
        let mut signal: i32 = -100;
        let mut security = SecurityType::Unknown("Unknown".into());

        for line in stdout.lines() {
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Detect new interface section (like awdl0:) - these have ~8 spaces indent
            // This means we've left the en0 interface section, so stop parsing
            if indent <= 8 && trimmed.ends_with(':') && !trimmed.contains(' ') {
                in_current_network = false;
                in_other_networks = false;
                continue;
            }

            // Detect section changes within en0
            if trimmed == "Current Network Information:" {
                in_current_network = true;
                in_other_networks = false;
                continue;
            }
            if trimmed == "Other Local Wi-Fi Networks:" {
                in_other_networks = true;
                in_current_network = false;
                continue;
            }

            // Skip if not in a network section
            if !in_other_networks && !in_current_network {
                continue;
            }

            // Check if this is a network SSID line
            // SSIDs have ~12 spaces indent and end with a single colon
            // Properties have more indent (~14+ spaces) and contain "key: value"
            if trimmed.ends_with(':') && !trimmed.contains(": ") && indent >= 10 && indent <= 14 {
                // Save previous network if exists
                if let Some(prev_ssid) = ssid.take() {
                    networks.push(NetworkInfo {
                        ssid: prev_ssid,
                        bssid: None, // system_profiler doesn't show BSSID
                        signal_dbm: signal,
                        channel,
                        security: security.clone(),
                    });
                }

                // Start new network
                ssid = Some(trimmed.trim_end_matches(':').to_string());
                channel = 0;
                signal = -100;
                security = SecurityType::Unknown("Unknown".into());
            }
            // Parse properties (key: value format)
            else if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "Channel" => channel = parse_channel(value),
                    "Signal / Noise" => signal = parse_signal(value),
                    "Security" => security = parse_security(value),
                    _ => {}
                }
            }
        }

        // Don't forget the last network
        if let Some(last_ssid) = ssid {
            networks.push(NetworkInfo {
                ssid: last_ssid,
                bssid: None,
                signal_dbm: signal,
                channel,
                security,
            });
        }

        // Remove duplicates (same SSID can appear on multiple channels)
        // Keep the one with strongest signal
        networks.sort_by(|a, b| {
            if a.ssid == b.ssid {
                b.signal_dbm.cmp(&a.signal_dbm)
            } else {
                b.signal_dbm.cmp(&a.signal_dbm)
            }
        });
        networks.dedup_by(|a, b| a.ssid == b.ssid);

        info!(network_count = networks.len(), "system_profiler scan complete");
        Ok(networks)
    }

    fn is_available(&self) -> bool {
        // Check if WiFi is enabled
        Command::new("networksetup")
            .args(["-getairportpower", "en0"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("On")
            })
            .unwrap_or(false)
    }

    fn interface_name(&self) -> Option<String> {
        self.interface_name.clone()
    }
}
