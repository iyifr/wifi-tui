//! Linux WiFi Scanner Implementation
//!
//! This module implements WiFi scanning using command-line utilities.
//!
//! # Approach
//!
//! We use `nmcli` (NetworkManager CLI) as the primary method because:
//! - Works without root privileges on most desktop Linux distributions
//! - NetworkManager maintains a cache of recently seen networks
//! - Pre-installed on Ubuntu, Fedora, and most desktop distros
//!
//! Falls back to `iw` if NetworkManager is unavailable, but this requires root.
//!
//! # Why not nl80211 FFI?
//!
//! nl80211 (the kernel's netlink-based wireless interface) would require:
//! - Complex netlink socket setup and message parsing
//! - Thousands of lines of unsafe FFI code
//! - Handling of various kernel versions and quirks
//!
//! The command-line approach is more maintainable and reliable.

use std::process::Command;

use tracing::{debug, info, warn};

use super::{NetworkInfo, ScanError, ScanResult, SecurityType, WiFiScanner};

/// Linux WiFi scanner using nmcli or iw
pub struct LinuxScanner {
    interface: Option<String>,
    has_nmcli: bool,
}

impl LinuxScanner {
    pub fn new() -> Self {
        let has_nmcli = Command::new("which")
            .arg("nmcli")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let interface = detect_wifi_interface();

        if let Some(ref iface) = interface {
            info!(interface = %iface, nmcli = has_nmcli, "Linux WiFi scanner initialized");
        } else {
            warn!("No wireless interface detected");
        }

        Self { interface, has_nmcli }
    }

    /// Scan using nmcli (NetworkManager CLI)
    /// This is the preferred method as it doesn't require root
    fn scan_with_nmcli(&self) -> ScanResult<Vec<NetworkInfo>> {
        info!("Scanning with nmcli (NetworkManager)");

        // First, trigger a rescan (may fail without root, but cached results still work)
        let _ = Command::new("nmcli")
            .args(["device", "wifi", "rescan"])
            .output();

        // Get the list of networks
        // -t: terse output (colon-separated)
        // -f: specify fields
        let output = Command::new("nmcli")
            .args([
                "-t",
                "-f",
                "SSID,BSSID,SIGNAL,FREQ,SECURITY",
                "device",
                "wifi",
                "list",
            ])
            .output()
            .map_err(|e| ScanError::CommandFailed(format!("Failed to run nmcli: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScanError::CommandFailed(format!("nmcli failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let networks = parse_nmcli_output(&stdout);

        info!(network_count = networks.len(), "nmcli scan complete");
        Ok(networks)
    }

    /// Scan using iw command (requires root)
    fn scan_with_iw(&self) -> ScanResult<Vec<NetworkInfo>> {
        let interface = self.interface.as_ref().ok_or_else(|| {
            ScanError::NoInterface("No wireless interface detected. Is WiFi enabled?".into())
        })?;

        info!(interface = %interface, "Scanning with iw (requires root)");

        let output = Command::new("iw")
            .args(["dev", interface, "scan"])
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ScanError::CommandFailed("iw command not found. Install: sudo apt install iw".into())
                } else {
                    ScanError::CommandFailed(format!("Failed to execute iw: {}", e))
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
                return Err(ScanError::PermissionDenied(
                    "iw scan requires root. Try: sudo wifi-tui".into(),
                ));
            }
            return Err(ScanError::CommandFailed(format!("iw scan failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let networks = parse_iw_output(&stdout);

        info!(network_count = networks.len(), "iw scan complete");
        Ok(networks)
    }
}

impl WiFiScanner for LinuxScanner {
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>> {
        // Prefer nmcli as it works without root
        if self.has_nmcli {
            match self.scan_with_nmcli() {
                Ok(networks) if !networks.is_empty() => return Ok(networks),
                Ok(_) => debug!("nmcli returned no networks, trying iw"),
                Err(e) => debug!(error = %e, "nmcli failed, trying iw"),
            }
        }

        // Fall back to iw (requires root)
        self.scan_with_iw()
    }

    fn is_available(&self) -> bool {
        // Available if we have nmcli OR (iw + interface)
        self.has_nmcli
            || (Command::new("which")
                .arg("iw")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
                && self.interface.is_some())
    }

    fn interface_name(&self) -> Option<String> {
        self.interface.clone()
    }
}

/// Detect the wireless interface name
fn detect_wifi_interface() -> Option<String> {
    // Try iw dev first (most reliable)
    if let Ok(output) = Command::new("iw").arg("dev").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(iface) = trimmed.strip_prefix("Interface ") {
                return Some(iface.trim().to_string());
            }
        }
    }

    // Fallback: look for common interface names in /sys/class/net
    for iface in ["wlan0", "wlp2s0", "wlp3s0", "wifi0"] {
        let path = format!("/sys/class/net/{}/wireless", iface);
        if std::path::Path::new(&path).exists() {
            return Some(iface.to_string());
        }
    }

    None
}

/// Parse nmcli terse output
/// Format: SSID:BSSID:SIGNAL:FREQ:SECURITY
fn parse_nmcli_output(output: &str) -> Vec<NetworkInfo> {
    let mut networks = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // nmcli uses : as separator, but BSSID also contains colons
        // Format: SSID:AA\:BB\:CC\:DD\:EE\:FF:SIGNAL:FREQ:SECURITY
        // The BSSID colons are escaped with backslashes
        let parts: Vec<&str> = line.split(':').collect();

        if parts.len() < 5 {
            continue;
        }

        // SSID is first field (may be empty for hidden networks)
        let ssid = parts[0].replace("\\:", ":"); // Unescape any colons in SSID

        // Skip hidden networks
        if ssid.is_empty() {
            continue;
        }

        // BSSID is parts 1-6 (MAC address with escaped colons)
        // We need to reconstruct it
        let bssid = if parts.len() >= 7 {
            Some(format!(
                "{}:{}:{}:{}:{}:{}",
                parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
            ))
        } else {
            None
        };

        // Signal, Freq, Security are after BSSID
        let (signal_idx, freq_idx, security_idx) = if parts.len() >= 9 {
            (7, 8, 9)
        } else {
            continue;
        };

        let signal: i32 = parts
            .get(signal_idx)
            .and_then(|s| s.parse().ok())
            .map(|pct: i32| {
                // nmcli reports signal as percentage (0-100)
                // Convert to approximate dBm: -30 (best) to -90 (worst)
                -90 + (pct * 60 / 100)
            })
            .unwrap_or(-100);

        let freq: u32 = parts
            .get(freq_idx)
            .and_then(|s| s.replace(" MHz", "").parse().ok())
            .unwrap_or(0);

        let security_str = parts.get(security_idx).unwrap_or(&"");
        let security = parse_security_string(security_str);

        networks.push(NetworkInfo {
            ssid,
            bssid,
            signal_dbm: signal,
            channel: freq_to_channel(freq),
            security,
        });
    }

    // Sort by signal strength (strongest first) and deduplicate
    networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    networks.dedup_by(|a, b| a.ssid == b.ssid);

    networks
}

/// Parse iw scan output
/// Format: BSS blocks starting with "BSS xx:xx:xx:xx:xx:xx"
fn parse_iw_output(output: &str) -> Vec<NetworkInfo> {
    let mut networks = Vec::new();
    let mut current_bssid: Option<String> = None;
    let mut current_ssid: Option<String> = None;
    let mut current_signal: i32 = -100;
    let mut current_freq: u32 = 0;
    let mut has_wpa = false;
    let mut has_rsn = false;
    let mut has_wpa3 = false;
    let mut has_privacy = false;

    for line in output.lines() {
        let trimmed = line.trim();

        // New BSS block starts
        if trimmed.starts_with("BSS ") {
            // Save previous network if complete
            if let (Some(bssid), Some(ssid)) = (&current_bssid, &current_ssid) {
                if !ssid.is_empty() {
                    let security = determine_security(has_wpa, has_rsn, has_wpa3, has_privacy);
                    networks.push(NetworkInfo {
                        ssid: ssid.clone(),
                        bssid: Some(bssid.clone()),
                        signal_dbm: current_signal,
                        channel: freq_to_channel(current_freq),
                        security,
                    });
                }
            }

            // Reset for new network
            current_bssid = trimmed
                .strip_prefix("BSS ")
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
            current_ssid = None;
            current_signal = -100;
            current_freq = 0;
            has_wpa = false;
            has_rsn = false;
            has_wpa3 = false;
            has_privacy = false;
        } else if let Some(ssid) = trimmed.strip_prefix("SSID: ") {
            current_ssid = Some(ssid.to_string());
        } else if let Some(signal) = trimmed.strip_prefix("signal: ") {
            // Format: "-XX.XX dBm"
            current_signal = signal
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<f32>().ok())
                .map(|f| f as i32)
                .unwrap_or(-100);
        } else if let Some(freq) = trimmed.strip_prefix("freq: ") {
            current_freq = freq.parse().unwrap_or(0);
        } else if trimmed.starts_with("WPA:") {
            has_wpa = true;
        } else if trimmed.starts_with("RSN:") {
            has_rsn = true;
        } else if trimmed.contains("SAE") || trimmed.contains("WPA3") {
            has_wpa3 = true;
        } else if trimmed.contains("Privacy") {
            has_privacy = true;
        }
    }

    // Don't forget the last network
    if let (Some(bssid), Some(ssid)) = (&current_bssid, &current_ssid) {
        if !ssid.is_empty() {
            let security = determine_security(has_wpa, has_rsn, has_wpa3, has_privacy);
            networks.push(NetworkInfo {
                ssid: ssid.clone(),
                bssid: Some(bssid.clone()),
                signal_dbm: current_signal,
                channel: freq_to_channel(current_freq),
                security,
            });
        }
    }

    // Sort by signal strength and deduplicate
    networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    networks.dedup_by(|a, b| a.ssid == b.ssid);

    networks
}

/// Parse security string from nmcli output
fn parse_security_string(security: &str) -> SecurityType {
    let s = security.to_uppercase();
    if s.contains("WPA3") {
        if s.contains("ENTERPRISE") || s.contains("802.1X") {
            SecurityType::WPA3Enterprise
        } else {
            SecurityType::WPA3Personal
        }
    } else if s.contains("WPA2") {
        if s.contains("ENTERPRISE") || s.contains("802.1X") {
            SecurityType::WPA2Enterprise
        } else {
            SecurityType::WPA2Personal
        }
    } else if s.contains("WPA") {
        SecurityType::WPA
    } else if s.contains("WEP") {
        SecurityType::WEP
    } else if s.is_empty() || s == "--" {
        SecurityType::Open
    } else {
        SecurityType::Unknown(security.to_string())
    }
}

/// Determine security type from iw scan flags
fn determine_security(has_wpa: bool, has_rsn: bool, has_wpa3: bool, has_privacy: bool) -> SecurityType {
    if has_wpa3 {
        SecurityType::WPA3Personal
    } else if has_rsn {
        SecurityType::WPA2Personal
    } else if has_wpa {
        SecurityType::WPA
    } else if has_privacy {
        SecurityType::WEP
    } else {
        SecurityType::Open
    }
}

/// Convert frequency (MHz) to WiFi channel number
fn freq_to_channel(freq_mhz: u32) -> u8 {
    match freq_mhz {
        // 2.4 GHz band (channels 1-14)
        2412 => 1,
        2417 => 2,
        2422 => 3,
        2427 => 4,
        2432 => 5,
        2437 => 6,
        2442 => 7,
        2447 => 8,
        2452 => 9,
        2457 => 10,
        2462 => 11,
        2467 => 12,
        2472 => 13,
        2484 => 14,
        // 5 GHz band (common channels)
        5180 => 36,
        5200 => 40,
        5220 => 44,
        5240 => 48,
        5260 => 52,
        5280 => 56,
        5300 => 60,
        5320 => 64,
        5500 => 100,
        5520 => 104,
        5540 => 108,
        5560 => 112,
        5580 => 116,
        5600 => 120,
        5620 => 124,
        5640 => 128,
        5660 => 132,
        5680 => 136,
        5700 => 140,
        5720 => 144,
        5745 => 149,
        5765 => 153,
        5785 => 157,
        5805 => 161,
        5825 => 165,
        // 6 GHz band (WiFi 6E) - simplified
        5955 => 1,   // 6 GHz channel 1
        6115 => 33,  // 6 GHz channel 33
        6275 => 65,  // 6 GHz channel 65
        // Fallback calculations
        f if f >= 5950 => ((f - 5950) / 5) as u8, // 6 GHz
        f if f >= 5000 => ((f - 5000) / 5) as u8, // 5 GHz
        f if f >= 2400 => ((f - 2407) / 5) as u8, // 2.4 GHz
        _ => 0,
    }
}
