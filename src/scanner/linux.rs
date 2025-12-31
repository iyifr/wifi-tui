//! Linux WiFi Scanner Implementation
//!
//! Uses the `iw` command-line utility for scanning.
//! Alternative nl80211 netlink interface would require massive manual FFI.
//!
//! Why command instead of nl80211:
//! - nl80211 requires complex netlink socket setup and message parsing
//! - Would need thousands of lines of unsafe FFI code
//! - iw is the standard Linux wireless tool, pre-installed on most distros
//! - May require sudo or CAP_NET_ADMIN capability for scanning

use std::process::Command;
use tracing::{debug, info, instrument, warn};

use super::{NetworkInfo, ScanError, ScanResult, SecurityType, WiFiScanner};

pub struct LinuxScanner {
    interface: Option<String>,
}

impl LinuxScanner {
    pub fn new() -> Self {
        let interface = Self::detect_interface();
        Self { interface }
    }

    /// Detect wireless interface using `iw dev`
    fn detect_interface() -> Option<String> {
        let output = Command::new("iw").arg("dev").output().ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output looking for "Interface" lines
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(iface) = trimmed.strip_prefix("Interface ") {
                return Some(iface.trim().to_string());
            }
        }
        None
    }

    /// Convert frequency (MHz) to channel number
    fn freq_to_channel(freq_mhz: u32) -> u8 {
        match freq_mhz {
            // 2.4 GHz band
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
            // Fallback: calculate for 5GHz
            f if f >= 5000 => ((f - 5000) / 5) as u8,
            // Fallback: calculate for 2.4GHz
            f if f >= 2400 => ((f - 2407) / 5) as u8,
            _ => 0,
        }
    }

    /// Parse security from capability/IE information
    fn parse_security(capabilities: &str, has_wpa: bool, has_rsn: bool, has_wpa3: bool) -> SecurityType {
        if has_wpa3 {
            SecurityType::WPA3Personal
        } else if has_rsn {
            // RSN = WPA2
            if capabilities.contains("Enterprise") {
                SecurityType::WPA2Enterprise
            } else {
                SecurityType::WPA2Personal
            }
        } else if has_wpa {
            SecurityType::WPA
        } else if capabilities.contains("Privacy") {
            SecurityType::WEP
        } else {
            SecurityType::Open
        }
    }

    /// Parse iw scan output into NetworkInfo structs
    /// Format: BSS blocks separated by "BSS xx:xx:xx:xx:xx:xx"
    fn parse_scan_output(output: &str) -> Vec<NetworkInfo> {
        let mut networks = Vec::new();
        let mut current_bssid: Option<String> = None;
        let mut current_ssid: Option<String> = None;
        let mut current_signal: Option<i32> = None;
        let mut current_freq: Option<u32> = None;
        let mut has_wpa = false;
        let mut has_rsn = false;
        let mut has_wpa3 = false;
        let mut capabilities = String::new();

        for line in output.lines() {
            let trimmed = line.trim();

            // New BSS block starts
            if trimmed.starts_with("BSS ") {
                // Save previous network if complete
                if let (Some(bssid), Some(ssid), Some(signal), Some(freq)) =
                    (&current_bssid, &current_ssid, current_signal, current_freq)
                {
                    let security = Self::parse_security(&capabilities, has_wpa, has_rsn, has_wpa3);
                    networks.push(NetworkInfo {
                        ssid: ssid.clone(),
                        bssid: Some(bssid.clone()),
                        signal_dbm: signal,
                        channel: Self::freq_to_channel(freq),
                        security,
                    });
                }

                // Reset for new network
                current_bssid = trimmed
                    .strip_prefix("BSS ")
                    .and_then(|s| s.split('(').next())
                    .map(|s| s.trim().to_string());
                current_ssid = None;
                current_signal = None;
                current_freq = None;
                has_wpa = false;
                has_rsn = false;
                has_wpa3 = false;
                capabilities.clear();
            } else if let Some(ssid) = trimmed.strip_prefix("SSID: ") {
                current_ssid = Some(ssid.to_string());
            } else if let Some(signal) = trimmed.strip_prefix("signal: ") {
                // Format: "-XX.XX dBm"
                current_signal = signal
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f32>().ok())
                    .map(|f| f as i32);
            } else if let Some(freq) = trimmed.strip_prefix("freq: ") {
                current_freq = freq.parse().ok();
            } else if trimmed.starts_with("WPA:") {
                has_wpa = true;
            } else if trimmed.starts_with("RSN:") {
                has_rsn = true;
            } else if trimmed.contains("SAE") || trimmed.contains("WPA3") {
                has_wpa3 = true;
            } else if let Some(cap) = trimmed.strip_prefix("capability: ") {
                capabilities = cap.to_string();
            }
        }

        // Don't forget the last network
        if let (Some(bssid), Some(ssid), Some(signal), Some(freq)) =
            (&current_bssid, &current_ssid, current_signal, current_freq)
        {
            let security = Self::parse_security(&capabilities, has_wpa, has_rsn, has_wpa3);
            networks.push(NetworkInfo {
                ssid: ssid.clone(),
                bssid: Some(bssid.clone()),
                signal_dbm: signal,
                channel: Self::freq_to_channel(freq),
                security,
            });
        }

        networks
    }
}

impl WiFiScanner for LinuxScanner {
    #[instrument(skip(self), name = "linux_scan")]
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>> {
        let interface = self.interface.as_ref().ok_or_else(|| {
            ScanError::NoInterface("No wireless interface detected. Is WiFi enabled?".into())
        })?;

        info!(interface = %interface, "Starting WiFi scan using iw");

        // Execute: iw dev <interface> scan
        let output = Command::new("iw")
            .args(["dev", interface, "scan"])
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ScanError::CommandFailed("iw command not found. Install iw package.".into())
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    ScanError::PermissionDenied(
                        "Permission denied. Try running with sudo or add CAP_NET_ADMIN.".into(),
                    )
                } else {
                    ScanError::CommandFailed(format!("Failed to execute iw: {}", e))
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check for common permission error
            if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
                return Err(ScanError::PermissionDenied(
                    "Scan requires elevated privileges. Try: sudo wifi-tui".into(),
                ));
            }
            return Err(ScanError::CommandFailed(format!("iw scan failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!(output_len = stdout.len(), "Parsing iw scan output");

        let networks = Self::parse_scan_output(&stdout);
        info!(network_count = networks.len(), "Scan complete");

        Ok(networks)
    }

    fn is_available(&self) -> bool {
        // Check if iw exists and interface is detected
        Command::new("which").arg("iw").output().map(|o| o.status.success()).unwrap_or(false)
            && self.interface.is_some()
    }

    fn interface_name(&self) -> Option<String> {
        self.interface.clone()
    }
}
