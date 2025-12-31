//! WiFi Scanner Module
//!
//! Platform-abstracted WiFi scanning with conditional compilation.
//! - macOS: Uses airport command (CoreWLAN needs objc runtime crate)
//! - Linux: Uses iw command (nl80211 netlink too complex without crates)
//! - Windows: Raw FFI to wlanapi.dll (demonstrates FFI skills)

use std::fmt;

// Platform-specific implementations
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

/// Security protocol type for WiFi networks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityType {
    Open,
    WEP,
    WPA,
    WPA2Personal,
    WPA2Enterprise,
    WPA3Personal,
    WPA3Enterprise,
    Unknown(String), // Store unrecognized security string for debugging
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::WEP => write!(f, "WEP"),
            Self::WPA => write!(f, "WPA"),
            Self::WPA2Personal => write!(f, "WPA2"),
            Self::WPA2Enterprise => write!(f, "WPA2-Ent"),
            Self::WPA3Personal => write!(f, "WPA3"),
            Self::WPA3Enterprise => write!(f, "WPA3-Ent"),
            Self::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Information about a discovered WiFi network
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub ssid: String,
    pub bssid: Option<String>,      // MAC address of access point
    pub signal_dbm: i32,            // Signal strength in dBm (negative, -30 best, -90 worst)
    pub channel: u8,
    pub security: SecurityType,
}

impl NetworkInfo {
    /// Convert dBm to quality percentage (0-100) for display
    /// Uses standard conversion: quality = 2 * (dBm + 100), clamped to 0-100
    pub fn signal_quality(&self) -> u8 {
        let quality = 2 * (self.signal_dbm + 100);
        quality.clamp(0, 100) as u8
    }

    /// Get signal bar representation for TUI
    pub fn signal_bars(&self) -> &'static str {
        let quality = self.signal_quality();
        match quality {
            80..=100 => "████",
            60..=79 => "███░",
            40..=59 => "██░░",
            20..=39 => "█░░░",
            _ => "░░░░",
        }
    }
}

/// Scanner error types unified across platforms
#[derive(Debug)]
pub enum ScanError {
    /// WiFi hardware not found or disabled
    NoInterface(String),
    /// Permission denied for scanning
    PermissionDenied(String),
    /// Command execution failed (macOS/Linux)
    CommandFailed(String),
    /// Failed to parse scanner output
    ParseError(String),
    /// Windows API error (Windows only)
    #[cfg(target_os = "windows")]
    WindowsApi(u32, String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInterface(msg) => write!(f, "No WiFi interface: {}", msg),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
            #[cfg(target_os = "windows")]
            Self::WindowsApi(code, msg) => write!(f, "Windows API error {}: {}", code, msg),
        }
    }
}

impl std::error::Error for ScanError {}

/// Result type for scanner operations
pub type ScanResult<T> = Result<T, ScanError>;

/// Trait defining the WiFi scanner interface
/// Each platform implements this with OS-specific code
pub trait WiFiScanner: Send + Sync {
    /// Scan for nearby WiFi networks
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>>;

    /// Check if WiFi hardware is available
    fn is_available(&self) -> bool;

    /// Get the name of the WiFi interface being used
    fn interface_name(&self) -> Option<String>;
}

/// Create the appropriate scanner for the current platform
/// Returns boxed trait object for runtime polymorphism
pub fn create_scanner() -> Box<dyn WiFiScanner> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSScanner::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxScanner::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsScanner::new())
    }
}
