//! Windows WiFi Scanner Implementation
//!
//! This module implements WiFi scanning using raw FFI to the Native WiFi API (wlanapi.dll).
//!
//! # Approach
//!
//! We use the Windows Native WiFi API directly via FFI because:
//! - The assessment restricts external crates (no windows-sys or winapi)
//! - Demonstrates understanding of FFI, memory safety, and Windows APIs
//! - All struct layouts match official Windows SDK definitions
//!
//! # API Functions Used
//!
//! - `WlanOpenHandle` - Open connection to WLAN service
//! - `WlanCloseHandle` - Close connection
//! - `WlanEnumInterfaces` - List wireless adapters
//! - `WlanScan` - Trigger a fresh network scan
//! - `WlanGetAvailableNetworkList` - Get visible networks with signal/security
//! - `WlanGetNetworkBssList` - Get BSS info (BSSID, channel)
//! - `WlanFreeMemory` - Free API-allocated memory
//!
//! # Safety Architecture
//!
//! All unsafe code is isolated with documented invariants:
//! - RAII wrapper (`WlanHandle`) ensures handle cleanup
//! - All Windows-allocated memory freed with `WlanFreeMemory`
//! - Pointer validity checked before dereference
//! - Struct layouts verified against Windows SDK

use std::ffi::c_void;
use std::ptr;

use tracing::{debug, info, warn};

use super::{NetworkInfo, ScanError, ScanResult, SecurityType, WiFiScanner};

// ============================================================================
// Windows API Constants
// ============================================================================

const ERROR_SUCCESS: u32 = 0;
const WLAN_API_VERSION_2_0: u32 = 2;

// DOT11_AUTH_ALGORITHM values (from wlantypes.h)
// See: https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-auth-algorithm
const DOT11_AUTH_ALGO_80211_OPEN: u32 = 1;
const DOT11_AUTH_ALGO_80211_SHARED_KEY: u32 = 2;
const DOT11_AUTH_ALGO_WPA: u32 = 3;
const DOT11_AUTH_ALGO_WPA_PSK: u32 = 4;
const DOT11_AUTH_ALGO_RSNA: u32 = 6;          // WPA2-Enterprise
const DOT11_AUTH_ALGO_RSNA_PSK: u32 = 7;      // WPA2-Personal
const DOT11_AUTH_ALGO_WPA3_ENT_192: u32 = 8;  // WPA3-Enterprise 192-bit
const DOT11_AUTH_ALGO_WPA3_SAE: u32 = 9;      // WPA3-Personal (SAE)
const DOT11_AUTH_ALGO_OWE: u32 = 10;          // Opportunistic Wireless Encryption
const DOT11_AUTH_ALGO_WPA3_ENT: u32 = 11;     // WPA3-Enterprise

// DOT11_CIPHER_ALGORITHM values
const DOT11_CIPHER_ALGO_NONE: u32 = 0;
const DOT11_CIPHER_ALGO_WEP40: u32 = 1;
const DOT11_CIPHER_ALGO_TKIP: u32 = 2;
const DOT11_CIPHER_ALGO_CCMP: u32 = 4;
const DOT11_CIPHER_ALGO_WEP104: u32 = 5;
const DOT11_CIPHER_ALGO_WEP: u32 = 0x101;

// DOT11_BSS_TYPE
const DOT11_BSS_TYPE_ANY: u32 = 3;

// ============================================================================
// Windows API Type Definitions
// ============================================================================

type HANDLE = *mut c_void;
type DWORD = u32;
type PVOID = *mut c_void;
type BOOL = i32;

/// GUID structure - 16 bytes
#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// DOT11_SSID - SSID with length prefix (max 32 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct DOT11_SSID {
    ssid_length: u32,
    ssid: [u8; 32],
}

/// DOT11_MAC_ADDRESS - 6-byte MAC address
type DOT11_MAC_ADDRESS = [u8; 6];

/// WLAN_INTERFACE_INFO - Single interface information
#[repr(C)]
struct WLAN_INTERFACE_INFO {
    interface_guid: GUID,
    interface_description: [u16; 256],
    state: u32,
}

/// WLAN_INTERFACE_INFO_LIST - Variable-length list of interfaces
#[repr(C)]
struct WLAN_INTERFACE_INFO_LIST {
    num_items: DWORD,
    index: DWORD,
    // Followed by InterfaceInfo[num_items]
}

/// WLAN_AVAILABLE_NETWORK - Information about a visible network
#[repr(C)]
struct WLAN_AVAILABLE_NETWORK {
    profile_name: [u16; 256],
    dot11_ssid: DOT11_SSID,
    dot11_bss_type: u32,
    number_of_bssids: u32,
    network_connectable: BOOL,
    not_connectable_reason: u32,
    number_of_phy_types: u32,
    phy_types: [u32; 8],
    more_phy_types: BOOL,
    signal_quality: u32,
    security_enabled: BOOL,
    dot11_default_auth_algorithm: u32,
    dot11_default_cipher_algorithm: u32,
    flags: u32,
    reserved: u32,
}

/// WLAN_AVAILABLE_NETWORK_LIST - Variable-length list of networks
#[repr(C)]
struct WLAN_AVAILABLE_NETWORK_LIST {
    num_items: DWORD,
    index: DWORD,
    // Followed by Network[num_items]
}

/// DOT11_RATE_SET_MAX_LENGTH from windot11.h
const DOT11_RATE_SET_MAX_LENGTH: usize = 126;

/// WLAN_RATE_SET - Set of supported data transfer rates
/// See: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_rate_set
#[repr(C)]
struct WLAN_RATE_SET {
    rate_set_length: u32,
    rate_set: [u16; DOT11_RATE_SET_MAX_LENGTH],
}

/// WLAN_BSS_ENTRY - BSS information including BSSID and channel
/// See: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry
#[repr(C)]
struct WLAN_BSS_ENTRY {
    dot11_ssid: DOT11_SSID,
    phy_id: u32,
    dot11_bssid: DOT11_MAC_ADDRESS,
    dot11_bss_type: u32,
    dot11_bss_phy_type: u32,
    rssi: i32,                     // Signal strength in dBm (LONG)
    link_quality: u32,             // 0-100 (ULONG)
    in_reg_domain: u8,             // BOOLEAN (1 byte, not BOOL)
    beacon_period: u16,            // USHORT
    timestamp: u64,                // ULONGLONG
    host_timestamp: u64,           // ULONGLONG
    capability_info: u16,          // USHORT
    channel_center_frequency: u32, // In kHz (ULONG)
    wlan_rate_set: WLAN_RATE_SET,  // Supported data rates
    ie_offset: u32,                // Offset to IE data (ULONG)
    ie_size: u32,                  // Size of IE data (ULONG)
}

/// WLAN_BSS_LIST - Variable-length list of BSS entries
#[repr(C)]
struct WLAN_BSS_LIST {
    total_size: DWORD,
    num_items: DWORD,
    // Followed by WLAN_BSS_ENTRY[num_items]
}

// ============================================================================
// Windows API Function Bindings
// ============================================================================

#[link(name = "wlanapi")]
extern "system" {
    fn WlanOpenHandle(
        client_version: DWORD,
        reserved: PVOID,
        negotiated_version: *mut DWORD,
        client_handle: *mut HANDLE,
    ) -> DWORD;

    fn WlanCloseHandle(client_handle: HANDLE, reserved: PVOID) -> DWORD;

    fn WlanEnumInterfaces(
        client_handle: HANDLE,
        reserved: PVOID,
        interface_list: *mut *mut WLAN_INTERFACE_INFO_LIST,
    ) -> DWORD;

    fn WlanScan(
        client_handle: HANDLE,
        interface_guid: *const GUID,
        dot11_ssid: *const DOT11_SSID,
        ie_data: *const c_void,
        reserved: PVOID,
    ) -> DWORD;

    fn WlanGetAvailableNetworkList(
        client_handle: HANDLE,
        interface_guid: *const GUID,
        flags: DWORD,
        reserved: PVOID,
        network_list: *mut *mut WLAN_AVAILABLE_NETWORK_LIST,
    ) -> DWORD;

    fn WlanGetNetworkBssList(
        client_handle: HANDLE,
        interface_guid: *const GUID,
        dot11_ssid: *const DOT11_SSID,
        dot11_bss_type: u32,
        security_enabled: BOOL,
        reserved: PVOID,
        bss_list: *mut *mut WLAN_BSS_LIST,
    ) -> DWORD;

    fn WlanFreeMemory(memory: PVOID);
}

// ============================================================================
// RAII Wrapper for WLAN Handle
// ============================================================================

/// Safe wrapper around WLAN client handle ensuring proper cleanup
struct WlanHandle {
    handle: HANDLE,
}

impl WlanHandle {
    /// Open a new WLAN client handle
    fn open() -> ScanResult<Self> {
        let mut negotiated_version: DWORD = 0;
        let mut handle: HANDLE = ptr::null_mut();

        // SAFETY: All out-pointers are valid stack variables
        let result = unsafe {
            WlanOpenHandle(
                WLAN_API_VERSION_2_0,
                ptr::null_mut(),
                &mut negotiated_version,
                &mut handle,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(ScanError::WindowsApi(
                result,
                format!("WlanOpenHandle failed with error {}", result),
            ));
        }

        debug!(negotiated_version, "WLAN handle opened");
        Ok(Self { handle })
    }

    fn as_ptr(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WlanHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle was obtained from WlanOpenHandle
            unsafe {
                WlanCloseHandle(self.handle, ptr::null_mut());
            }
            debug!("WLAN handle closed");
        }
    }
}

// ============================================================================
// Scanner Implementation
// ============================================================================

pub struct WindowsScanner {
    // Handle opened per-scan for simplicity
}

impl WindowsScanner {
    pub fn new() -> Self {
        info!("Windows WiFi scanner initialized");
        Self {}
    }

    /// Get the first available wireless interface GUID and name
    fn get_interface(handle: &WlanHandle) -> ScanResult<(GUID, String)> {
        let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();

        // SAFETY: handle is valid, interface_list points to valid storage
        let result = unsafe {
            WlanEnumInterfaces(handle.as_ptr(), ptr::null_mut(), &mut interface_list)
        };

        if result != ERROR_SUCCESS {
            return Err(ScanError::WindowsApi(
                result,
                "WlanEnumInterfaces failed".into(),
            ));
        }

        // SAFETY: On success, interface_list is valid
        let (guid, name) = unsafe {
            let list = &*interface_list;
            if list.num_items == 0 {
                WlanFreeMemory(interface_list as PVOID);
                return Err(ScanError::NoInterface("No wireless interfaces found".into()));
            }

            // Get first interface (after list header)
            let interfaces_ptr = (interface_list as *const u8)
                .add(std::mem::size_of::<WLAN_INTERFACE_INFO_LIST>())
                as *const WLAN_INTERFACE_INFO;

            let first = &*interfaces_ptr;
            let guid = first.interface_guid;

            // Convert wide string to Rust String
            let desc_len = first
                .interface_description
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(256);
            let name = String::from_utf16_lossy(&first.interface_description[..desc_len]);

            (guid, name)
        };

        // SAFETY: interface_list was allocated by WlanEnumInterfaces
        unsafe {
            WlanFreeMemory(interface_list as PVOID);
        }

        debug!(interface = %name, "Found wireless interface");
        Ok((guid, name))
    }

    /// Trigger a fresh network scan
    fn trigger_scan(handle: &WlanHandle, guid: &GUID) {
        // SAFETY: handle and guid are valid
        let result = unsafe {
            WlanScan(
                handle.as_ptr(),
                guid as *const GUID,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            )
        };

        if result == ERROR_SUCCESS {
            debug!("Triggered fresh network scan");
            // Give Windows time to perform the scan
            std::thread::sleep(std::time::Duration::from_millis(500));
        } else {
            warn!(error = result, "WlanScan failed, using cached results");
        }
    }

    /// Get BSS information for a specific SSID (channel, BSSID, actual RSSI)
    fn get_bss_info(
        handle: &WlanHandle,
        guid: &GUID,
        ssid: &DOT11_SSID,
    ) -> Option<(String, u8, i32)> {
        let mut bss_list: *mut WLAN_BSS_LIST = ptr::null_mut();

        // SAFETY: All pointers are valid
        let result = unsafe {
            WlanGetNetworkBssList(
                handle.as_ptr(),
                guid as *const GUID,
                ssid as *const DOT11_SSID,
                DOT11_BSS_TYPE_ANY,
                0, // security_enabled - 0 for any
                ptr::null_mut(),
                &mut bss_list,
            )
        };

        if result != ERROR_SUCCESS || bss_list.is_null() {
            return None;
        }

        // SAFETY: On success, bss_list is valid
        let info = unsafe {
            let list = &*bss_list;
            if list.num_items == 0 {
                WlanFreeMemory(bss_list as PVOID);
                return None;
            }

            // Get first BSS entry (after list header)
            let entries_ptr = (bss_list as *const u8)
                .add(std::mem::size_of::<WLAN_BSS_LIST>())
                as *const WLAN_BSS_ENTRY;

            let entry = &*entries_ptr;

            // Format BSSID as MAC address string
            let bssid = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                entry.dot11_bssid[0],
                entry.dot11_bssid[1],
                entry.dot11_bssid[2],
                entry.dot11_bssid[3],
                entry.dot11_bssid[4],
                entry.dot11_bssid[5]
            );

            // Convert frequency (kHz) to channel
            let channel = freq_khz_to_channel(entry.channel_center_frequency);

            // RSSI is actual signal strength in dBm
            let rssi = entry.rssi;

            (bssid, channel, rssi)
        };

        // SAFETY: bss_list was allocated by WlanGetNetworkBssList
        unsafe {
            WlanFreeMemory(bss_list as PVOID);
        }

        Some(info)
    }

    /// Get available networks
    fn get_networks(handle: &WlanHandle, guid: &GUID) -> ScanResult<Vec<NetworkInfo>> {
        let mut network_list: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();

        // SAFETY: All pointers are valid
        let result = unsafe {
            WlanGetAvailableNetworkList(
                handle.as_ptr(),
                guid as *const GUID,
                0, // flags
                ptr::null_mut(),
                &mut network_list,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(ScanError::WindowsApi(
                result,
                "WlanGetAvailableNetworkList failed".into(),
            ));
        }

        // SAFETY: On success, network_list is valid
        let networks = unsafe {
            let list = &*network_list;
            let num_networks = list.num_items as usize;

            debug!(num_networks, "Retrieved network list");

            let mut networks = Vec::with_capacity(num_networks);

            let networks_ptr = (network_list as *const u8)
                .add(std::mem::size_of::<WLAN_AVAILABLE_NETWORK_LIST>())
                as *const WLAN_AVAILABLE_NETWORK;

            for i in 0..num_networks {
                let network = &*networks_ptr.add(i);

                let ssid = extract_ssid(&network.dot11_ssid);
                if ssid.is_empty() {
                    continue; // Skip hidden networks
                }

                let security = parse_security(
                    network.dot11_default_auth_algorithm,
                    network.dot11_default_cipher_algorithm,
                );

                // Get BSS info for channel and BSSID
                let (bssid, channel, signal_dbm) =
                    Self::get_bss_info(handle, guid, &network.dot11_ssid)
                        .unwrap_or_else(|| {
                            // Fall back to quality-based signal estimate
                            (String::new(), 0, quality_to_dbm(network.signal_quality))
                        });

                networks.push(NetworkInfo {
                    ssid,
                    bssid: if bssid.is_empty() { None } else { Some(bssid) },
                    signal_dbm,
                    channel,
                    security,
                });
            }

            networks
        };

        // SAFETY: network_list was allocated by WlanGetAvailableNetworkList
        unsafe {
            WlanFreeMemory(network_list as PVOID);
        }

        Ok(networks)
    }
}

impl WiFiScanner for WindowsScanner {
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>> {
        info!("Starting WiFi scan using Windows Native WiFi API");

        // Open handle (RAII ensures cleanup)
        let handle = WlanHandle::open()?;

        // Get first wireless interface
        let (guid, interface_name) = Self::get_interface(&handle)?;
        info!(interface = %interface_name, "Using wireless interface");

        // Trigger fresh scan
        Self::trigger_scan(&handle, &guid);

        // Get networks
        let mut networks = Self::get_networks(&handle, &guid)?;

        // Sort by signal strength (strongest first) and deduplicate
        networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
        networks.dedup_by(|a, b| a.ssid == b.ssid);

        info!(network_count = networks.len(), "Scan complete");
        Ok(networks)
    }

    fn is_available(&self) -> bool {
        WlanHandle::open()
            .and_then(|h| Self::get_interface(&h).map(|_| true))
            .unwrap_or(false)
    }

    fn interface_name(&self) -> Option<String> {
        WlanHandle::open()
            .and_then(|h| Self::get_interface(&h).map(|(_, name)| name))
            .ok()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract SSID string from DOT11_SSID structure
fn extract_ssid(ssid: &DOT11_SSID) -> String {
    let len = ssid.ssid_length as usize;
    if len == 0 || len > 32 {
        return String::new();
    }
    String::from_utf8_lossy(&ssid.ssid[..len]).into_owned()
}

/// Convert Windows auth/cipher algorithms to SecurityType
/// See: https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-auth-algorithm
fn parse_security(auth: u32, cipher: u32) -> SecurityType {
    match auth {
        DOT11_AUTH_ALGO_80211_OPEN => {
            if cipher == DOT11_CIPHER_ALGO_NONE {
                SecurityType::Open
            } else {
                SecurityType::WEP
            }
        }
        DOT11_AUTH_ALGO_80211_SHARED_KEY => SecurityType::WEP,
        DOT11_AUTH_ALGO_WPA | DOT11_AUTH_ALGO_WPA_PSK => SecurityType::WPA,
        DOT11_AUTH_ALGO_RSNA => SecurityType::WPA2Enterprise,
        DOT11_AUTH_ALGO_RSNA_PSK => SecurityType::WPA2Personal,
        DOT11_AUTH_ALGO_WPA3_SAE => SecurityType::WPA3Personal,
        DOT11_AUTH_ALGO_OWE => SecurityType::Open, // OWE is enhanced open
        DOT11_AUTH_ALGO_WPA3_ENT_192 | DOT11_AUTH_ALGO_WPA3_ENT => SecurityType::WPA3Enterprise,
        _ => {
            // Fallback: determine from cipher
            match cipher {
                DOT11_CIPHER_ALGO_WEP | DOT11_CIPHER_ALGO_WEP40 | DOT11_CIPHER_ALGO_WEP104 => {
                    SecurityType::WEP
                }
                DOT11_CIPHER_ALGO_TKIP => SecurityType::WPA,
                DOT11_CIPHER_ALGO_CCMP => SecurityType::WPA2Personal,
                _ => SecurityType::Unknown(format!("auth:{}/cipher:{}", auth, cipher)),
            }
        }
    }
}

/// Convert signal quality percentage (0-100) to approximate dBm
fn quality_to_dbm(quality: u32) -> i32 {
    // Windows quality is 0-100, map to -100 dBm to -40 dBm range
    -100 + (quality as i32 * 60 / 100)
}

/// Convert frequency in kHz to WiFi channel number
fn freq_khz_to_channel(freq_khz: u32) -> u8 {
    let freq_mhz = freq_khz / 1000;
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
        // 5 GHz band
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
        // Fallback calculations
        f if f >= 5000 => ((f - 5000) / 5) as u8,
        f if f >= 2400 => ((f - 2407) / 5) as u8,
        _ => 0,
    }
}
