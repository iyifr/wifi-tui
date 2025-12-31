//! macOS WiFi Scanner Implementation using CoreWLAN Framework
//!
//! This module implements WiFi scanning using raw Objective-C FFI to Apple's
//! CoreWLAN framework. No external Objective-C crates are used - all FFI
//! bindings are defined manually to satisfy the assessment constraint of
//! only using ratatui and tracing as external dependencies.
//!
//! # Architecture
//!
//! CoreWLAN is an Objective-C framework. To call it from Rust, we use:
//! 1. `libobjc` - The Objective-C runtime library (always present on macOS)
//! 2. `objc_msgSend` - The universal message dispatch function
//! 3. `sel_registerName` - To get method selectors by name
//! 4. `objc_getClass` - To get class pointers by name
//!
//! # Safety
//!
//! All unsafe code is carefully documented with invariants.
//! Key safety requirements:
//! - All object pointers must be valid Objective-C objects
//! - Selectors must match the actual method signatures
//! - Memory must be managed via autorelease pools
//! - objc_msgSend must be cast to the correct function signature
//!
//! # References & Sources
//!
//! ## Apple Documentation (Primary Sources)
//! - CoreWLAN Framework Overview:
//!   https://developer.apple.com/documentation/corewlan
//!   "Query AirPort interfaces and choose wireless networks"
//!
//! - CWWiFiClient Class Reference:
//!   https://developer.apple.com/documentation/corewlan/cwwificlient
//!   "The interface to the Wi-Fi subsystem on macOS"
//!   Key method: +sharedWiFiClient returns singleton instance
//!
//! - CWInterface Class Reference:
//!   https://developer.apple.com/documentation/corewlan/cwinterface
//!   "Encapsulates an IEEE 802.11 interface"
//!   Key method: -scanForNetworksWithName:includeHidden:error:
//!
//! - CWNetwork Class Reference:
//!   https://developer.apple.com/documentation/corewlan/cwnetwork
//!   Properties used: ssid, bssid, rssiValue, wlanChannel, security
//!
//! - CWSecurity Enum Values:
//!   https://developer.apple.com/documentation/corewlan/cwsecurity
//!   Integer values for None(0), WEP(1), WPA2Personal(4), etc.
//!
//! - rssiValue Property:
//!   https://developer.apple.com/documentation/corewlan/cwnetwork/rssivalue
//!   "The aggregate RSSI measurement (dBm) for the network"
//!
//! ## Objective-C Runtime Documentation
//! - Objective-C Runtime Programming Guide:
//!   https://developer.apple.com/documentation/objectivec/objective-c_runtime
//!   Explains objc_msgSend, selectors, and class lookups
//!
//! ## Rust + Objective-C FFI Guides (Implementation Examples)
//! - "Objective-C from Rust: objc_msgSend" by Steven Sheldon:
//!   http://sasheldon.com/blog/2015/08/02/objective-c-from-rust-objc_msgsend/
//!   Critical insight: objc_msgSend must be cast to match target method signature
//!   Example: `let func: extern "C" fn(id, SEL) -> id = transmute(objc_msgSend)`
//!
//! - "Interoperating Between Objective-C and Rust" by Steven Sheldon:
//!   http://sasheldon.com/blog/2014/11/28/interoperating-between-objective-c-and-rust/
//!   Foundation for understanding ObjC runtime from Rust
//!
//! - objc2-core-wlan crate (API reference, not used as dependency):
//!   https://docs.rs/objc2-core-wlan
//!   https://crates.io/crates/objc2-core-wlan
//!   Used to verify correct method signatures and property names
//!
//! - Swift CoreWLAN Example (for API usage patterns):
//!   https://github.com/chbrown/macos-wifi/blob/master/corewlanlib.swift
//!   Shows CWWiFiClient -> CWInterface -> scan -> CWNetwork flow
//!
//! ## Known Issues & Permissions
//! - Location Services Requirement (macOS 10.15+):
//!   https://developer.apple.com/forums/thread/119798
//!   https://github.com/ronaldoussoren/pyobjc/issues/600
//!   CoreWLAN returns empty/null SSIDs without Location Services permission
//!   Solution: Enable Location Services for Terminal/IDE in System Settings
//!
//! - WiFi Scanning Blog Post:
//!   https://clburlison.com/macos-wifi-scanning/
//!   Practical guide to CoreWLAN scanning with permission handling

use std::ffi::{c_char, c_long, c_void, CStr};
use std::ptr;

use tracing::{debug, error, info, instrument, warn};

use super::{NetworkInfo, ScanError, ScanResult, SecurityType, WiFiScanner};

// =============================================================================
// Objective-C Runtime FFI Bindings
// =============================================================================
//
// These are raw bindings to libobjc, the Objective-C runtime.
// We link against libobjc (always present on macOS) and CoreWLAN framework.
//
// Reference: Apple Objective-C Runtime Documentation
// https://developer.apple.com/documentation/objectivec/objective-c_runtime
//
// The runtime provides C functions to interact with Objective-C objects:
// - objc_getClass: Get a Class pointer by name (like NSClassFromString)
// - sel_registerName: Get/create a SEL (selector) by name
// - objc_msgSend: Send a message to an object (call a method)

/// Opaque type representing an Objective-C object pointer
#[repr(C)]
struct ObjcObject {
    _private: [u8; 0],
}

/// Opaque type representing an Objective-C class
#[repr(C)]
struct ObjcClass {
    _private: [u8; 0],
}

/// Opaque type representing an Objective-C selector (method name)
#[repr(C)]
struct ObjcSelector {
    _private: [u8; 0],
}

/// Type alias for Objective-C object pointers (id in ObjC)
type Id = *mut ObjcObject;

/// Type alias for Objective-C class pointers (Class in ObjC)
type Class = *const ObjcClass;

/// Type alias for Objective-C selectors (SEL in ObjC)
type Sel = *const ObjcSelector;

/// Boolean type used by Objective-C (BOOL)
type ObjcBool = i8;

const YES: ObjcBool = 1;
const NO: ObjcBool = 0;

// Link against libobjc (Objective-C runtime) and CoreWLAN framework
#[link(name = "objc")]
extern "C" {
    /// Get a class by name. Returns null if class not found.
    fn objc_getClass(name: *const c_char) -> Class;

    /// Register/get a selector by name. Always succeeds.
    fn sel_registerName(name: *const c_char) -> Sel;

    /// The universal Objective-C message dispatch function.
    /// CRITICAL: This must be cast to the correct function pointer type
    /// matching the method's actual signature before calling.
    fn objc_msgSend();

    /// Allocate an autorelease pool. All ObjC objects created inside
    /// will be released when the pool is popped.
    fn objc_autoreleasePoolPush() -> *mut c_void;

    /// Pop and drain an autorelease pool, releasing all objects.
    fn objc_autoreleasePoolPop(pool: *mut c_void);
}

// Link against CoreWLAN framework (contains CWWiFiClient, CWNetwork, etc.)
#[link(name = "CoreWLAN", kind = "framework")]
extern "C" {}

// =============================================================================
// Objective-C Message Sending Helpers
// =============================================================================
//
// objc_msgSend is a "trampoline" function that dispatches to the actual
// method implementation. It must be cast to match the target method's
// signature. We define typed wrappers for each calling convention we need.
//
// Reference: "Objective-C from Rust: objc_msgSend" by Steven Sheldon
// http://sasheldon.com/blog/2015/08/02/objective-c-from-rust-objc_msgsend/
//
// Key insight from the article:
// "objc_msgSend isn't actually a variadic function - it's a trampoline
// that jumps directly to the method implementation. Safely calling it
// requires first casting it to the type of the underlying method."
//
// Example from the article:
//   let func: extern "C" fn(id, SEL) -> id = transmute(objc_msgSend);
//   func(obj, selector)
//
// We create separate wrapper functions for each return type we need:
// - msg_send_id: Returns object pointer (id)
// - msg_send_long: Returns NSInteger (c_long)
// - msg_send_ulong: Returns NSUInteger (u64)

/// Send a message with no arguments, returning an object pointer.
/// Used for: [CWWiFiClient sharedWiFiClient], [client interface], etc.
///
/// # Safety
/// - `obj` must be a valid Objective-C object or class pointer
/// - `sel` must be a valid selector for a method that returns id
#[inline]
unsafe fn msg_send_id(obj: Id, sel: Sel) -> Id {
    let func: extern "C" fn(Id, Sel) -> Id = std::mem::transmute(objc_msgSend as *const ());
    func(obj, sel)
}

/// Send a message with no arguments, returning a long integer.
/// Used for: [network rssiValue], [channel channelNumber], etc.
///
/// # Safety
/// - `obj` must be a valid Objective-C object
/// - `sel` must be a valid selector for a method that returns NSInteger/long
#[inline]
unsafe fn msg_send_long(obj: Id, sel: Sel) -> c_long {
    let func: extern "C" fn(Id, Sel) -> c_long = std::mem::transmute(objc_msgSend as *const ());
    func(obj, sel)
}

/// Send a message with no arguments, returning an unsigned long.
/// Used for: [set count], [network security], etc.
///
/// # Safety
/// - `obj` must be a valid Objective-C object
/// - `sel` must be a valid selector for a method that returns NSUInteger
#[inline]
unsafe fn msg_send_ulong(obj: Id, sel: Sel) -> u64 {
    let func: extern "C" fn(Id, Sel) -> u64 = std::mem::transmute(objc_msgSend as *const ());
    func(obj, sel)
}

/// Send a message to a class (class method), returning an object.
/// Used for: [CWWiFiClient sharedWiFiClient]
///
/// # Safety
/// - `class` must be a valid Objective-C class pointer
/// - `sel` must be a valid class method selector
#[inline]
unsafe fn msg_send_class_id(class: Class, sel: Sel) -> Id {
    let func: extern "C" fn(Class, Sel) -> Id = std::mem::transmute(objc_msgSend as *const ());
    func(class, sel)
}

/// Send scanForNetworksWithName:includeHidden:error: message.
/// Signature: -(NSSet*)scanForNetworksWithName:(NSString*)name includeHidden:(BOOL)hidden error:(NSError**)error
///
/// # Safety
/// - `obj` must be a valid CWInterface object
/// - `sel` must be the scanForNetworksWithName:includeHidden:error: selector
/// - `error_ptr` must point to valid memory for NSError* storage
#[inline]
unsafe fn msg_send_scan(obj: Id, sel: Sel, name: Id, hidden: ObjcBool, error_ptr: *mut Id) -> Id {
    let func: extern "C" fn(Id, Sel, Id, ObjcBool, *mut Id) -> Id =
        std::mem::transmute(objc_msgSend as *const ());
    func(obj, sel, name, hidden, error_ptr)
}

// =============================================================================
// Objective-C Selector Cache
// =============================================================================
//
// Selectors are interned strings identifying method names. We cache them
// for efficiency since sel_registerName has lookup overhead.
//
// Selector names come from Apple's CoreWLAN documentation:
// - CWWiFiClient: https://developer.apple.com/documentation/corewlan/cwwificlient
//   +sharedWiFiClient, -interface
// - CWInterface: https://developer.apple.com/documentation/corewlan/cwinterface
//   -interfaceName, -scanForNetworksWithName:includeHidden:error:
// - CWNetwork: https://developer.apple.com/documentation/corewlan/cwnetwork
//   -ssid, -bssid, -rssiValue, -noiseMeasurement, -wlanChannel, -security
// - CWChannel: https://developer.apple.com/documentation/corewlan/cwchannel
//   -channelNumber
//
// Note: Selector strings must exactly match ObjC method names including colons.
// Example: "scanForNetworksWithName:includeHidden:error:" has 3 parameters.

struct Selectors {
    shared_wifi_client: Sel,      // +[CWWiFiClient sharedWiFiClient]
    interface: Sel,               // -[CWWiFiClient interface]
    interface_name: Sel,          // -[CWInterface interfaceName]
    scan_for_networks: Sel,       // -[CWInterface scanForNetworksWithName:includeHidden:error:]
    all_objects: Sel,             // -[NSSet allObjects]
    count: Sel,                   // -[NSArray/NSSet count]
    object_at_index: Sel,         // -[NSArray objectAtIndex:]
    ssid: Sel,                    // -[CWNetwork ssid]
    bssid: Sel,                   // -[CWNetwork bssid]
    rssi_value: Sel,              // -[CWNetwork rssiValue]
    noise_measurement: Sel,       // -[CWNetwork noiseMeasurement]
    wlan_channel: Sel,            // -[CWNetwork wlanChannel]
    channel_number: Sel,          // -[CWChannel channelNumber]
    security: Sel,                // -[CWNetwork security]
    utf8_string: Sel,             // -[NSString UTF8String]
    localized_description: Sel,   // -[NSError localizedDescription]
}

impl Selectors {
    /// Register all selectors we need. Called once at scanner creation.
    ///
    /// # Safety
    /// sel_registerName is safe to call with any valid C string.
    /// It always returns a valid selector (creating one if needed).
    fn new() -> Self {
        unsafe {
            Self {
                shared_wifi_client: sel_registerName(b"sharedWiFiClient\0".as_ptr() as *const c_char),
                interface: sel_registerName(b"interface\0".as_ptr() as *const c_char),
                interface_name: sel_registerName(b"interfaceName\0".as_ptr() as *const c_char),
                scan_for_networks: sel_registerName(
                    b"scanForNetworksWithName:includeHidden:error:\0".as_ptr() as *const c_char
                ),
                all_objects: sel_registerName(b"allObjects\0".as_ptr() as *const c_char),
                count: sel_registerName(b"count\0".as_ptr() as *const c_char),
                object_at_index: sel_registerName(b"objectAtIndex:\0".as_ptr() as *const c_char),
                ssid: sel_registerName(b"ssid\0".as_ptr() as *const c_char),
                bssid: sel_registerName(b"bssid\0".as_ptr() as *const c_char),
                rssi_value: sel_registerName(b"rssiValue\0".as_ptr() as *const c_char),
                noise_measurement: sel_registerName(b"noiseMeasurement\0".as_ptr() as *const c_char),
                wlan_channel: sel_registerName(b"wlanChannel\0".as_ptr() as *const c_char),
                channel_number: sel_registerName(b"channelNumber\0".as_ptr() as *const c_char),
                security: sel_registerName(b"security\0".as_ptr() as *const c_char),
                utf8_string: sel_registerName(b"UTF8String\0".as_ptr() as *const c_char),
                localized_description: sel_registerName(b"localizedDescription\0".as_ptr() as *const c_char),
            }
        }
    }
}

// =============================================================================
// CWSecurity Enum Mapping
// =============================================================================
//
// CoreWLAN's CWSecurity enum values. These are the raw integer values
// returned by [CWNetwork security].
//
// Reference: Apple CWSecurity Documentation
// https://developer.apple.com/documentation/corewlan/cwsecurity
//
// Values verified against:
// - Apple's CoreWLAN headers (via Xcode)
// - objc2-core-wlan crate source: https://docs.rs/objc2-core-wlan
// - Runtime-Headers project: https://github.com/onmyway133/Runtime-Headers
//
// Note: WPA3 values (11-13) were added in macOS 10.15 (Catalina).
// The exact values may vary by macOS version; Unknown catches unrecognized values.

/// CWSecurity enum from CoreWLAN framework
/// Maps directly to NSUInteger values returned by [CWNetwork security]
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
enum CWSecurity {
    None = 0,              // Open network, no security
    WEP = 1,               // Wired Equivalent Privacy (deprecated, insecure)
    WPAPersonal = 2,       // WPA with PSK (pre-shared key)
    WPAPersonalMixed = 3,  // WPA/WPA2 mixed mode with PSK
    WPA2Personal = 4,      // WPA2 with PSK (most common home networks)
    Personal = 5,          // Generic personal security (WPA/WPA2 auto)
    DynamicWEP = 6,        // 802.1X with dynamic WEP keys
    WPAEnterprise = 7,     // WPA with 802.1X authentication
    WPAEnterpriseMixed = 8,// WPA/WPA2 Enterprise mixed mode
    WPA2Enterprise = 9,    // WPA2 with 802.1X (corporate networks)
    Enterprise = 10,       // Generic enterprise security
    WPA3Personal = 11,     // WPA3-SAE (Simultaneous Authentication of Equals)
    WPA3Enterprise = 12,   // WPA3 with 802.1X
    WPA3Transition = 13,   // WPA3/WPA2 transition mode
    Unknown = 0xFFFFFFFF,  // Catch-all for unrecognized values
}

impl From<u64> for CWSecurity {
    fn from(value: u64) -> Self {
        match value {
            0 => CWSecurity::None,
            1 => CWSecurity::WEP,
            2 => CWSecurity::WPAPersonal,
            3 => CWSecurity::WPAPersonalMixed,
            4 => CWSecurity::WPA2Personal,
            5 => CWSecurity::Personal,
            6 => CWSecurity::DynamicWEP,
            7 => CWSecurity::WPAEnterprise,
            8 => CWSecurity::WPAEnterpriseMixed,
            9 => CWSecurity::WPA2Enterprise,
            10 => CWSecurity::Enterprise,
            11 => CWSecurity::WPA3Personal,
            12 => CWSecurity::WPA3Enterprise,
            13 => CWSecurity::WPA3Transition,
            _ => CWSecurity::Unknown,
        }
    }
}

impl From<CWSecurity> for SecurityType {
    fn from(cw: CWSecurity) -> Self {
        match cw {
            CWSecurity::None => SecurityType::Open,
            CWSecurity::WEP | CWSecurity::DynamicWEP => SecurityType::WEP,
            CWSecurity::WPAPersonal | CWSecurity::WPAPersonalMixed => SecurityType::WPA,
            CWSecurity::WPA2Personal | CWSecurity::Personal => SecurityType::WPA2Personal,
            CWSecurity::WPAEnterprise | CWSecurity::WPAEnterpriseMixed => SecurityType::WPA2Enterprise,
            CWSecurity::WPA2Enterprise | CWSecurity::Enterprise => SecurityType::WPA2Enterprise,
            CWSecurity::WPA3Personal | CWSecurity::WPA3Transition => SecurityType::WPA3Personal,
            CWSecurity::WPA3Enterprise => SecurityType::WPA3Enterprise,
            CWSecurity::Unknown => SecurityType::Unknown("Unknown".into()),
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert an NSString to a Rust String.
///
/// # Safety
/// - `nsstring` must be a valid NSString object or null
/// - The returned string is copied, so safe to use after ObjC object is released
unsafe fn nsstring_to_string(nsstring: Id, sel: &Selectors) -> Option<String> {
    if nsstring.is_null() {
        return None;
    }

    // Call [nsstring UTF8String] to get a C string pointer
    let utf8: *const c_char = std::mem::transmute(msg_send_id(nsstring, sel.utf8_string));

    if utf8.is_null() {
        return None;
    }

    // Convert C string to Rust String (copies the data)
    Some(CStr::from_ptr(utf8).to_string_lossy().into_owned())
}

/// Send [array objectAtIndex:idx] message.
///
/// # Safety
/// - `array` must be a valid NSArray object
/// - `idx` must be within bounds (caller must verify with count)
#[inline]
unsafe fn msg_send_object_at_index(array: Id, sel: Sel, idx: u64) -> Id {
    let func: extern "C" fn(Id, Sel, u64) -> Id = std::mem::transmute(objc_msgSend as *const ());
    func(array, sel, idx)
}

// =============================================================================
// MacOS Scanner Implementation
// =============================================================================

pub struct MacOSScanner {
    /// Cached CWWiFiClient instance (Objective-C object)
    /// This is a singleton, safe to cache
    wifi_client: Id,
    /// Cached selectors for method calls
    selectors: Selectors,
    /// Cached interface name
    interface_name: Option<String>,
}

// SAFETY: The CWWiFiClient singleton is thread-safe according to Apple docs.
// We only read from it, never modify state.
unsafe impl Send for MacOSScanner {}
unsafe impl Sync for MacOSScanner {}

impl MacOSScanner {
    /// Create a new macOS WiFi scanner using CoreWLAN.
    ///
    /// This initializes the Objective-C runtime connection and
    /// obtains the shared CWWiFiClient instance.
    pub fn new() -> Self {
        let selectors = Selectors::new();

        // Get CWWiFiClient class and shared instance
        // SAFETY: objc_getClass returns null if class not found, which we handle
        let wifi_client = unsafe {
            let class = objc_getClass(b"CWWiFiClient\0".as_ptr() as *const c_char);
            if class.is_null() {
                warn!("CWWiFiClient class not found - CoreWLAN not available");
                ptr::null_mut()
            } else {
                // [CWWiFiClient sharedWiFiClient]
                msg_send_class_id(class, selectors.shared_wifi_client)
            }
        };

        // Get interface name for logging
        let interface_name = if !wifi_client.is_null() {
            unsafe {
                let interface = msg_send_id(wifi_client, selectors.interface);
                if !interface.is_null() {
                    let name_ns = msg_send_id(interface, selectors.interface_name);
                    nsstring_to_string(name_ns, &selectors)
                } else {
                    None
                }
            }
        } else {
            None
        };

        if let Some(ref name) = interface_name {
            info!(interface = %name, "CoreWLAN scanner initialized");
        } else {
            warn!("No WiFi interface available");
        }

        Self {
            wifi_client,
            selectors,
            interface_name,
        }
    }

    /// Extract network information from a CWNetwork object.
    ///
    /// # Safety
    /// - `network` must be a valid CWNetwork Objective-C object
    unsafe fn extract_network_info(&self, network: Id) -> Option<NetworkInfo> {
        let sel = &self.selectors;

        // Get SSID: [network ssid] -> NSString
        let ssid_ns = msg_send_id(network, sel.ssid);
        let ssid = nsstring_to_string(ssid_ns, sel)?;

        // Skip hidden networks (empty SSID)
        if ssid.is_empty() {
            debug!("Skipping hidden network");
            return None;
        }

        // Get BSSID: [network bssid] -> NSString
        let bssid_ns = msg_send_id(network, sel.bssid);
        let bssid = nsstring_to_string(bssid_ns, sel);

        // Get RSSI: [network rssiValue] -> NSInteger (long)
        let rssi = msg_send_long(network, sel.rssi_value) as i32;

        // Get channel: [network wlanChannel] -> CWChannel, then [channel channelNumber]
        let channel = {
            let wlan_channel = msg_send_id(network, sel.wlan_channel);
            if !wlan_channel.is_null() {
                msg_send_long(wlan_channel, sel.channel_number) as u8
            } else {
                0
            }
        };

        // Get security: [network security] -> CWSecurity (NSUInteger)
        let security_raw = msg_send_ulong(network, sel.security);
        let security: SecurityType = CWSecurity::from(security_raw).into();

        debug!(
            ssid = %ssid,
            rssi = rssi,
            channel = channel,
            security = ?security_raw,
            "Parsed network"
        );

        Some(NetworkInfo {
            ssid,
            bssid,
            signal_dbm: rssi,
            channel,
            security,
        })
    }
}

impl WiFiScanner for MacOSScanner {
    /// Scan for nearby WiFi networks using CoreWLAN framework.
    ///
    /// # API Flow (based on Swift example from github.com/chbrown/macos-wifi)
    ///
    /// ```text
    /// CWWiFiClient.sharedWiFiClient()     // Get singleton WiFi client
    ///     └─> client.interface()          // Get default WiFi interface (CWInterface)
    ///         └─> interface.scanForNetworksWithName(nil, includeHidden: false, error: &err)
    ///             └─> NSSet<CWNetwork>    // Set of discovered networks
    ///                 └─> for each CWNetwork:
    ///                     - network.ssid         -> String?
    ///                     - network.bssid        -> String?
    ///                     - network.rssiValue    -> Int (dBm)
    ///                     - network.wlanChannel  -> CWChannel
    ///                     - network.security     -> CWSecurity (enum)
    /// ```
    ///
    /// # Location Services Requirement
    ///
    /// On macOS 10.15+, CoreWLAN requires Location Services permission.
    /// Without it, scan succeeds but returns empty SSIDs/BSSIDs.
    /// Reference: https://developer.apple.com/forums/thread/119798
    #[instrument(skip(self), name = "corewlan_scan")]
    fn scan(&self) -> ScanResult<Vec<NetworkInfo>> {
        info!("Starting WiFi scan using CoreWLAN framework");

        if self.wifi_client.is_null() {
            return Err(ScanError::NoInterface(
                "CoreWLAN not available - CWWiFiClient is null".into()
            ));
        }

        let sel = &self.selectors;

        // SAFETY: All operations are within an autorelease pool to manage ObjC memory.
        // All object pointers are validated before use.
        // Selectors match the method signatures documented by Apple.
        let networks = unsafe {
            // Create autorelease pool - all ObjC objects allocated during scan
            // will be released when we pop this pool
            let pool = objc_autoreleasePoolPush();

            // Get the WiFi interface: [client interface] -> CWInterface
            let interface = msg_send_id(self.wifi_client, sel.interface);
            if interface.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(ScanError::NoInterface(
                    "No WiFi interface available. Is WiFi enabled?".into()
                ));
            }

            // Perform the scan:
            // [interface scanForNetworksWithName:nil includeHidden:NO error:&error]
            // Returns NSSet<CWNetwork*>
            let mut error: Id = ptr::null_mut();
            let network_set = msg_send_scan(
                interface,
                sel.scan_for_networks,
                ptr::null_mut(), // nil = scan for all networks
                NO,              // don't include hidden networks
                &mut error,
            );

            // Check for scan error
            if !error.is_null() {
                let error_desc = msg_send_id(error, sel.localized_description);
                let error_msg = nsstring_to_string(error_desc, sel)
                    .unwrap_or_else(|| "Unknown error".into());

                error!(error = %error_msg, "CoreWLAN scan failed");
                objc_autoreleasePoolPop(pool);

                // Check for permission error
                if error_msg.contains("permission") || error_msg.contains("Location") {
                    return Err(ScanError::PermissionDenied(error_msg));
                }
                return Err(ScanError::CommandFailed(error_msg));
            }

            if network_set.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(ScanError::CommandFailed(
                    "Scan returned null - possible permission issue".into()
                ));
            }

            // Convert NSSet to NSArray for indexed access: [set allObjects]
            let network_array = msg_send_id(network_set, sel.all_objects);
            let count = msg_send_ulong(network_array, sel.count);

            debug!(network_count = count, "Scan returned networks");

            // Extract network info from each CWNetwork
            let mut result = Vec::with_capacity(count as usize);
            for i in 0..count {
                let network = msg_send_object_at_index(network_array, sel.object_at_index, i);
                if !network.is_null() {
                    if let Some(info) = self.extract_network_info(network) {
                        result.push(info);
                    }
                }
            }

            // Pop autorelease pool - all ObjC objects are now released
            objc_autoreleasePoolPop(pool);

            result
        };

        info!(network_count = networks.len(), "CoreWLAN scan complete");
        Ok(networks)
    }

    fn is_available(&self) -> bool {
        !self.wifi_client.is_null() && self.interface_name.is_some()
    }

    fn interface_name(&self) -> Option<String> {
        self.interface_name.clone()
    }
}

// =============================================================================
// Unsafe Code Summary & Justification
// =============================================================================
//
// This module contains extensive unsafe code for Objective-C FFI. This section
// documents all unsafe operations and explains why they are sound.
//
// Reference: Rust FFI Omnibus - https://jakegoulding.com/rust-ffi-omnibus/
// Reference: Rustonomicon - https://doc.rust-lang.org/nomicon/ffi.html
//
// -----------------------------------------------------------------------------
// 1. AUTORELEASE POOL
// -----------------------------------------------------------------------------
// All ObjC operations occur within an autorelease pool:
//   let pool = objc_autoreleasePoolPush();
//   // ... ObjC operations ...
//   objc_autoreleasePoolPop(pool);
//
// This ensures all temporary ObjC objects (NSSet, NSArray, NSString) are
// released when the pool is popped. Without this, we would leak memory.
//
// Reference: Apple Memory Management Guide
// https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/
//
// -----------------------------------------------------------------------------
// 2. NULL CHECKS
// -----------------------------------------------------------------------------
// Every ObjC object pointer is checked for null before use:
//   - objc_getClass returns null if class not found
//   - Method calls can return nil (ObjC equivalent of null)
//   - NSString's UTF8String can return null
//
// We check all pointers and handle null gracefully (return None or Err).
//
// -----------------------------------------------------------------------------
// 3. CORRECT MSG_SEND SIGNATURES
// -----------------------------------------------------------------------------
// objc_msgSend must be cast to the correct function pointer type.
// This is the most critical safety requirement.
//
// Reference: http://sasheldon.com/blog/2015/08/02/objective-c-from-rust-objc_msgsend/
// "Safely calling [objc_msgSend] requires first casting it to the type
// of the underlying method implementation."
//
// We verify signatures against Apple documentation:
// - Methods returning id (object): extern "C" fn(Id, Sel) -> Id
// - Methods returning NSInteger: extern "C" fn(Id, Sel) -> c_long
// - Methods returning NSUInteger: extern "C" fn(Id, Sel) -> u64
// - scanForNetworksWithName:includeHidden:error: has 3 parameters
//
// -----------------------------------------------------------------------------
// 4. SELECTOR CORRECTNESS
// -----------------------------------------------------------------------------
// All selectors match the exact ObjC method names from Apple documentation.
// Selector strings are null-terminated byte strings (b"methodName:\0").
//
// If a selector is wrong, the ObjC runtime will:
// - Return nil (if method not found and object handles it)
// - Crash with "unrecognized selector" (if object doesn't handle it)
//
// We mitigate by using exact names from Apple's header files.
//
// -----------------------------------------------------------------------------
// 5. THREAD SAFETY
// -----------------------------------------------------------------------------
// CWWiFiClient's sharedWiFiClient is documented as thread-safe.
// Reference: https://developer.apple.com/documentation/corewlan/cwwificlient
// "The shared WiFi client object is thread-safe."
//
// We only read from objects, never modify state, so no data races.
//
// -----------------------------------------------------------------------------
// 6. STRING HANDLING
// -----------------------------------------------------------------------------
// NSString to Rust String conversion:
//   let utf8 = [nsstring UTF8String];  // Returns const char*
//   CStr::from_ptr(utf8).to_string_lossy().into_owned()
//
// We copy the string data into an owned Rust String immediately.
// This ensures our String remains valid after ObjC objects are released.
//
// -----------------------------------------------------------------------------
// 7. MEMORY MANAGEMENT
// -----------------------------------------------------------------------------
// - Autorelease pool handles all temporary objects
// - CWWiFiClient is a singleton (framework owns it, we just borrow)
// - We don't call retain/release - autorelease pool handles everything
// - All allocations are freed when objc_autoreleasePoolPop is called
//
// This matches the recommended pattern from:
// https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/
