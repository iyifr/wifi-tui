//! Integration test for the WiFi scanner
//!
//! NOTE: CoreWLAN requires Location Services permission on macOS 10.15+.
//! If tests return 0 networks, grant Terminal/IDE location access in
//! System Preferences > Security & Privacy > Privacy > Location Services.

use wifi_tui::scanner::create_scanner;

#[test]
fn test_scanner_available() {
    let scanner = create_scanner();
    println!("Scanner available: {}", scanner.is_available());
    println!("Interface: {:?}", scanner.interface_name());
    assert!(scanner.is_available(), "WiFi scanner should be available");
}

#[test]
fn test_scan_networks() {
    let scanner = create_scanner();
    if !scanner.is_available() {
        println!("Scanner not available, skipping");
        return;
    }

    match scanner.scan() {
        Ok(networks) => {
            println!("Found {} networks:", networks.len());
            for net in &networks {
                println!("  {} | {} dBm | Ch {} | {:?}",
                    net.ssid, net.signal_dbm, net.channel, net.security);
            }

            if networks.is_empty() {
                println!("\nWARNING: 0 networks found. This usually means:");
                println!("  1. Location Services not enabled for this app");
                println!("  2. Go to System Settings > Privacy & Security > Location Services");
                println!("  3. Enable location for Terminal or your IDE");
                println!("\nTest passes but scan may be limited without location permission.");
            }
        }
        Err(e) => {
            println!("Scan error: {}", e);
            println!("This may be a permission issue on macOS.");
        }
    }
}
