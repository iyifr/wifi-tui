//! Simple test binary to verify the scanner works without TUI

use wifi_tui::scanner::create_scanner;

fn main() {
    let scanner = create_scanner();

    println!("WiFi available: {}", scanner.is_available());
    if let Some(iface) = scanner.interface_name() {
        println!("Interface: {}", iface);
    }

    match scanner.scan() {
        Ok(networks) => {
            println!("\nFound {} networks:\n", networks.len());
            for net in &networks {
                println!(
                    "  {} | {:>6} | {:>4} dBm | {} | {}",
                    net.signal_bars(),
                    net.frequency_band(),
                    net.signal_dbm,
                    net.security,
                    net.ssid
                );
            }
        }
        Err(e) => {
            eprintln!("Scan error: {}", e);
        }
    }
}
