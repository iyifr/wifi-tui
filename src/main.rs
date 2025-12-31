//! WiFi TUI - Cross-platform WiFi Network Scanner
//!
//! A terminal user interface for discovering and listing nearby WiFi networks.
//! Displays SSID, signal strength, channel, and security protocol.
//!
//! Platform implementations:
//! - macOS: Uses airport command (CoreWLAN needs objc runtime)
//! - Linux: Uses iw command (nl80211 too complex without crates)
//! - Windows: Raw FFI to wlanapi.dll (Native WiFi API)

use std::io::{self, stdout};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::prelude::*;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

mod app;
mod ui;

use app::App;
use wifi_tui::scanner;

fn main() -> io::Result<()> {
    // Initialize tracing with env filter (RUST_LOG=debug for verbose)
    init_tracing();

    info!(
        platform = std::env::consts::OS,
        "Starting WiFi TUI"
    );

    // Run the TUI application
    let result = run_app();

    // Log exit status
    match &result {
        Ok(()) => info!("Application exited normally"),
        Err(e) => error!(error = %e, "Application exited with error"),
    }

    result
}

/// Initialize tracing subscriber for structured logging
fn init_tracing() {
    // Use RUST_LOG env var, default to info level
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("wifi_tui=info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}

/// Main application loop
fn run_app() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    // Create application state
    let mut app = App::new();

    // Check if scanner is available
    let scanner = scanner::create_scanner();
    if !scanner.is_available() {
        // Still show TUI but with error
        app.error = Some("WiFi hardware not available or disabled".into());
    } else {
        // Start initial scan
        app.start_scan();
    }

    // Event loop
    let tick_rate = Duration::from_millis(100);

    while app.running {
        // Poll for scan completion
        app.poll_scan();

        // Draw UI
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        // Handle input with timeout
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // Only handle key press events (not release)
                if key.kind == KeyEventKind::Press {
                    // Handle Ctrl+C for quit
                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        app.quit();
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.quit();
                        }
                        KeyCode::Char('r') => {
                            app.start_scan();
                        }
                        KeyCode::Char('l') => {
                            app.toggle_logs();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.logs_visible {
                                app.scroll_logs_up();
                            } else {
                                app.select_previous();
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.logs_visible {
                                app.scroll_logs_down();
                            } else {
                                app.select_next();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}
