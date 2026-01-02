//! WiFi TUI - Cross-platform WiFi Network Scanner
//!
//! A terminal user interface for discovering and listing nearby WiFi networks.
//! Displays SSID, signal strength, channel, and security protocol.
//!
//! Platform implementations:
//! - macOS: airport command (see ffi.md for why not CoreWLAN)
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

mod app;
mod ui;

use app::App;
use wifi_tui::scanner;

fn main() -> io::Result<()> {
    // Note: We don't initialize tracing to stdout because it would corrupt the TUI.
    // All logging goes through app.log_buffer and is displayed in the TUI log panel.

    // Set up panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    run_app()
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
                    // Handle Ctrl+C for quit (check both 'c' and 'C' for compatibility)
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
                        app.quit();
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
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
