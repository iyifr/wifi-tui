//! Application State and Logic
//!
//! Manages WiFi network list, selection state, scan coordination, and log display.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use wifi_tui::scanner::{create_scanner, NetworkInfo, ScanError};

/// Maximum number of log entries to keep
const MAX_LOG_ENTRIES: usize = 100;

/// A single log entry with timestamp and level
#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)] // All levels defined for completeness
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

/// Thread-safe log buffer that can be shared with tracing
pub type LogBuffer = Arc<Mutex<VecDeque<LogEntry>>>;

/// Create a new shared log buffer
pub fn create_log_buffer() -> LogBuffer {
    Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)))
}

/// Add a log entry to the buffer
pub fn push_log(buffer: &LogBuffer, level: LogLevel, message: String) {
    if let Ok(mut logs) = buffer.lock() {
        let timestamp = chrono_lite_now();
        logs.push_back(LogEntry {
            timestamp,
            level,
            message,
        });
        // Keep buffer bounded
        while logs.len() > MAX_LOG_ENTRIES {
            logs.pop_front();
        }
    }
}

/// Simple timestamp without chrono crate
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() % 86400; // seconds in day
    let hours = (secs / 3600) % 24;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

/// Messages sent from scanner thread to main thread
pub enum ScanMessage {
    Started,
    Complete(Vec<NetworkInfo>),
    Error(ScanError),
}

/// Application state
pub struct App {
    /// List of discovered networks, sorted by signal strength
    pub networks: Vec<NetworkInfo>,
    /// Currently selected network index
    pub selected: usize,
    /// Scroll offset for network list display
    pub scroll_offset: usize,
    /// Last scan timestamp
    pub last_scan: Option<Instant>,
    /// Whether a scan is in progress
    pub scanning: bool,
    /// Error message to display (if any)
    pub error: Option<String>,
    /// WiFi interface name
    pub interface_name: Option<String>,
    /// Channel for receiving scan results
    scan_receiver: Option<Receiver<ScanMessage>>,
    /// Whether to keep running
    pub running: bool,
    /// Log buffer for TUI display
    pub log_buffer: LogBuffer,
    /// Whether the log panel is visible
    pub logs_visible: bool,
    /// Scroll offset for log display
    pub log_scroll: usize,
}

impl App {
    pub fn new() -> Self {
        Self::with_log_buffer(create_log_buffer())
    }

    pub fn with_log_buffer(log_buffer: LogBuffer) -> Self {
        let scanner = create_scanner();
        let interface_name = scanner.interface_name();

        // Log initialization
        push_log(&log_buffer, LogLevel::Info, format!(
            "WiFi TUI initialized on {}",
            std::env::consts::OS
        ));
        if let Some(ref iface) = interface_name {
            push_log(&log_buffer, LogLevel::Info, format!(
                "Using interface: {}",
                iface
            ));
        }

        Self {
            networks: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            last_scan: None,
            scanning: false,
            error: None,
            interface_name,
            scan_receiver: None,
            running: true,
            log_buffer,
            logs_visible: false,
            log_scroll: 0,
        }
    }

    /// Minimum interval between scans to avoid "Resource busy" errors
    const MIN_SCAN_INTERVAL: Duration = Duration::from_secs(3);

    /// Start a background scan
    pub fn start_scan(&mut self) {
        if self.scanning {
            push_log(&self.log_buffer, LogLevel::Debug, "Scan already in progress, skipping".into());
            return; // Already scanning
        }

        // Prevent rapid rescanning which causes "Resource busy" errors
        if let Some(last) = self.last_scan {
            if last.elapsed() < Self::MIN_SCAN_INTERVAL {
                push_log(&self.log_buffer, LogLevel::Debug,
                    "Please wait a few seconds between scans".into());
                return;
            }
        }

        push_log(&self.log_buffer, LogLevel::Info, "Starting WiFi scan...".into());

        self.scanning = true;
        self.error = None;

        let (tx, rx): (Sender<ScanMessage>, Receiver<ScanMessage>) = mpsc::channel();
        self.scan_receiver = Some(rx);
        let log_buffer = Arc::clone(&self.log_buffer);

        // Spawn scanner thread
        thread::spawn(move || {
            let _ = tx.send(ScanMessage::Started);

            let scanner = create_scanner();
            match scanner.scan() {
                Ok(networks) => {
                    push_log(&log_buffer, LogLevel::Info, format!(
                        "Scan complete: {} networks found",
                        networks.len()
                    ));
                    let _ = tx.send(ScanMessage::Complete(networks));
                }
                Err(e) => {
                    push_log(&log_buffer, LogLevel::Error, format!("Scan failed: {}", e));
                    let _ = tx.send(ScanMessage::Error(e));
                }
            }
        });
    }

    /// Check for scan completion (non-blocking)
    pub fn poll_scan(&mut self) {
        let Some(rx) = &self.scan_receiver else {
            return;
        };

        // Try to receive without blocking
        match rx.try_recv() {
            Ok(ScanMessage::Started) => {
                push_log(&self.log_buffer, LogLevel::Debug, "Scan thread started".into());
            }
            Ok(ScanMessage::Complete(mut networks)) => {
                // Log each network found
                for net in &networks {
                    push_log(&self.log_buffer, LogLevel::Debug, format!(
                        "  {} ({} dBm, Ch {}, {:?})",
                        net.ssid, net.signal_dbm, net.channel, net.security
                    ));
                }

                // Sort by signal strength (strongest first)
                networks.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));

                // Check for permission issue (0 networks on macOS usually means no location permission)
                #[cfg(target_os = "macos")]
                if networks.is_empty() {
                    push_log(&self.log_buffer, LogLevel::Warn,
                        "No networks found - Location Services may be required".into());
                    push_log(&self.log_buffer, LogLevel::Info,
                        "Go to System Settings > Privacy & Security > Location Services".into());
                    push_log(&self.log_buffer, LogLevel::Info,
                        "Enable location access for Terminal or your IDE".into());
                }

                self.networks = networks;
                self.scanning = false;
                self.last_scan = Some(Instant::now());
                self.scan_receiver = None;

                // Reset selection if out of bounds
                if self.selected >= self.networks.len() {
                    self.selected = self.networks.len().saturating_sub(1);
                }
            }
            Ok(ScanMessage::Error(e)) => {
                self.error = Some(e.to_string());
                self.scanning = false;
                self.scan_receiver = None;
            }
            Err(mpsc::TryRecvError::Empty) => {
                // Still waiting, nothing to do
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                // Sender dropped unexpectedly
                push_log(&self.log_buffer, LogLevel::Error, "Scanner thread crashed".into());
                self.error = Some("Scanner thread crashed".into());
                self.scanning = false;
                self.scan_receiver = None;
            }
        }
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            // Adjust scroll if needed
            if self.selected < self.scroll_offset {
                self.scroll_offset = self.selected;
            }
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.selected < self.networks.len().saturating_sub(1) {
            self.selected += 1;
        }
    }

    /// Adjust scroll offset based on visible area
    pub fn adjust_scroll(&mut self, visible_rows: usize) {
        // Ensure selected item is visible
        if self.selected >= self.scroll_offset + visible_rows {
            self.scroll_offset = self.selected - visible_rows + 1;
        }
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
    }

    /// Get time since last scan as human-readable string
    pub fn time_since_scan(&self) -> String {
        match self.last_scan {
            Some(instant) => {
                let elapsed = instant.elapsed();
                if elapsed < Duration::from_secs(60) {
                    format!("{}s ago", elapsed.as_secs())
                } else {
                    format!("{}m ago", elapsed.as_secs() / 60)
                }
            }
            None => "never".into(),
        }
    }

    /// Get the currently selected network (if any)
    #[allow(dead_code)] // API for future network details view
    pub fn selected_network(&self) -> Option<&NetworkInfo> {
        self.networks.get(self.selected)
    }

    /// Toggle log panel visibility
    pub fn toggle_logs(&mut self) {
        self.logs_visible = !self.logs_visible;
        push_log(&self.log_buffer, LogLevel::Debug, format!(
            "Log panel {}",
            if self.logs_visible { "shown" } else { "hidden" }
        ));
    }

    /// Scroll logs up
    pub fn scroll_logs_up(&mut self) {
        if self.log_scroll > 0 {
            self.log_scroll -= 1;
        }
    }

    /// Scroll logs down
    pub fn scroll_logs_down(&mut self) {
        if let Ok(logs) = self.log_buffer.lock() {
            if self.log_scroll < logs.len().saturating_sub(1) {
                self.log_scroll += 1;
            }
        }
    }

    /// Get log entries for display
    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.log_buffer
            .lock()
            .map(|logs| logs.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Quit the application
    pub fn quit(&mut self) {
        push_log(&self.log_buffer, LogLevel::Info, "Shutting down...".into());
        self.running = false;
    }
}
