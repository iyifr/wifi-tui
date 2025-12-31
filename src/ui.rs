//! TUI Rendering Module
//!
//! Renders the WiFi network list and optional log panel using Ratatui.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::app::{App, LogLevel};
use wifi_tui::scanner::SecurityType;

/// Main render function
pub fn render(frame: &mut Frame, app: &mut App) {
    if app.logs_visible {
        // Split screen: networks on top, logs on bottom
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),  // Networks section
                Constraint::Percentage(40),  // Logs section
            ])
            .split(frame.area());

        render_networks_section(frame, app, main_chunks[0]);
        render_logs_panel(frame, app, main_chunks[1]);
    } else {
        // Full screen for networks
        render_networks_section(frame, app, frame.area());
    }
}

/// Render the networks section (header + table + footer)
fn render_networks_section(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(5),     // Network table
            Constraint::Length(3),  // Footer/status
        ])
        .split(area);

    render_header(frame, app, chunks[0]);
    render_network_table(frame, app, chunks[1]);
    render_footer(frame, app, chunks[2]);
}

/// Render the header with title and interface info
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let interface_text = app
        .interface_name
        .as_ref()
        .map(|n| format!(" [{}]", n))
        .unwrap_or_default();

    let title = format!("WiFi Scanner{}", interface_text);

    let status = if app.scanning {
        Span::styled(" Scanning...", Style::default().fg(Color::Yellow))
    } else {
        Span::styled(
            format!(" {} networks", app.networks.len()),
            Style::default().fg(Color::Green),
        )
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(title, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        status,
    ]))
    .block(Block::default().borders(Borders::ALL));

    frame.render_widget(header, area);
}

/// Render the network table
fn render_network_table(frame: &mut Frame, app: &mut App, area: Rect) {
    // Calculate visible rows (accounting for table header and borders)
    let visible_rows = area.height.saturating_sub(3) as usize;
    app.adjust_scroll(visible_rows);

    // Table headers
    let header_cells = ["SSID", "Signal", "Ch", "Security"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1);

    // Table rows
    let rows: Vec<Row> = app
        .networks
        .iter()
        .skip(app.scroll_offset)
        .take(visible_rows)
        .map(|network| {
            let signal_color = signal_color(network.signal_dbm);
            let security_color = security_color(&network.security);

            Row::new(vec![
                Cell::from(truncate_ssid(&network.ssid, 24)),
                Cell::from(format!("{} {:>3}dBm", network.signal_bars(), network.signal_dbm))
                    .style(Style::default().fg(signal_color)),
                Cell::from(format!("{:>3}", network.channel)),
                Cell::from(network.security.to_string())
                    .style(Style::default().fg(security_color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(26),        // SSID
            Constraint::Length(13),     // Signal
            Constraint::Length(4),      // Channel
            Constraint::Length(10),     // Security
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Networks"))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("► ");

    // Create table state for selection
    let mut table_state = TableState::default();
    // Adjust selection relative to scroll offset
    if !app.networks.is_empty() {
        table_state.select(Some(app.selected.saturating_sub(app.scroll_offset)));
    }

    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Render the footer with status and keybindings
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let content = if let Some(ref error) = app.error {
        Line::from(vec![
            Span::styled("Error: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(error.as_str(), Style::default().fg(Color::Red)),
        ])
    } else {
        let log_indicator = if app.logs_visible { "[logs]" } else { "" };
        Line::from(vec![
            Span::styled("Last scan: ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.time_since_scan()),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled("r", Style::default().fg(Color::Cyan)),
            Span::raw(":scan "),
            Span::styled("l", Style::default().fg(Color::Cyan)),
            Span::raw(":logs "),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::raw(":quit "),
            Span::styled(log_indicator, Style::default().fg(Color::Magenta)),
        ])
    };

    let footer = Paragraph::new(content).block(Block::default().borders(Borders::ALL));

    frame.render_widget(footer, area);
}

/// Render the expandable log panel
fn render_logs_panel(frame: &mut Frame, app: &App, area: Rect) {
    let logs = app.get_logs();
    let log_count = logs.len();

    // Create list items from log entries
    let items: Vec<ListItem> = logs
        .iter()
        .skip(app.log_scroll)
        .map(|entry| {
            let level_style = match entry.level {
                LogLevel::Error => Style::default().fg(Color::Red),
                LogLevel::Warn => Style::default().fg(Color::Yellow),
                LogLevel::Info => Style::default().fg(Color::Green),
                LogLevel::Debug => Style::default().fg(Color::DarkGray),
            };

            let level_char = match entry.level {
                LogLevel::Error => "E",
                LogLevel::Warn => "W",
                LogLevel::Info => "I",
                LogLevel::Debug => "D",
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", entry.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("[{}] ", level_char), level_style),
                Span::raw(&entry.message),
            ]))
        })
        .collect();

    let title = format!("Logs ({}) - ↑↓:scroll l:hide", log_count);

    let logs_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .style(Style::default().fg(Color::White));

    frame.render_widget(logs_list, area);
}

/// Get color based on signal strength
fn signal_color(dbm: i32) -> Color {
    match dbm {
        -50..=0 => Color::Green,        // Excellent
        -60..=-51 => Color::LightGreen, // Good
        -70..=-61 => Color::Yellow,     // Fair
        -80..=-71 => Color::LightRed,   // Weak
        _ => Color::Red,                // Very weak
    }
}

/// Get color based on security type
fn security_color(security: &SecurityType) -> Color {
    match security {
        SecurityType::Open => Color::Red,        // Insecure
        SecurityType::WEP => Color::LightRed,    // Weak security
        SecurityType::WPA => Color::Yellow,      // Outdated
        SecurityType::WPA2Personal | SecurityType::WPA2Enterprise => Color::Green,
        SecurityType::WPA3Personal | SecurityType::WPA3Enterprise => Color::LightGreen,
        SecurityType::Unknown(_) => Color::Gray,
    }
}

/// Truncate SSID to fit in column, adding ellipsis if needed
fn truncate_ssid(ssid: &str, max_len: usize) -> String {
    if ssid.len() <= max_len {
        ssid.to_string()
    } else {
        format!("{}…", &ssid[..max_len - 1])
    }
}
