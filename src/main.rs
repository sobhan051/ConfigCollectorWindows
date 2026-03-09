use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use eframe::egui;
use regex::Regex;
use reqwest::blocking::{Client, ClientBuilder};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const APP_CONFIG_PATH: &str = "config/app_config.toml";
const CHANNELS_PATH: &str = "config/channels.txt";
const OUTPUT_NEW_DIR: &str = "output/new_only";
const OUTPUT_APPEND_DIR: &str = "output/append_unique";
const LOG_FILE: &str = "logs/app.log";
const HISTORY_PATH: &str = "output/sent_history.json";
const DEFAULT_PROTOCOLS: [&str; 27] = [
    "vmess", "vless", "trojan", "ss", "ssr", "tuic", "hysteria", "hysteria2", "hy2", "juicity",
    "snell", "anytls", "ssh", "wireguard", "wg", "warp", "socks", "socks4", "socks5", "tg", "dns",
    "nm-dns", "nm-vless", "slipnet-enc", "slipnet", "slipstream", "dnstt",
];

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 650.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Telegram Config Collector",
        options,
        Box::new(|_| Ok(Box::new(AppState::bootstrap()))),
    );
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtocolRule {
    enabled: bool,
    max_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum ProxyType {
    None,
    System,
    Http,
    Socks5,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct AppConfig {
    interval_minutes: u64,
    max_pages_per_channel: usize,
    lookback_days: i64,
    proxy_type: ProxyType,
    proxy_host: String,
    proxy_port: u16,
    proxy_username: String,
    proxy_password: String,
    output_new_only_enabled: bool,
    output_append_unique_enabled: bool,
    protocol_rules: BTreeMap<String, ProtocolRule>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut protocol_rules = BTreeMap::new();
        for p in DEFAULT_PROTOCOLS {
            protocol_rules.insert(
                p.to_string(),
                ProtocolRule {
                    enabled: true,
                    max_count: 500,
                },
            );
        }
        Self {
            interval_minutes: 5,
            max_pages_per_channel: 15,
            lookback_days: 2,
            proxy_type: ProxyType::System,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 10808,
            proxy_username: String::new(),
            proxy_password: String::new(),
            output_new_only_enabled: true,
            output_append_unique_enabled: false,
            protocol_rules,
        }
    }
}

impl AppConfig {
    fn load_or_create() -> Self {
        if let Ok(raw) = fs::read_to_string(APP_CONFIG_PATH) {
            if let Ok(mut cfg) = toml::from_str::<Self>(&raw) {
                for p in DEFAULT_PROTOCOLS {
                    cfg.protocol_rules
                        .entry(p.to_string())
                        .or_insert(ProtocolRule {
                            enabled: true,
                            max_count: 500,
                        });
                }
                return cfg;
            }
        }
        let cfg = Self::default();
        let _ = cfg.save();
        cfg
    }

    fn save(&self) -> Result<()> {
        ensure_parent(APP_CONFIG_PATH)?;
        fs::write(APP_CONFIG_PATH, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SentHistory {
    sent_at: BTreeMap<String, DateTime<Utc>>,
}

impl SentHistory {
    fn load() -> Self {
        if let Ok(raw) = fs::read_to_string(HISTORY_PATH) {
            if let Ok(v) = serde_json::from_str::<Self>(&raw) {
                return v;
            }
        }
        Self::default()
    }

    fn prune(&mut self, lookback_days: i64) {
        let threshold = Utc::now() - ChronoDuration::days(lookback_days.max(1));
        self.sent_at.retain(|_, ts| *ts >= threshold);
    }

    fn save(&self) -> Result<()> {
        ensure_parent(HISTORY_PATH)?;
        fs::write(HISTORY_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Debug)]
struct LogMessage {
    time: String,
    level: LogLevel,
    text: String,
}

#[derive(Clone, Debug)]
enum WorkerEvent {
    Log(LogLevel, String),
    Stats {
        total: usize,
        by_protocol: BTreeMap<String, usize>,
    },
    ProxyAccess {
        ok: bool,
        detail: String,
    },
}

struct AppState {
    config: AppConfig,
    channels_text: String,
    active_tab: usize,
    proxy_access_status: String,
    proxy_access_ok: Option<bool>,
    logs: Vec<LogMessage>,
    total_configs: usize,
    by_protocol: BTreeMap<String, usize>,
    running: bool,
    stop_flag: Arc<AtomicBool>,
    worker_handle: Option<thread::JoinHandle<()>>,
    event_rx: Option<Receiver<WorkerEvent>>,
}

impl AppState {
    fn bootstrap() -> Self {
        Self {
            config: AppConfig::load_or_create(),
            channels_text: fs::read_to_string(CHANNELS_PATH).unwrap_or_else(|_| {
                "# One channel per line\n# @channel\n# https://t.me/channel\nIranProxyPlus".to_string()
            }),
            active_tab: 0,
            proxy_access_status: "Waiting for connection...".to_string(),
            proxy_access_ok: None,
            logs: vec![LogMessage {
                time: Local::now().format("%H:%M:%S").to_string(),
                level: LogLevel::Info,
                text: "System initialized and ready.".to_string(),
            }],
            total_configs: 0,
            by_protocol: BTreeMap::new(),
            running: false,
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            event_rx: None,
        }
    }

    fn start(&mut self) {
        if self.running {
            return;
        }
        if let Err(e) = save_channels(&self.channels_text).and_then(|_| self.config.save()) {
            self.add_log(LogLevel::Error, format!("Failed to save settings: {e:#}"));
            return;
        }

        self.stop_flag.store(false, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.event_rx = Some(rx);
        self.running = true;
        let cfg = self.config.clone();
        let channels_raw = self.channels_text.clone();
        let stop_flag = self.stop_flag.clone();

        self.worker_handle = Some(thread::spawn(move || {
            if let Err(err) = run_worker(cfg, channels_raw, stop_flag, tx.clone()) {
                let _ = tx.send(WorkerEvent::Log(
                    LogLevel::Error,
                    format!("Critical error: {err:#}"),
                ));
            }
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.add_log(LogLevel::Warning, "Stop requested. Waiting for worker...".to_string());
    }

    fn add_log(&mut self, level: LogLevel, text: String) {
        self.logs.push(LogMessage {
            time: Local::now().format("%H:%M:%S").to_string(),
            level,
            text,
        });
    }

    fn poll_events(&mut self) {
        if let Some(rx) = &self.event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    WorkerEvent::Log(level, msg) => self.add_log(level, msg),
                    WorkerEvent::Stats { total, by_protocol } => {
                        self.total_configs = total;
                        self.by_protocol = by_protocol;
                    }
                    WorkerEvent::ProxyAccess { ok, detail } => {
                        self.proxy_access_ok = Some(ok);
                        self.proxy_access_status = detail;
                    }
                }
            }
        }
        if let Some(handle) = self.worker_handle.take() {
            if handle.is_finished() {
                let _ = handle.join();
                self.running = false;
                self.add_log(LogLevel::Warning, "Worker thread has stopped.".to_string());
            } else {
                self.worker_handle = Some(handle);
            }
        }
    }
}

// 🎨 طراح رابط کاربری (Theme Setup)
fn apply_modern_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(15, 17, 26);
    visuals.window_fill = egui::Color32::from_rgb(20, 23, 33);
    
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(26, 30, 41);
    visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(200, 205, 215);
    visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
    
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(33, 38, 51);
    visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
    
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 52, 69);
    visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
    
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(59, 130, 246);
    visuals.widgets.active.rounding = egui::Rounding::same(8.0);
    
    visuals.selection.bg_fill = egui::Color32::from_rgb(59, 130, 246);
    ctx.set_visuals(visuals);

    ctx.style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.window_margin = egui::Margin::same(15.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
    });
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        apply_modern_theme(ctx);

        // Header Panel
        egui::TopBottomPanel::top("header").exact_height(70.0).frame(
            egui::Frame::default().fill(egui::Color32::from_rgb(20, 23, 33)).inner_margin(15.0)
        ).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🚀 Telegram Config Collector").size(24.0).strong().color(egui::Color32::from_rgb(240, 240, 240)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.running {
                        if ui.add(egui::Button::new(egui::RichText::new("⏹ Stop Process").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(220, 38, 38))).clicked() {
                            self.stop();
                        }
                        ui.spinner();
                        ui.label(egui::RichText::new("Scraping in progress...").color(egui::Color32::from_rgb(59, 130, 246)));
                    } else {
                        if ui.add(egui::Button::new(egui::RichText::new("▶ Start Scraping").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(16, 185, 129))).clicked() {
                            self.start();
                        }
                        if ui.button("💾 Save Configs").clicked() {
                            let _ = save_channels(&self.channels_text);
                            let _ = self.config.save();
                            self.add_log(LogLevel::Success, "Settings saved successfully.".to_string());
                        }
                    }
                });
            });
        });

        // Left Sidebar Settings
        egui::SidePanel::left("sidebar").default_width(320.0).frame(
            egui::Frame::default().fill(egui::Color32::from_rgb(20, 23, 33)).inner_margin(15.0)
        ).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, 0, "📡 Settings");
                ui.selectable_value(&mut self.active_tab, 1, "📝 Channels");
                ui.selectable_value(&mut self.active_tab, 2, "⚙️ Protocols");
            });
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    0 => {
                        // General Settings
                        ui.heading(egui::RichText::new("Scraping Rules").color(egui::Color32::LIGHT_BLUE));
                        ui.add_space(5.0);
                        ui.horizontal(|ui| {
                            ui.label("Interval (Minutes):");
                            ui.add(egui::DragValue::new(&mut self.config.interval_minutes).range(1..=240));
                        });
                        ui.horizontal(|ui| {
                            ui.label("Max Pages/Channel:");
                            ui.add(egui::DragValue::new(&mut self.config.max_pages_per_channel).range(1..=100));
                        });
                        ui.horizontal(|ui| {
                            ui.label("Lookback Days:");
                            ui.add(egui::DragValue::new(&mut self.config.lookback_days).range(1..=30));
                        });

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("Network & Proxy").color(egui::Color32::LIGHT_BLUE));
                        ui.add_space(5.0);
                        egui::ComboBox::from_label("Connection Type")
                            .selected_text(match self.config.proxy_type {
                                ProxyType::None => "Direct (No Proxy)",
                                ProxyType::System => "System Proxy",
                                ProxyType::Http => "HTTP Proxy",
                                ProxyType::Socks5 => "SOCKS5 Proxy",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::System, "System Proxy");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::Socks5, "SOCKS5 Proxy");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::Http, "HTTP Proxy");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::None, "Direct (No Proxy)");
                            });

                        if matches!(self.config.proxy_type, ProxyType::Http | ProxyType::Socks5) {
                            ui.horizontal(|ui| {
                                ui.label("IP:");
                                ui.text_edit_singleline(&mut self.config.proxy_host);
                            });
                            ui.horizontal(|ui| {
                                ui.label("Port:");
                                ui.add(egui::DragValue::new(&mut self.config.proxy_port).range(1..=65535));
                            });
                        }

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("Storage Modes").color(egui::Color32::LIGHT_BLUE));
                        ui.add_space(5.0);
                        ui.checkbox(&mut self.config.output_new_only_enabled, "Save as 'New Only'");
                        ui.checkbox(&mut self.config.output_append_unique_enabled, "Append to 'Unique List'");
                    }
                    1 => {
                        ui.heading(egui::RichText::new("Target Channels").color(egui::Color32::LIGHT_BLUE));
                        ui.label(egui::RichText::new("One per line (e.g., @v2ray_config)").small().color(egui::Color32::GRAY));
                        ui.add_sized(
                            [ui.available_width(), ui.available_height() - 20.0],
                            egui::TextEdit::multiline(&mut self.channels_text).font(egui::TextStyle::Monospace),
                        );
                    }
                    2 => {
                        ui.heading(egui::RichText::new("Protocols Filter").color(egui::Color32::LIGHT_BLUE));
                        for (name, rule) in &mut self.config.protocol_rules {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut rule.enabled, name);
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.add(egui::DragValue::new(&mut rule.max_count).range(1..=50000));
                                });
                            });
                        }
                    }
                    _ => {}
                }
            });
        });

        // Main Console Area
        egui::CentralPanel::default().frame(
            egui::Frame::default().fill(egui::Color32::from_rgb(15, 17, 26)).inner_margin(15.0)
        ).show(ctx, |ui| {
            // Stats Header
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Total Extracted:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(self.total_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(16, 185, 129)));
                });
                
                let proxy_color = match self.proxy_access_ok {
                    Some(true) => egui::Color32::from_rgb(16, 185, 129),
                    Some(false) => egui::Color32::from_rgb(239, 68, 68),
                    None => egui::Color32::GRAY,
                };
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Connection Status:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(&self.proxy_access_status).size(14.0).strong().color(proxy_color));
                });
            });

            ui.add_space(10.0);
            
            // Terminal Window
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(10, 12, 16))
                .rounding(10.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(egui::RichText::new("Terminal Logs").color(egui::Color32::WHITE));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("📋 Copy Logs").clicked() {
                                let txt = self.logs.iter().map(|l| format!("[{}] {}", l.time, l.text)).collect::<Vec<_>>().join("\n");
                                ctx.output_mut(|o| o.copied_text = txt);
                            }
                        });
                    });
                    ui.separator();
                    
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing.y = 4.0;
                            for log in self.logs.iter().rev().take(300).rev() {
                                let color = match log.level {
                                    LogLevel::Info => egui::Color32::from_rgb(156, 163, 175), // Gray
                                    LogLevel::Success => egui::Color32::from_rgb(52, 211, 153), // Green
                                    LogLevel::Warning => egui::Color32::from_rgb(251, 191, 36), // Yellow
                                    LogLevel::Error => egui::Color32::from_rgb(248, 113, 113), // Red
                                };
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(format!("[{}]", log.time)).color(egui::Color32::from_rgb(75, 85, 99)).monospace());
                                    ui.label(egui::RichText::new(&log.text).color(color).monospace());
                                });
                            }
                        });
                });
        });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

// -------------------------------------------------------------
// Core Network & Worker Logic (Completely Redesigned Fallback)
// -------------------------------------------------------------

fn run_worker(
    config: AppConfig,
    channels_raw: String,
    stop: Arc<AtomicBool>,
    tx: Sender<WorkerEvent>,
) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    if channels.is_empty() {
        let _ = tx.send(WorkerEvent::Log(LogLevel::Error, "No valid channels provided.".to_string()));
        return Ok(());
    }

    let client_result = build_client(&config);
    let client = match client_result {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(WorkerEvent::Log(LogLevel::Error, format!("Failed to build client: {}", e)));
            return Ok(());
        }
    };
    
    let regex = build_protocol_regex()?;
    let mut history = SentHistory::load();

    let mode_str = match config.proxy_type {
        ProxyType::None => "Direct Access (No Proxy)",
        ProxyType::System => "System Proxy",
        ProxyType::Http => "HTTP Proxy",
        ProxyType::Socks5 => "SOCKS5 Proxy (Secure DNS)",
    };
    log_worker(&tx, LogLevel::Info, format!("🚀 Starting worker in mode: {}", mode_str));

    // Probe Telegram domain (not web.telegram.org to avoid web restrictions)
    let probe_url = "https://t.me/s/telegram";
    match client.get(probe_url).send() {
        Ok(resp) if resp.status().is_success() => {
            let _ = tx.send(WorkerEvent::ProxyAccess { ok: true, detail: "Connection: Online 🟢".to_string() });
            log_worker(&tx, LogLevel::Success, "Proxy/Network connectivity check passed.".to_string());
        }
        Ok(resp) => {
            let _ = tx.send(WorkerEvent::ProxyAccess { ok: false, detail: format!("HTTP {}", resp.status()) });
            log_worker(&tx, LogLevel::Warning, format!("Connectivity check returned status: {}", resp.status()));
        }
        Err(e) => {
            let _ = tx.send(WorkerEvent::ProxyAccess { ok: false, detail: "Connection: Failed 🔴".to_string() });
            log_worker(&tx, LogLevel::Error, format!("Network check failed. Error: {}", e));
        }
    }

    loop {
        if stop.load(Ordering::SeqCst) { break; }

        history.prune(config.lookback_days);
        let threshold = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for channel in &channels {
            if stop.load(Ordering::SeqCst) { break; }
            log_worker(&tx, LogLevel::Info, format!("📥 Scraping @{} ...", channel));
            
            match fetch_channel_configs(&client, channel, config.max_pages_per_channel, threshold, &regex, &config.protocol_rules, &tx) {
                Ok(map) => {
                    let mut count = 0;
                    for (p, links) in map {
                        count += links.len();
                        gathered.entry(p).or_default().extend(links);
                    }
                    if count > 0 {
                        log_worker(&tx, LogLevel::Success, format!("Found {} raw configs from @{}", count, channel));
                    }
                }
                Err(e) => log_worker(&tx, LogLevel::Error, format!("Failed on @{}: {}", channel, e)),
            }
            thread::sleep(Duration::from_secs(2)); // Safe delay between channels
        }

        let mut new_only: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (proto, links) in gathered {
            for link in links {
                if !history.sent_at.contains_key(&link) {
                    history.sent_at.insert(link.clone(), Utc::now());
                    new_only.entry(proto.clone()).or_default().insert(link);
                }
            }
        }

        apply_protocol_limits(&mut new_only, &config.protocol_rules);
        
        let mut by_protocol = BTreeMap::new();
        let mut total_new = 0;
        for (k, v) in &new_only {
            by_protocol.insert(k.clone(), v.len());
            total_new += v.len();
        }
        
        if config.output_new_only_enabled { let _ = write_outputs_replace(OUTPUT_NEW_DIR, &new_only); }
        if config.output_append_unique_enabled { let _ = write_outputs_append_unique(OUTPUT_APPEND_DIR, &new_only); }
        
        let _ = history.save();
        let _ = tx.send(WorkerEvent::Stats { total: total_new, by_protocol });
        
        log_worker(&tx, LogLevel::Success, format!("✅ Cycle complete. Saved {} NEW unique configs.", total_new));
        log_worker(&tx, LogLevel::Info, format!("💤 Sleeping for {} minutes...", config.interval_minutes));

        for _ in 0..(config.interval_minutes * 60) {
            if stop.load(Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }
    log_worker(&tx, LogLevel::Warning, "Worker thread terminated safely.".to_string());
    Ok(())
}

fn fetch_channel_configs(
    client: &Client,
    channel: &str,
    max_pages: usize,
    threshold: DateTime<Utc>,
    pattern: &Regex,
    rules: &BTreeMap<String, ProtocolRule>,
    tx: &Sender<WorkerEvent>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let wrap_sel = Selector::parse("div.tgme_widget_message").unwrap();
    let text_sel = Selector::parse("div.tgme_widget_message_text").unwrap();
    let time_sel = Selector::parse("time").unwrap();

    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut before: Option<String> = None;

    for page in 1..=max_pages {
        let mut url = format!("https://t.me/s/{}", channel);
        if let Some(ref id) = before {
            url.push_str(&format!("?before={}", id));
        }

        let resp = match client.get(&url).send() {
            Ok(r) => r,
            Err(e) => anyhow::bail!("Request failed: {}", e),
        };

        if resp.status().as_u16() == 429 {
            log_worker(tx, LogLevel::Warning, "Rate limit (429) hit! Sleeping for 5 seconds...".to_string());
            thread::sleep(Duration::from_secs(5));
            continue; // Retry same page
        }

        if !resp.status().is_success() {
            anyhow::bail!("HTTP Status: {}", resp.status());
        }

        let body = resp.text()?;
        let doc = Html::parse_document(&body);
        let mut found_any = false;
        let mut next_before = None;
        let mut should_stop = false;

        for wrap in doc.select(&wrap_sel) {
            if let Some(post) = wrap.value().attr("data-post") {
                next_before = post.split('/').nth(1).map(|s| s.to_string());
            }

            let msg_time = wrap.select(&time_sel).next()
                .and_then(|t| t.value().attr("datetime"))
                .and_then(|iso| DateTime::parse_from_rfc3339(iso).ok())
                .map(|t| t.with_timezone(&Utc));

            if let Some(mt) = msg_time {
                if mt < threshold {
                    should_stop = true;
                    continue;
                }
            }

            for text in wrap.select(&text_sel) {
                found_any = true;
                let content = text.text().collect::<Vec<_>>().join(" ");
                for m in pattern.find_iter(&content) {
                    if let Some(proto) = m.as_str().split("://").next() {
                        let p = proto.to_lowercase();
                        if let Some(rule) = rules.get(&p) {
                            if rule.enabled {
                                result.entry(p).or_default().insert(m.as_str().to_string());
                            }
                        }
                    }
                }
            }
        }

        if !found_any || should_stop {
            break;
        }
        before = next_before;
        thread::sleep(Duration::from_millis(1500)); // Python script used 1.5s delay
    }

    Ok(result)
}

fn build_client(config: &AppConfig) -> Result<Client> {
    // Timeout های طولانی‌تر برای شبکه‌های ایران
    let mut b = ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15)) 
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    match config.proxy_type {
        ProxyType::None => {
            b = b.no_proxy();
        }
        ProxyType::System => {
            // به طور پیش‌فرض reqwest از پروکسی سیستم استفاده می‌کند.
        }
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = match config.proxy_type {
                ProxyType::Http => "http",
                ProxyType::Socks5 => "socks5h", // 'h' = Remote DNS Resolution (Critical for bypass)
                _ => unreachable!(),
            };
            
            let host = if config.proxy_host.trim().is_empty() { "127.0.0.1" } else { config.proxy_host.trim() };
            
            let proxy_url = if config.proxy_username.trim().is_empty() {
                format!("{}://{}:{}", scheme, host, config.proxy_port)
            } else {
                format!(
                    "{}://{}:{}@{}:{}",
                    scheme,
                    url::form_urlencoded::byte_serialize(config.proxy_username.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(config.proxy_password.as_bytes()).collect::<String>(),
                    host,
                    config.proxy_port
                )
            };
            
            b = b.proxy(reqwest::Proxy::all(&proxy_url)?);
        }
    }

    Ok(b.build()?)
}

// ... Utility Functions ...

fn log_worker(tx: &Sender<WorkerEvent>, level: LogLevel, text: String) {
    let _ = tx.send(WorkerEvent::Log(level, text));
}

fn apply_protocol_limits(store: &mut BTreeMap<String, BTreeSet<String>>, rules: &BTreeMap<String, ProtocolRule>) {
    for (proto, links) in store.iter_mut() {
        if let Some(rule) = rules.get(proto) {
            if links.len() > rule.max_count {
                *links = links.iter().take(rule.max_count).cloned().collect();
            }
        }
    }
}

fn write_outputs_replace(base_dir: &str, store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(base_dir)?;
    let mut mixed = Vec::new();
    for (p, links) in store {
        let lines: Vec<String> = links.iter().cloned().collect();
        fs::write(Path::new(base_dir).join(format!("{p}.txt")), lines.join("\n"))?;
        mixed.extend(lines);
    }
    fs::write(Path::new(base_dir).join("mixed.txt"), mixed.join("\n"))?;
    Ok(())
}

fn write_outputs_append_unique(base_dir: &str, store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(base_dir)?;
    for (p, links) in store {
        let path = Path::new(base_dir).join(format!("{p}.txt"));
        let mut combined = read_existing_set(&path)?;
        combined.extend(links.iter().cloned());
        fs::write(&path, combined.into_iter().collect::<Vec<_>>().join("\n"))?;
    }
    let mixed_path = Path::new(base_dir).join("mixed.txt");
    let mut mixed = read_existing_set(&mixed_path)?;
    for links in store.values() { mixed.extend(links.iter().cloned()); }
    fs::write(mixed_path, mixed.into_iter().collect::<Vec<_>>().join("\n"))?;
    Ok(())
}

fn read_existing_set(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() { return Ok(BTreeSet::new()); }
    Ok(fs::read_to_string(path)?.lines().map(str::trim).filter(|l| !l.is_empty()).map(ToOwned::to_owned).collect())
}

fn parse_channels(raw: &str) -> Vec<String> {
    raw.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|line| {
        if let Some(rest) = line.strip_prefix('@') { return Some(rest.to_string()); }
        if line.contains("t.me/") { return line.split("t.me/").nth(1).map(|x| x.split('?').next().unwrap_or_default().trim_matches('/').to_string()); }
        Some(line.to_string())
    }).filter(|s| !s.is_empty()).collect()
}

fn build_protocol_regex() -> Result<Regex> {
    Regex::new(r#"(?i)(vmess|vless|trojan|ssr?|tuic|hysteria2?|hy2|juicity|snell|anytls|ssh|wireguard|wg|warp|socks(?:4|5)?|tg|dns|nm-dns|nm-vless|slipnet-enc|slipnet|slipstream|dnstt)://[^\s<>'"]+"#)
        .context("regex")
}

fn save_channels(body: &str) -> Result<()> {
    ensure_parent(CHANNELS_PATH)?;
    fs::write(CHANNELS_PATH, body)?;
    Ok(())
}

fn ensure_parent(path: &str) -> Result<()> {
    let parent: PathBuf = Path::new(path).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(parent)?;
    Ok(())
}
