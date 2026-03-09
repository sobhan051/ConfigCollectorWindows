use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use eframe::egui;
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const APP_CONFIG_PATH: &str = "config/app_config.toml";
const CHANNELS_PATH: &str = "config/channels.txt";
const OUTPUT_NEW_DIR: &str = "output/new_only";
const OUTPUT_APPEND_DIR: &str = "output/append_unique";
const HISTORY_PATH: &str = "output/sent_history.json";
const CREATE_NO_WINDOW: u32 = 0x08000000;

const DEFAULT_PROTOCOLS: [&str; 26] = [
    "vmess", "vless", "trojan", "ss", "ssr", "tuic", "hysteria", "hysteria2", "juicity",
    "snell", "anytls", "ssh", "wireguard", "wg", "warp", "socks", "socks4", "socks5", "tg", "dns",
    "nm-dns", "nm-vless", "slipnet-enc", "slipnet", "slipstream", "dnstt",
];

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1050.0, 750.0])
            .with_min_inner_size([850.0, 600.0]),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Config Collector Pro",
        options,
        Box::new(|_| Ok(Box::new(AppState::bootstrap()))),
    );
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ScrapingEngine {
    RealBrowser,
    Reqwest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ProxyType {
    None,
    System,
    Http,
    Socks5,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum PerformanceProfile {
    WeakPC,
    MediumPC,
    StrongPC,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtocolRule {
    enabled: bool,
    max_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct AppConfig {
    interval_minutes: u64,
    max_pages_per_channel: usize,
    lookback_days: i64,
    engine: ScrapingEngine,
    proxy_type: ProxyType,
    proxy_host: String,
    proxy_port: u16,
    performance: PerformanceProfile,
    ignore_ssl_errors: bool,
    remote_dns: bool,
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
                    max_count: 5000, // محدودیت پیش‌فرض بالاتر برای بکاپ کامل
                },
            );
        }
        Self {
            interval_minutes: 5,
            max_pages_per_channel: 15,
            lookback_days: 2,
            engine: ScrapingEngine::Reqwest, // سرعت بالا با ریکوئست
            proxy_type: ProxyType::System,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 10808,
            performance: PerformanceProfile::StrongPC,
            ignore_ssl_errors: true,
            remote_dns: true,
            output_new_only_enabled: true,
            output_append_unique_enabled: true,
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
                            max_count: 5000,
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
        if let Some(parent) = Path::new(APP_CONFIG_PATH).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(APP_CONFIG_PATH, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
        if let Some(parent) = Path::new(HISTORY_PATH).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(HISTORY_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum LogLevel {
    Debug,
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
enum AppEvent {
    Log(LogLevel, String),
    Stats {
        total: usize,
        by_protocol: BTreeMap<String, usize>,
    },
    PingResult {
        ok: bool,
        detail: String,
    },
    WorkerStopped,
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
    event_tx: Sender<AppEvent>,
    event_rx: Receiver<AppEvent>,
}

impl AppState {
    fn bootstrap() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut state = Self {
            config: AppConfig::load_or_create(),
            channels_text: fs::read_to_string(CHANNELS_PATH)
                .unwrap_or_else(|_| "IranProxyPlus\nfilembad".to_string()),
            active_tab: 0,
            proxy_access_status: "Awaiting test...".to_string(),
            proxy_access_ok: None,
            logs: vec![LogMessage {
                time: Local::now().format("%H:%M:%S").to_string(),
                level: LogLevel::Info,
                text: "🖥️ System Boot: Ultra-Fast Core Loaded. Output engines fixed.".to_string(),
            }],
            total_configs: 0,
            by_protocol: BTreeMap::new(),
            running: false,
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            event_tx: tx,
            event_rx: rx,
        };
        state.test_connection();
        state
    }

    fn test_connection(&mut self) {
        self.proxy_access_status = "Testing connection...".to_string();
        self.proxy_access_ok = None;
        let tx = self.event_tx.clone();
        let config = self.config.clone();

        thread::spawn(move || {
            let start = Instant::now();
            match fetch_html("https://t.me/s/telegram", &config) {
                Ok(html) => {
                    let elapsed = start.elapsed().as_millis();
                    if html.len() > 100 {
                        let _ = tx.send(AppEvent::PingResult {
                            ok: true,
                            detail: format!("Online ({}ms)", elapsed),
                        });
                        let _ = tx.send(AppEvent::Log(
                            LogLevel::Success,
                            format!("📡 Network Passed! Size: {} bytes", html.len()),
                        ));
                    } else {
                        let _ = tx.send(AppEvent::PingResult {
                            ok: false,
                            detail: "Failed (Empty)".to_string(),
                        });
                    }
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::PingResult {
                        ok: false,
                        detail: "Failed".to_string(),
                    });
                    let _ = tx.send(AppEvent::Log(
                        LogLevel::Error,
                        format!("📡 Network Failed: {}", e),
                    ));
                }
            }
        });
    }

    fn start(&mut self) {
        if self.running {
            return;
        }
        let _ = fs::write(CHANNELS_PATH, &self.channels_text);
        let _ = self.config.save();
        self.stop_flag.store(false, Ordering::SeqCst);
        self.running = true;

        let tx = self.event_tx.clone();
        let cfg = self.config.clone();
        let channels_raw = self.channels_text.clone();
        let stop_flag = self.stop_flag.clone();

        self.worker_handle = Some(thread::spawn(move || {
            if let Err(err) = run_worker(cfg, channels_raw, stop_flag, tx.clone()) {
                let _ = tx.send(AppEvent::Log(
                    LogLevel::Error,
                    format!("🔥 CRASH: {}", err),
                ));
            }
            let _ = tx.send(AppEvent::WorkerStopped);
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.add_log(
            LogLevel::Warning,
            "🛑 Stop signal sent. Wrapping up safely...".to_string(),
        );
    }

    fn add_log(&mut self, level: LogLevel, text: String) {
        self.logs.push(LogMessage {
            time: Local::now().format("%H:%M:%S").to_string(),
            level,
            text,
        });
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::Log(level, msg) => self.add_log(level, msg),
                AppEvent::Stats { total, by_protocol } => {
                    self.total_configs = total;
                    self.by_protocol = by_protocol;
                }
                AppEvent::PingResult { ok, detail } => {
                    self.proxy_access_ok = Some(ok);
                    self.proxy_access_status = detail;
                }
                AppEvent::WorkerStopped => {
                    self.running = false;
                    self.add_log(
                        LogLevel::Warning,
                        "💤 Worker successfully terminated.".to_string(),
                    );
                }
            }
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = Command::new("cmd")
            .args(&["/C", "taskkill /F /IM msedge.exe /FI \"WINDOWTITLE eq \""])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        let _ = Command::new("cmd")
            .args(&["/C", "taskkill /F /IM chrome.exe /FI \"WINDOWTITLE eq \""])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
}

fn apply_modern_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(13, 15, 23);
    visuals.window_fill = egui::Color32::from_rgb(18, 20, 30);
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(25, 28, 40);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(32, 36, 50);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 52, 70);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 100, 220);
    visuals.selection.bg_fill = egui::Color32::from_rgb(60, 100, 220);
    ctx.set_visuals(visuals);
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        apply_modern_theme(ctx);

        egui::TopBottomPanel::top("header")
            .exact_height(75.0)
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(18, 20, 30))
                    .inner_margin(15.0),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("⚡ Telegram Config Collector")
                            .size(26.0)
                            .strong()
                            .color(egui::Color32::from_rgb(230, 240, 255)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.running {
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Stop Process")
                                            .strong()
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(200, 40, 40)),
                                )
                                .clicked()
                            {
                                self.stop();
                            }
                            ui.spinner();
                        } else {
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Start Engine")
                                            .strong()
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(30, 160, 100)),
                                )
                                .clicked()
                            {
                                self.start();
                            }
                            if ui.button("Test Network").clicked() {
                                self.test_connection();
                            }
                        }
                    });
                });
            });

        egui::SidePanel::left("sidebar")
            .default_width(340.0)
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(18, 20, 30))
                    .inner_margin(15.0),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.active_tab, 0, "Main");
                    ui.selectable_value(&mut self.active_tab, 1, "Targets");
                    ui.selectable_value(&mut self.active_tab, 2, "Filters");
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match self.active_tab {
                        0 => {
                            ui.heading(
                                egui::RichText::new("🚀 Scraping Engine")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            egui::ComboBox::from_label("Type")
                                .selected_text(match self.config.engine {
                                    ScrapingEngine::RealBrowser => "Browser (Stealth/Slow)",
                                    ScrapingEngine::Reqwest => "API (Fast)",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.config.engine,
                                        ScrapingEngine::Reqwest,
                                        "API (Fast)",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.engine,
                                        ScrapingEngine::RealBrowser,
                                        "Browser (Stealth/Slow)",
                                    );
                                });

                            ui.add_space(10.0);
                            ui.heading(
                                egui::RichText::new("💻 Performance Profile")
                                    .color(egui::Color32::GOLD),
                            );
                            egui::ComboBox::from_label("PC Power")
                                .selected_text(match self.config.performance {
                                    PerformanceProfile::WeakPC => "Weak PC (Safe)",
                                    PerformanceProfile::MediumPC => "Medium PC (Balanced)",
                                    PerformanceProfile::StrongPC => "Strong PC (Fast Multi-threading)",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.config.performance,
                                        PerformanceProfile::WeakPC,
                                        "Weak PC (Safe)",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.performance,
                                        PerformanceProfile::MediumPC,
                                        "Medium PC (Balanced)",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.performance,
                                        PerformanceProfile::StrongPC,
                                        "Strong PC (Fast Multi-threading)",
                                    );
                                });

                            ui.add_space(15.0);
                            ui.heading(
                                egui::RichText::new("🌐 Network & Proxy")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            egui::ComboBox::from_label("Proxy")
                                .selected_text(match self.config.proxy_type {
                                    ProxyType::None => "Direct",
                                    ProxyType::System => "System Auto",
                                    ProxyType::Http => "HTTP",
                                    ProxyType::Socks5 => "SOCKS5",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.config.proxy_type,
                                        ProxyType::System,
                                        "System Auto",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.proxy_type,
                                        ProxyType::Socks5,
                                        "SOCKS5",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.proxy_type,
                                        ProxyType::Http,
                                        "HTTP",
                                    );
                                    ui.selectable_value(
                                        &mut self.config.proxy_type,
                                        ProxyType::None,
                                        "Direct",
                                    );
                                });

                            if matches!(self.config.proxy_type, ProxyType::Http | ProxyType::Socks5)
                            {
                                ui.horizontal(|ui| {
                                    ui.label("IP:");
                                    ui.text_edit_singleline(&mut self.config.proxy_host);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Port:");
                                    ui.add(
                                        egui::DragValue::new(&mut self.config.proxy_port)
                                            .range(1..=65535),
                                    );
                                });
                            }
                            ui.checkbox(
                                &mut self.config.ignore_ssl_errors,
                                "Bypass SSL/TLS Filter",
                            );
                            if self.config.proxy_type == ProxyType::Socks5 {
                                ui.checkbox(&mut self.config.remote_dns, "Remote DNS (socks5h)");
                            }

                            ui.add_space(15.0);
                            ui.heading(
                                egui::RichText::new("📁 Output Settings")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            ui.checkbox(&mut self.config.output_new_only_enabled, "Save 'New Only' Configs");
                            ui.label(egui::RichText::new("    └ Extracts fresh configs not in history (output/new_only)").small().color(egui::Color32::GRAY));
                            
                            ui.add_space(5.0);
                            ui.checkbox(&mut self.config.output_append_unique_enabled, "Save 'Full Backup' (Append)");
                            ui.label(egui::RichText::new("    └ Adds ALL found configs to old ones (output/append_unique)").small().color(egui::Color32::GRAY));

                            ui.add_space(15.0);
                            ui.heading(
                                egui::RichText::new("⏱️ Scheduler & Limits")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            ui.horizontal(|ui| {
                                ui.label("Interval (Min):");
                                ui.add(
                                    egui::DragValue::new(&mut self.config.interval_minutes)
                                        .range(1..=240),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("Max Pages/Ch:");
                                ui.add(
                                    egui::DragValue::new(&mut self.config.max_pages_per_channel)
                                        .range(1..=100),
                                );
                            });
                            ui.horizontal(|ui| {
                                ui.label("Lookback Days:");
                                ui.add(
                                    egui::DragValue::new(&mut self.config.lookback_days)
                                        .range(1..=30),
                                );
                            });
                        }
                        1 => {
                            ui.heading(
                                egui::RichText::new("📡 Target Channels")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            ui.add_sized(
                                [ui.available_width(), ui.available_height() - 20.0],
                                egui::TextEdit::multiline(&mut self.channels_text)
                                    .font(egui::TextStyle::Monospace),
                            );
                        }
                        2 => {
                            ui.heading(
                                egui::RichText::new("🎯 Protocols Filter")
                                    .color(egui::Color32::LIGHT_BLUE),
                            );
                            for (name, rule) in &mut self.config.protocol_rules {
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut rule.enabled, name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::DragValue::new(&mut rule.max_count)
                                                    .range(1..=50000),
                                            );
                                        },
                                    );
                                });
                            }
                        }
                        _ => {}
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(13, 15, 23))
                    .inner_margin(15.0),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.group(|ui| {
                        ui.label(
                            egui::RichText::new("💎 Total In Current Run:").color(egui::Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(self.total_configs.to_string())
                                .size(20.0)
                                .strong()
                                .color(egui::Color32::from_rgb(30, 180, 120)),
                        );
                    });
                    let proxy_color = match self.proxy_access_ok {
                        Some(true) => egui::Color32::from_rgb(30, 180, 120),
                        Some(false) => egui::Color32::from_rgb(220, 60, 60),
                        None => egui::Color32::from_rgb(200, 150, 40),
                    };
                    ui.group(|ui| {
                        ui.label(
                            egui::RichText::new("🌐 Network Status:").color(egui::Color32::GRAY),
                        );
                        ui.label(
                            egui::RichText::new(&self.proxy_access_status)
                                .size(14.0)
                                .strong()
                                .color(proxy_color),
                        );
                    });
                });

                ui.add_space(10.0);
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(8, 10, 15))
                    .rounding(8.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading(
                                egui::RichText::new("📟 Professional Terminal")
                                    .color(egui::Color32::WHITE),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Clear").clicked() {
                                        self.logs.clear();
                                    }
                                    if ui.button("Copy").clicked() {
                                        let text = self
                                            .logs
                                            .iter()
                                            .map(|l| format!("[{}] {}", l.time, l.text))
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        ctx.output_mut(|o| o.copied_text = text);
                                    }
                                },
                            );
                        });
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .auto_shrink([false; 2])
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 5.0;
                                for log in self.logs.iter().rev().take(400).rev() {
                                    let color = match log.level {
                                        LogLevel::Debug => egui::Color32::from_rgb(100, 110, 130),
                                        LogLevel::Info => egui::Color32::from_rgb(160, 180, 200),
                                        LogLevel::Success => egui::Color32::from_rgb(60, 210, 130),
                                        LogLevel::Warning => egui::Color32::from_rgb(240, 180, 50),
                                        LogLevel::Error => egui::Color32::from_rgb(255, 90, 90),
                                    };
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!("[{}]", log.time))
                                                .color(egui::Color32::from_rgb(80, 90, 110))
                                                .monospace()
                                                .small(),
                                        );
                                        ui.label(
                                            egui::RichText::new(&log.text)
                                                .color(color)
                                                .monospace(),
                                        );
                                    });
                                }
                            });
                    });
            });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

// =============================================================
// 🛡️ هسته شبکه ایمن
// =============================================================

fn get_performance_settings(profile: &PerformanceProfile, engine: &ScrapingEngine) -> (Duration, u64, usize) {
    match (profile, engine) {
        (PerformanceProfile::WeakPC, ScrapingEngine::RealBrowser) => (Duration::from_secs(4), 18000, 1),
        (PerformanceProfile::MediumPC, ScrapingEngine::RealBrowser) => (Duration::from_secs(2), 12000, 1),
        (PerformanceProfile::StrongPC, ScrapingEngine::RealBrowser) => (Duration::from_secs(1), 8000, 2),
        
        (PerformanceProfile::WeakPC, ScrapingEngine::Reqwest) => (Duration::from_millis(1500), 10000, 2),
        (PerformanceProfile::MediumPC, ScrapingEngine::Reqwest) => (Duration::from_millis(500), 10000, 5),
        (PerformanceProfile::StrongPC, ScrapingEngine::Reqwest) => (Duration::from_millis(100), 10000, 10),
    }
}

fn fetch_html(url: &str, config: &AppConfig) -> Result<String> {
    match config.engine {
        ScrapingEngine::RealBrowser => fetch_with_safe_browser(url, config),
        ScrapingEngine::Reqwest => fetch_with_reqwest(url, config),
    }
}

fn fetch_with_safe_browser(url: &str, config: &AppConfig) -> Result<String> {
    let (_, timeout_ms, _) = get_performance_settings(&config.performance, &config.engine);

    let mut args = vec![
        "--headless=new".to_string(),
        "--dump-dom".to_string(),
        "--disable-gpu".to_string(),
        "--no-sandbox".to_string(),
        "--disable-dev-shm-usage".to_string(),
        "--disable-extensions".to_string(),
        "--mute-audio".to_string(),
        "--window-size=1920,1080".to_string(),
        format!("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    ];

    match config.proxy_type {
        ProxyType::System => {}
        ProxyType::None => {
            args.push("--no-proxy-server".to_string());
        }
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = if config.proxy_type == ProxyType::Socks5 { "socks5" } else { "http" };
            let host = if config.proxy_host.is_empty() { "127.0.0.1" } else { &config.proxy_host };
            args.push(format!("--proxy-server={}://{}:{}", scheme, host, config.proxy_port));
        }
    }
    args.push(url.to_string());

    let browsers = [
        "msedge.exe",
        "chrome.exe",
        r#"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"#,
        r#"C:\Program Files\Google\Chrome\Application\chrome.exe"#,
    ];

    for browser in browsers {
        let mut child_proc = match Command::new(browser)
            .args(&args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn() 
        {
            Ok(child) => child,
            Err(_) => continue,
        };

        let start_time = Instant::now();
        let mut stdout_str = String::new();
        let mut is_completed = false;

        if let Some(mut stdout) = child_proc.stdout.take() {
            let mut buffer = [0; 4096];
            loop {
                if start_time.elapsed().as_millis() as u64 > timeout_ms { break; }
                match stdout.read(&mut buffer) {
                    Ok(0) => { is_completed = true; break; }
                    Ok(n) => stdout_str.push_str(&String::from_utf8_lossy(&buffer[..n])),
                    Err(_) => break,
                }
                thread::sleep(Duration::from_millis(50));
            }
        }

        if !is_completed {
            let _ = child_proc.kill();
            return Err(anyhow::anyhow!("Browser timeout. Process safely killed."));
        }
        let _ = child_proc.wait();
        if stdout_str.len() > 50 { return Ok(stdout_str); }
    }
    anyhow::bail!("Failed to execute browser or received empty response.")
}

fn fetch_with_reqwest(url: &str, config: &AppConfig) -> Result<String> {
    let mut b = ClientBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
        .danger_accept_invalid_certs(config.ignore_ssl_errors);

    match config.proxy_type {
        ProxyType::None => b = b.no_proxy(),
        ProxyType::System => {}
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = if config.proxy_type == ProxyType::Socks5 && config.remote_dns { "socks5h" } else if config.proxy_type == ProxyType::Socks5 { "socks5" } else { "http" };
            let host = if config.proxy_host.trim().is_empty() { "127.0.0.1" } else { config.proxy_host.trim() };
            b = b.proxy(reqwest::Proxy::all(&format!("{}://{}:{}", scheme, host, config.proxy_port))?);
        }
    }
    let resp = b.build()?.get(url).send()?;
    if !resp.status().is_success() { anyhow::bail!("HTTP {}", resp.status()); }
    Ok(resp.text()?)
}

// =============================================================
// 🧠 پردازشگر چند نخی و استخراج هوشمند (مانند کد پایتون)
// =============================================================

fn run_worker(
    config: AppConfig,
    channels_raw: String,
    stop: Arc<AtomicBool>,
    tx: Sender<AppEvent>,
) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    let (delay, _, concurrency) = get_performance_settings(&config.performance, &config.engine);

    // Regex قدرتمند و تمیز
    let regex_pattern = r"(?i)(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2|juicity|snell|anytls|ssh|wireguard|wg|warp|socks|socks4|socks5|tg|dns|nm-dns|nm-vless|slipnet-enc|slipnet|slipstream|dnstt)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,%;=]+";
    let regex = Arc::new(Regex::new(regex_pattern).unwrap());
    let mut history = SentHistory::load();

    log_worker(&tx, LogLevel::Info, format!("🚀 Crawler Started | Engine: {:?} | Threads: {}", config.engine, concurrency));

    loop {
        if stop.load(Ordering::SeqCst) { break; }
        history.prune(config.lookback_days);
        
        let mut global_gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total_run_configs = 0;

        for chunk in channels.chunks(concurrency) {
            if stop.load(Ordering::SeqCst) { break; }

            thread::scope(|s| {
                let mut handles = vec![];

                for channel in chunk {
                    let tx_clone = tx.clone();
                    let config_clone = config.clone();
                    let stop_clone = stop.clone();
                    let regex_clone = regex.clone();
                    let chan = channel.clone();

                    let h = s.spawn(move || {
                        let mut local_gathered = BTreeMap::new();
                        let mut channel_configs = 0;
                        let mut before: Option<String> = None;

                        log_worker(&tx_clone, LogLevel::Info, format!("📡 Scanning channel: @{}", chan));

                        for page in 1..=config_clone.max_pages_per_channel {
                            if stop_clone.load(Ordering::SeqCst) { break; }
                            let mut url = format!("https://t.me/s/{}", chan);
                            if let Some(ref id) = before { url.push_str(&format!("?before={}", id)); }

                            match fetch_html(&url, &config_clone) {
                                Ok(raw_html) => {
                                    let mut found_in_page = 0;
                                    let mut next_before = None;

                                    // پاکسازی کدهای مخفی HTML مثل سورس پایتون
                                    let decoded_html = raw_html
                                        .replace("&amp;", "&")
                                        .replace("&lt;", "<")
                                        .replace("&gt;", ">")
                                        .replace("&quot;", "\"")
                                        .replace("&#39;", "'");

                                    let date_regex = Regex::new(r#"<time datetime="([^"]+)""#).unwrap();
                                    let mut latest_time_in_page: Option<DateTime<Utc>> = None;
                                    
                                    for cap in date_regex.captures_iter(&decoded_html) {
                                        if let Ok(parsed_time) = DateTime::parse_from_rfc3339(&cap[1]) {
                                            let utc_time = parsed_time.with_timezone(&Utc);
                                            if latest_time_in_page.is_none() || utc_time > latest_time_in_page.unwrap() {
                                                latest_time_in_page = Some(utc_time);
                                            }
                                        }
                                    }

                                    let mut reached_old_posts = false;
                                    if let Some(latest) = latest_time_in_page {
                                        let threshold = Utc::now() - ChronoDuration::days(config_clone.lookback_days.max(1));
                                        if latest < threshold { reached_old_posts = true; }
                                    }

                                    let next_regex = Regex::new(r#"data-post="[^/]+/(\d+)""#).unwrap();
                                    for cap in next_regex.captures_iter(&decoded_html) {
                                        next_before = Some(cap[1].to_string());
                                    }

                                    for m in regex_clone.find_iter(&decoded_html) {
                                        let full_match = m.as_str();
                                        // پاک کردن کاراکترهای اضافه انتهای لینک
                                        let clean_link = full_match
                                            .trim_end_matches(&['(', ')', '[', ']', ' ', '!', '.', ',', ';', '\'', '"', '<', '>'][..])
                                            .to_string();

                                        if let Some(proto_raw) = clean_link.split("://").next() {
                                            let mut proto = proto_raw.to_lowercase();
                                            // ادغام هوشمند hy2 با hysteria2 (طبق پایتون)
                                            if proto == "hy2" { proto = "hysteria2".to_string(); }
                                            
                                            found_in_page += 1;
                                            local_gathered.entry(proto).or_insert_with(BTreeSet::new).insert(clean_link);
                                        }
                                    }

                                    if found_in_page > 0 {
                                        log_worker(&tx_clone, LogLevel::Success, format!("    ✔️ @{} | Page {}: {} configs.", chan, page, found_in_page));
                                    }

                                    channel_configs += found_in_page;
                                    before = next_before;

                                    if reached_old_posts {
                                        log_worker(&tx_clone, LogLevel::Warning, format!("    ⏳ @{} reached posts older than {} days. Stopping pagination.", chan, config_clone.lookback_days));
                                        break;
                                    }

                                    if before.is_none() { break; }
                                }
                                Err(e) => { log_worker(&tx_clone, LogLevel::Error, format!("    ❌ @{} | Page {} failed: {}", chan, page, extract_error_msg(&e))); }
                            }
                            thread::sleep(delay);
                        }
                        
                        log_worker(&tx_clone, LogLevel::Info, format!("🏁 Finished @{}: Total {} configs.", chan, channel_configs));
                        (chan, channel_configs, local_gathered)
                    });
                    handles.push(h);
                }

                for h in handles {
                    if let Ok((_chan, count, local_gathered)) = h.join() {
                        total_run_configs += count;
                        for (proto, links) in local_gathered {
                            global_gathered.entry(proto).or_default().extend(links);
                        }
                    }
                }
            });
            thread::sleep(Duration::from_secs(2));
        }

        // تفکیک کانفیگ‌های کاملاً جدید
        let mut new_only: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (proto, links) in &global_gathered {
            for link in links {
                if !history.sent_at.contains_key(link) {
                    history.sent_at.insert(link.clone(), Utc::now());
                    new_only.entry(proto.clone()).or_default().insert(link.clone());
                }
            }
        }

        apply_protocol_limits(&mut new_only, &config.protocol_rules);
        apply_protocol_limits(&mut global_gathered, &config.protocol_rules);

        let mut by_protocol = BTreeMap::new();
        let mut total_new = 0;
        for (k, v) in &new_only {
            by_protocol.insert(k.clone(), v.len());
            total_new += v.len();
        }

        // سیستم ذخیره‌سازی پیشرفته و ۱۰۰٪ ایمن
        if config.output_new_only_enabled {
            // ذخیره فایل‌های فقط جدید (حالت Replace)
            let _ = write_configs_safe(OUTPUT_NEW_DIR, &new_only, &config, false);
        }
        
        if config.output_append_unique_enabled {
            // نکته طلایی: برای بکاپ کامل، کل کانفیگ‌های پیدا شده (global_gathered) را به قبلی‌ها اضافه می‌کنیم!
            let _ = write_configs_safe(OUTPUT_APPEND_DIR, &global_gathered, &config, true);
        }

        let _ = history.save();
        let _ = tx.send(AppEvent::Stats { total: total_new, by_protocol });

        log_worker(&tx, LogLevel::Success, format!("🎉 Cycle Complete! Parsed {} total, {} were NEW.", total_run_configs, total_new));
        log_worker(&tx, LogLevel::Info, format!("💤 Sleeping for {} minutes...", config.interval_minutes));

        for _ in 0..(config.interval_minutes * 60) {
            if stop.load(Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

// =============================================================
// توابع ذخیره سازی فایل و Base64 کاملا امن
// =============================================================

fn extract_error_msg(err: &anyhow::Error) -> String {
    let mut chain = Vec::new();
    let mut current = Some(err.as_ref() as &dyn std::error::Error);
    while let Some(e) = current { chain.push(e.to_string()); current = e.source(); }
    chain.join(" -> ")
}

fn log_worker(tx: &Sender<AppEvent>, level: LogLevel, text: String) { let _ = tx.send(AppEvent::Log(level, text)); }

fn apply_protocol_limits(store: &mut BTreeMap<String, BTreeSet<String>>, rules: &BTreeMap<String, ProtocolRule>) {
    for (proto, links) in store.iter_mut() {
        if let Some(rule) = rules.get(proto) {
            if links.len() > rule.max_count {
                *links = links.iter().take(rule.max_count).cloned().collect();
            }
        }
    }
}

// تابع جدید که بدون خراب کردن فایل‌ها عملیات را انجام می‌دهد و Base64 نیز می‌سازد
fn write_configs_safe(
    base_dir: &str, 
    store: &BTreeMap<String, BTreeSet<String>>, 
    config: &AppConfig, 
    append_mode: bool
) -> Result<()> {
    fs::create_dir_all(base_dir)?;
    let mut mixed = BTreeSet::new();

    for (proto, rule) in &config.protocol_rules {
        if !rule.enabled { continue; }

        let mut current_set = BTreeSet::new();
        let path_txt = Path::new(base_dir).join(format!("{}.txt", proto));
        let path_b64 = Path::new(base_dir).join(format!("{}_base64.txt", proto));

        // اگر حالت اپند فعال بود، ابتدا محتوای قبلی فایل‌ها را می‌خوانیم
        if append_mode {
            if let Ok(existing) = read_existing_set(&path_txt) {
                current_set.extend(existing);
            }
        }

        // سپس اطلاعات این دوره‌ی اسکن را به لیست اضافه می‌کنیم
        if let Some(links) = store.get(proto) {
            current_set.extend(links.iter().cloned());
        }

        // فقط در صورتی فایلی نوشته یا آپدیت می‌شود که کانفیگی برای آن وجود داشته باشد!
        if !current_set.is_empty() {
            let text_content = current_set.iter().cloned().collect::<Vec<_>>().join("\n");
            
            // نوشتن فایل معمولی
            fs::write(&path_txt, &text_content)?;
            
            // نوشتن فایل Base64
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            fs::write(&path_b64, STANDARD.encode(&text_content))?;
            
            // اضافه کردن به میکس نهایی
            mixed.extend(current_set);
        }
    }

    // نوشتن فایل‌های Mixed
    if !mixed.is_empty() {
        let path_mixed = Path::new(base_dir).join("mixed.txt");
        let path_mixed_b64 = Path::new(base_dir).join("mixed_base64.txt");
        
        let mut final_mixed = if append_mode {
            read_existing_set(&path_mixed).unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        
        final_mixed.extend(mixed);
        
        let mixed_text = final_mixed.into_iter().collect::<Vec<_>>().join("\n");
        fs::write(&path_mixed, &mixed_text)?;
        
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        fs::write(&path_mixed_b64, STANDARD.encode(&mixed_text))?;
    }

    Ok(())
}

fn read_existing_set(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() { return Ok(BTreeSet::new()); }
    let raw = fs::read_to_string(path)?;
    let lines = raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(ToOwned::to_owned).collect();
    Ok(lines)
}

fn parse_channels(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            if let Some(rest) = line.strip_prefix('@') { return Some(rest.to_string()); }
            if line.contains("t.me/") {
                return line.split("t.me/").nth(1).map(|x| x.split('?').next().unwrap_or_default().trim_matches('/').to_string());
            }
            Some(line.to_string())
        })
        .filter(|s| !s.is_empty())
        .collect()
}
