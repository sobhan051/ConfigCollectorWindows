#![windows_subsystem = "windows"]
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use eframe::egui;
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::net::TcpStream;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

const APP_CONFIG_PATH: &str = "config/app_config.toml";
const CHANNELS_PATH: &str = "config/channels.txt";
const OUTPUT_NEW_DIR: &str = "output/new_only";
const OUTPUT_APPEND_DIR: &str = "output/append_unique";
const OUTPUT_WORKING_DIR: &str = "output/working_pool";
const HOT_POOL_PATH: &str = "output/hot_pool.json";
const HISTORY_PATH: &str = "output/sent_history.json";
const PSIPHON_TEST_URL: &str = "http://149.154.167.91:443";
const CREATE_NO_WINDOW: u32 = 0x08000000;

const DEFAULT_PROTOCOLS: [&str; 4] = ["vless", "vmess", "trojan", "ss"];

// =============================================================
// DATA STRUCTURES
// =============================================================

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ScrapingEngine { RealBrowser, Reqwest }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ProxyType { None, System, Http, Socks5 }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtocolRule { enabled: bool, max_count: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HotPoolEntry {
    link: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_tested: DateTime<Utc>,
    success_count: u32,
    fail_count: u32,
    avg_connect_time_secs: f64,
    endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HotPool {
    entries: Vec<HotPoolEntry>,
}

impl HotPool {
    fn load() -> Self {
        if let Ok(raw) = fs::read_to_string(HOT_POOL_PATH) {
            if let Ok(v) = serde_json::from_str::<Self>(&raw) { return v; }
        }
        Self { entries: vec![] }
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = Path::new(HOT_POOL_PATH).parent() { fs::create_dir_all(parent)?; }
        fs::write(HOT_POOL_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn get_working(&self, max_age_mins: i64) -> Vec<HotPoolEntry> {
        let threshold = Utc::now() - ChronoDuration::minutes(max_age_mins);
        self.entries.iter()
            .filter(|e| e.last_tested > threshold && e.fail_count == 0)
            .cloned()
            .collect()
    }

    fn update_or_add(&mut self, link: &str, endpoint: &str, success: bool, connect_time: f64) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.link == link) {
            entry.last_tested = Utc::now();
            if success {
                entry.success_count += 1;
                entry.avg_connect_time_secs = (entry.avg_connect_time_secs + connect_time) / 2.0;
            } else {
                entry.fail_count += 1;
            }
        } else {
            self.entries.push(HotPoolEntry {
                link: link.to_string(),
                last_tested: Utc::now(),
                success_count: if success { 1 } else { 0 },
                fail_count: if success { 0 } else { 1 },
                avg_connect_time_secs: connect_time,
                endpoint: endpoint.to_string(),
            });
        }
        if self.entries.len() > 500 {
            self.entries.sort_by(|a, b| b.last_tested.cmp(&a.last_tested));
            self.entries.truncate(500);
        }
    }

    fn is_endpoint_tested_recently(&self, endpoint: &str, mins: i64) -> bool {
        let threshold = Utc::now() - ChronoDuration::minutes(mins);
        self.entries.iter().any(|e| e.endpoint == endpoint && e.last_tested > threshold && e.success_count > 0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct AppConfig {
    interval_minutes: u64,
    max_pages_per_channel: usize,
    lookback_days: i64,
    engine: ScrapingEngine,
    psiphon_http_host: String,
    psiphon_http_port: u16,
    performance: String,
    output_new_only_enabled: bool,
    output_append_unique_enabled: bool,
    test_configs_enabled: bool,
    testing_timeout_seconds: u64,
    max_concurrent_tests: usize,
    tier1_timeout_seconds: u64,
    tier2_timeout_seconds: u64,
    psiphon_health_check_interval_secs: u64,
    min_bytes_for_success: usize,
    protocol_rules: BTreeMap<String, ProtocolRule>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut protocol_rules = BTreeMap::new();
        for p in DEFAULT_PROTOCOLS {
            protocol_rules.insert(p.to_string(), ProtocolRule { enabled: true, max_count: 100 });
        }
        Self {
            interval_minutes: 15,
            max_pages_per_channel: 2,
            lookback_days: 2,
            engine: ScrapingEngine::Reqwest,
            psiphon_http_host: "127.0.0.1".to_string(),
            psiphon_http_port: 10880,
            performance: "low_bandwidth".to_string(),
            output_new_only_enabled: true,
            output_append_unique_enabled: true,
            test_configs_enabled: true,
            testing_timeout_seconds: 120,
            max_concurrent_tests: 2,
            tier1_timeout_seconds: 15,
            tier2_timeout_seconds: 90,
            psiphon_health_check_interval_secs: 120,
            min_bytes_for_success: 100,
            protocol_rules,
        }
    }
}

impl AppConfig {
    fn load_or_create() -> Self {
        if let Ok(raw) = fs::read_to_string(APP_CONFIG_PATH) {
            if let Ok(mut cfg) = toml::from_str::<Self>(&raw) {
                if cfg.testing_timeout_seconds == 0 { cfg.testing_timeout_seconds = 120; }
                if cfg.max_concurrent_tests == 0 { cfg.max_concurrent_tests = 2; }
                if cfg.tier1_timeout_seconds == 0 { cfg.tier1_timeout_seconds = 15; }
                if cfg.tier2_timeout_seconds == 0 { cfg.tier2_timeout_seconds = 90; }
                for p in DEFAULT_PROTOCOLS {
                    cfg.protocol_rules.entry(p.to_string()).or_insert(ProtocolRule { enabled: true, max_count: 100 });
                }
                return cfg;
            }
        }
        let cfg = Self::default();
        let _ = cfg.save();
        cfg
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = Path::new(APP_CONFIG_PATH).parent() { fs::create_dir_all(parent)?; }
        fs::write(APP_CONFIG_PATH, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SentHistory {
    // #[serde(with = "chrono::serde::ts_seconds")]  // ← Changed here
    sent_at: BTreeMap<String, DateTime<Utc>>,
    // #[serde(with = "chrono::serde::ts_seconds")]  // ← Changed here
    tested_at: BTreeMap<String, DateTime<Utc>>,
}

impl SentHistory {
    fn load() -> Self {
        if let Ok(raw) = fs::read_to_string(HISTORY_PATH) {
            if let Ok(v) = serde_json::from_str::<Self>(&raw) { return v; }
        }
        Self::default()
    }

    fn prune(&mut self, lookback_days: i64) {
        let threshold = Utc::now() - ChronoDuration::days(lookback_days.max(1));
        self.sent_at.retain(|_, ts| *ts >= threshold);
        self.tested_at.retain(|_, ts| *ts >= threshold);
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = Path::new(HISTORY_PATH).parent() { fs::create_dir_all(parent)?; }
        fs::write(HISTORY_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn mark_tested(&mut self, link: &str) {
        self.tested_at.insert(link.to_string(), Utc::now());
    }

    fn was_tested_recently(&self, link: &str, mins: i64) -> bool {
        if let Some(ts) = self.tested_at.get(link) {
            *ts > Utc::now() - ChronoDuration::minutes(mins)
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum LogLevel { Debug, Info, Success, Warning, Error }

#[derive(Clone, Debug)]
struct LogMessage { time: String, level: LogLevel, text: String }

#[derive(Clone, Debug)]
enum AppEvent {
    Log(LogLevel, String),
    Stats { total: usize, working: usize, by_protocol: BTreeMap<String, usize>, hot_pool_size: usize },
    PingResult { ok: bool, detail: String },
    PsiphonHealth { ok: bool, detail: String },
    WorkerStopped,
    TestingProgress { current: usize, total: usize },
}

#[derive(Clone, Debug)]
struct TestResult {
    link: String,
    endpoint: String,
    success: bool,
    connect_time_secs: f64,
    bytes_transferred: usize,
    error: Option<String>,
}

// =============================================================
// APP STATE
// =============================================================

struct AppState {
    config: AppConfig,
    channels_text: String,
    active_tab: usize,
    proxy_access_status: String,
    proxy_access_ok: Option<bool>,
    psiphon_health_ok: Option<bool>,
    psiphon_health_detail: String,
    logs: Vec<LogMessage>,
    total_configs: usize,
    working_configs: usize,
    by_protocol: BTreeMap<String, usize>,
    hot_pool_size: usize,
    testing_progress: Option<(usize, usize)>,
    running: bool,
    stop_flag: Arc<AtomicBool>,
    worker_handle: Option<thread::JoinHandle<()>>,
    event_tx: Sender<AppEvent>,
    event_rx: Receiver<AppEvent>,
    last_psiphon_check: Instant,
}

impl AppState {
    fn bootstrap() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut state = Self {
            config: AppConfig::load_or_create(),
            channels_text: fs::read_to_string(CHANNELS_PATH).unwrap_or_else(|_| "IranProxyPlus\nfilembad".to_string()),
            active_tab: 0,
            proxy_access_status: "Awaiting test...".to_string(),
            proxy_access_ok: None,
            psiphon_health_ok: None,
            psiphon_health_detail: "Not checked".to_string(),
            logs: vec![LogMessage {
                time: Local::now().format("%H:%M:%S").to_string(),
                level: LogLevel::Info,
                text: "🖥️ System Boot: Low-bandwidth optimized tester loaded.".to_string(),
            }],
            total_configs: 0,
            working_configs: 0,
            by_protocol: BTreeMap::new(),
            hot_pool_size: 0,
            testing_progress: None,
            running: false,
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            event_tx: tx,
            event_rx: rx,
            last_psiphon_check: Instant::now() - Duration::from_secs(300),
        };
        state.test_connection();
        state.check_psiphon_health();
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
                        let _ = tx.send(AppEvent::PingResult { ok: true, detail: format!("Online ({}ms)", elapsed) });
                        let _ = tx.send(AppEvent::Log(LogLevel::Success, format!("📡 Network Check Passed! Page size: {} bytes", html.len())));
                    } else {
                        let _ = tx.send(AppEvent::PingResult { ok: false, detail: "Failed (Empty Page)".to_string() });
                    }
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::PingResult { ok: false, detail: "Failed".to_string() });
                    let _ = tx.send(AppEvent::Log(LogLevel::Error, format!("📡 Network Test Failed: {}", e)));
                }
            }
        });
    }

    fn check_psiphon_health(&mut self) {
        if self.last_psiphon_check.elapsed().as_secs() < 60 {
            return;
        }
        self.last_psiphon_check = Instant::now();
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        thread::spawn(move || {
            let result = test_psiphon_alone(&config);
            let _ = tx.send(AppEvent::PsiphonHealth { 
                ok: result.is_ok(), 
                detail: result.unwrap_or_else(|e| e.to_string()) 
            });
        });
    }

    fn start(&mut self) {
        if self.running { return; }
        let _ = fs::write(CHANNELS_PATH, &self.channels_text);
        let _ = self.config.save();
        self.stop_flag.store(false, Ordering::SeqCst);
        self.running = true;
        self.testing_progress = None;
        let tx = self.event_tx.clone();
        let cfg = self.config.clone();
        let channels_raw = self.channels_text.clone();
        let stop_flag = self.stop_flag.clone();
        self.worker_handle = Some(thread::spawn(move || {
            if let Err(err) = run_worker(cfg, channels_raw, stop_flag, tx.clone()) {
                let _ = tx.send(AppEvent::Log(LogLevel::Error, format!("🔥 CRASH: {}", err)));
            }
            let _ = tx.send(AppEvent::WorkerStopped);
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.add_log(LogLevel::Warning, "🛑 Stop signal sent. Wrapping up safely...".to_string());
    }

    fn add_log(&mut self, level: LogLevel, text: String) {
        self.logs.push(LogMessage { time: Local::now().format("%H:%M:%S").to_string(), level, text });
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::Log(level, msg) => self.add_log(level, msg),
                AppEvent::Stats { total, working, by_protocol, hot_pool_size } => {
                    self.total_configs += total;
                    self.working_configs = working;
                    self.by_protocol = by_protocol;
                    self.hot_pool_size = hot_pool_size;
                }
                AppEvent::PingResult { ok, detail } => {
                    self.proxy_access_ok = Some(ok);
                    self.proxy_access_status = detail;
                }
                AppEvent::PsiphonHealth { ok, detail } => {
                    self.psiphon_health_ok = Some(ok);
                    self.psiphon_health_detail = detail.clone();
                    if !ok {
                        self.add_log(LogLevel::Error, format!("🚨 Psiphon Health Check Failed: {}", detail));
                    } else {
                        self.add_log(LogLevel::Success, format!("✅ Psiphon Healthy: {}", detail));
                    }
                }
                AppEvent::TestingProgress { current, total } => {
                    self.testing_progress = Some((current, total));
                }
                AppEvent::WorkerStopped => {
                    self.running = false;
                    self.testing_progress = None;
                    self.add_log(LogLevel::Warning, "💤 Worker thread terminated.".to_string());
                }
            }
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = Command::new("cmd").args(&["/C", "taskkill /F /IM xray.exe 2>nul"]).creation_flags(CREATE_NO_WINDOW).output();
    }
}

fn generate_icon() -> egui::IconData {
    let width = 32;
    let height = 32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for _y in 0..height {
        for _x in 0..width {
            rgba.push(30);
            rgba.push(160);
            rgba.push(100);
            rgba.push(255);
        }
    }
    egui::IconData { rgba, width, height }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([900.0, 600.0])
            .with_icon(generate_icon()),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "⚡ Config Collector Pro (Low-Bandwidth Optimized)",
        options,
        Box::new(|_| Box::new(AppState::bootstrap())),
    );
}


// =============================================================
// UI IMPLEMENTATION
// =============================================================

fn apply_modern_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(13, 15, 23);
    visuals.window_fill = egui::Color32::from_rgb(18, 20, 30);
    ctx.set_visuals(visuals);
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        apply_modern_theme(ctx);

        if self.last_psiphon_check.elapsed().as_secs() > self.config.psiphon_health_check_interval_secs {
            self.check_psiphon_health();
        }

        egui::TopBottomPanel::top("header")
            .exact_height(85.0)
            .frame(egui::Frame::default().fill(egui::Color32::from_rgb(18, 20, 30)).inner_margin(15.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("⚡ Config Collector Pro").size(24.0).strong().color(egui::Color32::from_rgb(230, 240, 255)));
                    ui.label(egui::RichText::new("(Low-Bandwidth Optimized)").size(14.0).color(egui::Color32::GRAY));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (ps_color, ps_text) = match self.psiphon_health_ok {
                            Some(true) => (egui::Color32::from_rgb(30, 180, 120), "🟢 Psiphon OK"),
                            Some(false) => (egui::Color32::from_rgb(220, 60, 60), "🔴 Psiphon Down"),
                            None => (egui::Color32::from_rgb(200, 150, 40), "🟡 Psiphon Unknown"),
                        };
                        ui.group(|ui| {
                            ui.label(egui::RichText::new(ps_text).color(ps_color).strong());
                        });

                        ui.add_space(20.0);

                        if self.running {
                            if ui.add(egui::Button::new(egui::RichText::new("🛑 Stop Process").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(200, 40, 40))).clicked() {
                                self.stop();
                            }
                            ui.spinner();
                        } else {
                            if ui.add(egui::Button::new(egui::RichText::new("▶ Start Engine").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(30, 160, 100))).clicked() {
                                self.start();
                            }
                            if ui.button("🔄 Test Network").clicked() {
                                self.test_connection();
                            }
                            if ui.button("🏥 Check Psiphon").clicked() {
                                self.check_psiphon_health();
                            }
                        }
                    });
                });

                if let Some((current, total)) = self.testing_progress {
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label(format!("Testing: {}/{}", current, total));
                        ui.add(egui::ProgressBar::new(current as f32 / total.max(1) as f32).desired_width(300.0));
                    });
                }
            });

        egui::SidePanel::left("sidebar")
            .default_width(360.0)
            .frame(egui::Frame::default().fill(egui::Color32::from_rgb(18, 20, 30)).inner_margin(15.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.active_tab, 0, "Main");
                    ui.selectable_value(&mut self.active_tab, 1, "Targets");
                    ui.selectable_value(&mut self.active_tab, 2, "Filters");
                    ui.selectable_value(&mut self.active_tab, 3, "Hot Pool");
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match self.active_tab {
                        0 => {
                            ui.heading(egui::RichText::new("🚀 Scraping Engine").color(egui::Color32::LIGHT_BLUE));
                            egui::ComboBox::from_label("Type").selected_text(match self.config.engine {
                                ScrapingEngine::RealBrowser => "Browser (Stealth)", ScrapingEngine::Reqwest => "API (Fast)",
                            }).show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.engine, ScrapingEngine::Reqwest, "API (Fast)");
                                ui.selectable_value(&mut self.config.engine, ScrapingEngine::RealBrowser, "Browser (Stealth)");
                            });
                            ui.add_space(10.0);

                            ui.heading(egui::RichText::new("🔗 Psiphon Upstream").color(egui::Color32::LIGHT_BLUE));
                            ui.horizontal(|ui| { ui.label("HTTP Host:"); ui.text_edit_singleline(&mut self.config.psiphon_http_host); });
                            ui.horizontal(|ui| { ui.label("HTTP Port:"); ui.add(egui::DragValue::new(&mut self.config.psiphon_http_port).clamp_range(1..=65535)); });
                            ui.add_space(15.0);

                            ui.heading(egui::RichText::new("⏱️ Scheduler").color(egui::Color32::LIGHT_BLUE));
                            ui.horizontal(|ui| { ui.label("Interval (Min):"); ui.add(egui::DragValue::new(&mut self.config.interval_minutes).clamp_range(5..=240)); });
                            ui.horizontal(|ui| { ui.label("Max Pages:"); ui.add(egui::DragValue::new(&mut self.config.max_pages_per_channel).clamp_range(1..=100)); });
                            ui.horizontal(|ui| { ui.label("Lookback Days:"); ui.add(egui::DragValue::new(&mut self.config.lookback_days).clamp_range(1..=30)); });
                            ui.add_space(15.0);

                            ui.heading(egui::RichText::new("🧪 Testing Config").color(egui::Color32::LIGHT_BLUE));
                            ui.checkbox(&mut self.config.test_configs_enabled, "Enable Two-Tier Testing");
                            ui.horizontal(|ui| {
                                ui.label("Tier 1 Timeout (s):");
                                ui.add(egui::DragValue::new(&mut self.config.tier1_timeout_seconds).clamp_range(5..=60));
                            });
                            ui.horizontal(|ui| {
                                ui.label("Tier 2 Timeout (s):");
                                ui.add(egui::DragValue::new(&mut self.config.tier2_timeout_seconds).clamp_range(30..=300));
                            });
                            ui.horizontal(|ui| {
                                ui.label("Concurrent Tests:");
                                ui.add(egui::DragValue::new(&mut self.config.max_concurrent_tests).clamp_range(1..=4));
                            });
                            ui.horizontal(|ui| {
                                ui.label("Min Success Bytes:");
                                ui.add(egui::DragValue::new(&mut self.config.min_bytes_for_success).clamp_range(10..=1000));
                            });
                            ui.add_space(15.0);

                            ui.heading(egui::RichText::new("💾 Output").color(egui::Color32::LIGHT_BLUE));
                            ui.checkbox(&mut self.config.output_new_only_enabled, "Extract New Configs Only");
                            ui.checkbox(&mut self.config.output_append_unique_enabled, "Backup All Unique");
                        }
                        1 => {
                            ui.heading(egui::RichText::new("📡 Target Channels").color(egui::Color32::LIGHT_BLUE));
                            ui.label("One channel per line (@channel or URL)");
                            ui.add_sized([ui.available_width(), ui.available_height() - 40.0], 
                                egui::TextEdit::multiline(&mut self.channels_text).font(egui::TextStyle::Monospace));
                        }
                        2 => {
                            ui.heading(egui::RichText::new("🎯 Protocols Filter").color(egui::Color32::LIGHT_BLUE));
                            for (name, rule) in &mut self.config.protocol_rules {
                                ui.horizontal(|ui| {
                                    ui.checkbox(&mut rule.enabled, name);
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.add(egui::DragValue::new(&mut rule.max_count).clamp_range(1..=1000));
                                    });
                                });
                            }
                        }
                        3 => {
                            ui.heading(egui::RichText::new("🔥 Hot Pool Status").color(egui::Color32::LIGHT_BLUE));
                            ui.label(format!("Cached working configs: {}", self.hot_pool_size));
                            ui.label("These are recycled without retesting to save bandwidth.");
                            ui.add_space(10.0);
                            if ui.button("🗑️ Clear Hot Pool").clicked() {
                                let _ = fs::remove_file(HOT_POOL_PATH);
                                self.hot_pool_size = 0;
                            }
                        }
                        _ => {}
                    }
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(egui::Color32::from_rgb(13, 15, 23)).inner_margin(15.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.group(|ui| { 
                        ui.label(egui::RichText::new("Extracted:").color(egui::Color32::GRAY)); 
                        ui.label(egui::RichText::new(self.total_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(30, 180, 120))); 
                    });
                    ui.group(|ui| { 
                        ui.label(egui::RichText::new("Working:").color(egui::Color32::GRAY)); 
                        ui.label(egui::RichText::new(self.working_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(255, 215, 0))); 
                    });
                    ui.group(|ui| { 
                        ui.label(egui::RichText::new("Hot Pool:").color(egui::Color32::GRAY)); 
                        ui.label(egui::RichText::new(self.hot_pool_size.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(100, 200, 255))); 
                    });
                    let proxy_color = match self.proxy_access_ok {
                        Some(true) => egui::Color32::from_rgb(30, 180, 120),
                        Some(false) => egui::Color32::from_rgb(220, 60, 60),
                        None => egui::Color32::from_rgb(200, 150, 40),
                    };
                    ui.group(|ui| { 
                        ui.label(egui::RichText::new("Network:").color(egui::Color32::GRAY)); 
                        ui.label(egui::RichText::new(&self.proxy_access_status).size(14.0).strong().color(proxy_color)); 
                    });
                });

                ui.horizontal_wrapped(|ui| {
                    ui.label("By Protocol: ");
                    for (proto, count) in &self.by_protocol {
                        ui.label(egui::RichText::new(format!("{}: {}", proto, count)).color(egui::Color32::LIGHT_GRAY).monospace());
                    }
                });

                ui.add_space(10.0);
                egui::Frame::none().fill(egui::Color32::from_rgb(8, 10, 15)).rounding(8.0).inner_margin(10.0).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(egui::RichText::new("Terminal Log").color(egui::Color32::WHITE));
                        if ui.button("Clear").clicked() { self.logs.clear(); }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new("Max 500 lines").color(egui::Color32::DARK_GRAY).small());
                        });
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false; 2]).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 5.0;
                        for log in self.logs.iter().rev().take(500).rev() {
                            let color = match log.level {
                                LogLevel::Debug => egui::Color32::from_rgb(100, 110, 130),
                                LogLevel::Info => egui::Color32::from_rgb(160, 180, 200),
                                LogLevel::Success => egui::Color32::from_rgb(60, 210, 130),
                                LogLevel::Warning => egui::Color32::from_rgb(240, 180, 50),
                                LogLevel::Error => egui::Color32::from_rgb(255, 90, 90),
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(format!("[{}]", log.time)).color(egui::Color32::from_rgb(80, 90, 110)).monospace().small());
                                ui.label(egui::RichText::new(&log.text).color(color).monospace());
                            });
                        }
                    });
                });
            });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}


// =============================================================
// NETWORK CORE
// =============================================================

fn fetch_html(url: &str, config: &AppConfig) -> Result<String> {
    match config.engine {
        ScrapingEngine::RealBrowser => fetch_with_safe_browser(url, config),
        ScrapingEngine::Reqwest => fetch_with_reqwest(url, config),
    }
}

fn fetch_with_safe_browser(url: &str, config: &AppConfig) -> Result<String> {
    let timeout_ms = 45000u64;
    let mut args = vec![
        "--headless=new".to_string(), "--dump-dom".to_string(), "--disable-gpu".to_string(),
        "--no-sandbox".to_string(), "--disable-dev-shm-usage".to_string(), "--mute-audio".to_string(),
        "--ignore-certificate-errors".to_string(), "--ignore-ssl-errors".to_string(), 
        "--blink-settings=imagesEnabled=false".to_string(),
        "--disable-javascript".to_string(),
        format!("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"),
    ];

    args.push(format!("--proxy-server=http://{}:{}", config.psiphon_http_host, config.psiphon_http_port));
    args.push(url.to_string());

    let browsers = ["msedge.exe", "chrome.exe", r#"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"#, r#"C:\Program Files\Google\Chrome\Application\chrome.exe"#];
    for browser in browsers {
        let mut child_proc = match Command::new(browser).args(&args).creation_flags(CREATE_NO_WINDOW).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
            Ok(child) => child,
            Err(_) => continue,
        };
        let start_time = Instant::now();
        let mut stdout_str = String::new();
        let mut is_completed = false;
        if let Some(mut stdout) = child_proc.stdout.take() {
            let mut buffer = [0u8; 2048];
            loop {
                if start_time.elapsed().as_millis() as u64 > timeout_ms { break; }
                match stdout.read(&mut buffer) {
                    Ok(0) => { is_completed = true; break; }
                    Ok(n) => { stdout_str.push_str(&String::from_utf8_lossy(&buffer[..n])); }
                    Err(_) => break,
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        if !is_completed { let _ = child_proc.kill(); return Err(anyhow::anyhow!("Browser timeout.")); }
        let _ = child_proc.wait();
        if stdout_str.len() > 50 { return Ok(stdout_str); }
    }
    anyhow::bail!("Failed to execute browser or empty response.")
}

fn fetch_with_reqwest(url: &str, config: &AppConfig) -> Result<String> {
    let proxy_url = format!("http://{}:{}", config.psiphon_http_host, config.psiphon_http_port);

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(25))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .danger_accept_invalid_certs(true)
        .proxy(reqwest::Proxy::all(&proxy_url)?)
        .build()?;

    let resp = client.get(url).send()?;
    if !resp.status().is_success() { anyhow::bail!("HTTP {}", resp.status()); }
    Ok(resp.text()?)
}

fn test_psiphon_alone(config: &AppConfig) -> Result<String> {
    let proxy_url = format!("http://{}:{}", config.psiphon_http_host, config.psiphon_http_port);
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .proxy(reqwest::Proxy::all(&proxy_url)?)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Try primary URL, fallback to secondary
    let test_urls = [
        "https://www.google.com/generate_204",
        "https://1.1.1.1/cdn-cgi/trace",
    ];
    
    for url in test_urls {
        if let Ok(resp) = client.get(url).send() {
            if resp.status().is_success() || resp.status().as_u16() == 204 {
                return Ok(format!("Connected ({})", url));
            }
        }
    }
    Err(anyhow::anyhow!("All test URLs failed"))
}

fn extract_endpoint(link: &str) -> Option<String> {
    if let Ok(url) = Url::parse(link) {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(match url.scheme() {
                "vless" | "vmess" | "trojan" => 443,
                "ss" => 8388,
                _ => 443,
            });
            return Some(format!("{}:{}", host, port));
        }
    }

    if link.starts_with("vmess://") {
        if let Some(b64) = link.strip_prefix("vmess://").and_then(|s| s.split('#').next()) {
            if let Ok(decoded) = STANDARD.decode(b64) {
                if let Ok(json_str) = String::from_utf8(decoded) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let host = v["add"].as_str()?;
                        let port = v["port"].as_str().unwrap_or("443");
                        return Some(format!("{}:{}", host, port));
                    }
                }
            }
        }
    }

    None
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    protocol: String,
    host: String,
    port: u16,
    uuid_or_pass: String,
    params: HashMap<String, String>,
    raw_link: String,
}

fn parse_config_link(link: &str) -> Option<ParsedConfig> {
    let proto = link.split("://").next()?.to_lowercase();

    match proto.as_str() {
        "vless" | "trojan" => parse_vless_trojan(link),
        "vmess" => parse_vmess(link),
        "ss" => parse_shadowsocks(link),
        _ => None,
    }
}

fn parse_vless_trojan(link: &str) -> Option<ParsedConfig> {
    let url = Url::parse(link).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port()?;
    let uuid_or_pass = url.username().to_string();

    let mut params = HashMap::new();
    for (k, v) in url.query_pairs() {
        params.insert(k.to_string(), v.to_string());
    }

    Some(ParsedConfig {
        protocol: link.split("://").next()?.to_string(),
        host,
        port,
        uuid_or_pass,
        params,
        raw_link: link.to_string(),
    })
}

fn parse_vmess(link: &str) -> Option<ParsedConfig> {
    let b64 = link.strip_prefix("vmess://")?.split('#').next()?.trim();
    let decoded = STANDARD.decode(b64).ok()?;
    let json_str = String::from_utf8(decoded).ok()?;
    let v = serde_json::from_str::<serde_json::Value>(&json_str).ok()?;

    Some(ParsedConfig {
        protocol: "vmess".to_string(),
        host: v["add"].as_str()?.to_string(),
        port: v["port"].as_str()?.parse().ok()?,
        uuid_or_pass: v["id"].as_str()?.to_string(),
        params: HashMap::new(),
        raw_link: link.to_string(),
    })
}

fn parse_shadowsocks(link: &str) -> Option<ParsedConfig> {
    let after_ss = link.strip_prefix("ss://")?;

    if let Some((b64_part, host_port)) = after_ss.split_once('@') {
        if let Ok(decoded) = STANDARD.decode(b64_part) {
            let decoded_str = String::from_utf8_lossy(&decoded);
            if let Some((method, password)) = decoded_str.split_once(':') {
                if let Some((host, port_str)) = host_port.split_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let mut params = HashMap::new();
                        params.insert("method".to_string(), method.to_string());
                        return Some(ParsedConfig {
                            protocol: "ss".to_string(),
                            host: host.to_string(),
                            port,
                            uuid_or_pass: password.to_string(),
                            params,
                            raw_link: link.to_string(),
                        });
                    }
                }
            }
        }
    }

    let url = Url::parse(link).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port()?;
    let userinfo = url.username();
    let (method, password) = userinfo.split_once(':')?;

    let mut params = HashMap::new();
    params.insert("method".to_string(), method.to_string());

    Some(ParsedConfig {
        protocol: "ss".to_string(),
        host,
        port,
        uuid_or_pass: password.to_string(),
        params,
        raw_link: link.to_string(),
    })
}


// =============================================================
// XRAY CONFIG GENERATION
// =============================================================

fn generate_xray_config(parsed: &ParsedConfig, socks_port: u16, psiphon_host: &str, psiphon_port: u16) -> Option<String> {
    let outbound = match parsed.protocol.as_str() {
        "vless" => build_vless_outbound(parsed),
        "trojan" => build_trojan_outbound(parsed),
        "vmess" => build_vmess_outbound(parsed),
        "ss" => build_ss_outbound(parsed),
        _ => return None,
    }?;

    let psiphon_upstream = json!({
        "tag": "psiphon-out",
        "protocol": "http",
        "settings": {
            "servers": [{
                "address": psiphon_host,
                "port": psiphon_port
            }]
        }
    });

    let config = json!({
        "log": {
            "loglevel": "error",
            "access": "",
            "error": ""
        },
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "udp": true,
                "auth": "noauth"
            },
            "sniffing": {
                "enabled": false
            }
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": parsed.protocol.clone(),
                "settings": outbound,
                "proxySettings": {
                    "tag": "psiphon-out"
                },
                "streamSettings": build_stream_settings(parsed)
            },
            psiphon_upstream,
            {
                "tag": "direct",
                "protocol": "freedom"
            },
            {
                "tag": "block",
                "protocol": "blackhole"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": []
        }
    });

    Some(serde_json::to_string_pretty(&config).unwrap())
}

fn build_vless_outbound(parsed: &ParsedConfig) -> Option<serde_json::Value> {
    let flow = parsed.params.get("flow").map(|s| s.as_str()).unwrap_or("");
    let encryption = parsed.params.get("encryption").map(|s| s.as_str()).unwrap_or("none");

    Some(json!({
        "vnext": [{
            "address": parsed.host,
            "port": parsed.port,
            "users": [{
                "id": parsed.uuid_or_pass,
                "encryption": encryption,
                "flow": flow
            }]
        }]
    }))
}

fn build_trojan_outbound(parsed: &ParsedConfig) -> Option<serde_json::Value> {
    Some(json!({
        "servers": [{
            "address": parsed.host,
            "port": parsed.port,
            "password": parsed.uuid_or_pass
        }]
    }))
}

fn build_vmess_outbound(parsed: &ParsedConfig) -> Option<serde_json::Value> {
    let aid: u16 = parsed.params.get("aid").and_then(|s| s.parse().ok()).unwrap_or(0);

    Some(json!({
        "vnext": [{
            "address": parsed.host,
            "port": parsed.port,
            "users": [{
                "id": parsed.uuid_or_pass,
                "alterId": aid,
                "security": "auto"
            }]
        }]
    }))
}

fn build_ss_outbound(parsed: &ParsedConfig) -> Option<serde_json::Value> {
    let method = parsed.params.get("method").map(|s| s.as_str()).unwrap_or("aes-256-gcm");

    Some(json!({
        "servers": [{
            "address": parsed.host,
            "port": parsed.port,
            "method": method,
            "password": parsed.uuid_or_pass
        }]
    }))
}

fn build_stream_settings(parsed: &ParsedConfig) -> serde_json::Value {
    let network = parsed.params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let security = parsed.params.get("security").map(|s| s.as_str()).unwrap_or("none");
    let sni = parsed.params.get("sni").map(|s| s.to_string()).unwrap_or_else(|| parsed.host.clone());
    let path = parsed.params.get("path").map(|s| s.to_string()).unwrap_or_else(|| "/".to_string());
    let host = parsed.params.get("host").map(|s| s.to_string()).unwrap_or_else(|| parsed.host.clone());

    let mut settings = json!({
        "network": network,
        "security": security
    });

    if security == "tls" {
        settings["tlsSettings"] = json!({
            "serverName": sni,
            "allowInsecure": true,
            "alpn": ["h2", "http/1.1"]
        });
    }

    if security == "reality" {
        let pbk = parsed.params.get("pbk").map(|s| s.to_string()).unwrap_or_default();
        let sid = parsed.params.get("sid").map(|s| s.to_string()).unwrap_or_default();
        settings["realitySettings"] = json!({
            "serverName": sni,
            "publicKey": pbk,
            "shortId": sid,
            "fingerprint": "chrome",
            "spiderX": ""
        });
    }

    if network == "ws" {
        settings["wsSettings"] = json!({
            "path": path,
            "headers": {
                "Host": host
            }
        });
    }

    if network == "grpc" {
        settings["grpcSettings"] = json!({
            "serviceName": path.trim_start_matches('/'),
            "multiMode": false
        });
    }

    settings
}

// =============================================================
// TWO-TIER TESTING SYSTEM
// =============================================================

fn tier1_quick_test(parsed: &ParsedConfig, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", parsed.host, parsed.port);
    match TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(timeout_secs)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn tier2_full_test(
    parsed: &ParsedConfig, 
    socks_port: u16, 
    config: &AppConfig,
    tx: &Sender<AppEvent>
) -> TestResult {
    let _start_time = Instant::now();
    let endpoint = format!("{}:{}", parsed.host, parsed.port);

    let xray_json = match generate_xray_config(
        parsed, 
        socks_port, 
        &config.psiphon_http_host, 
        config.psiphon_http_port
    ) {
        Some(c) => c,
        None => {
            return TestResult {
                link: parsed.raw_link.clone(),
                endpoint: endpoint.clone(),
                success: false,
                connect_time_secs: 0.0,
                bytes_transferred: 0,
                error: Some("Failed to generate Xray config".to_string()),
            };
        }
    };

    let temp_file = format!("temp_xray_{}.json", socks_port);
    if let Err(e) = fs::write(&temp_file, xray_json) {
        return TestResult {
            link: parsed.raw_link.clone(),
            endpoint: endpoint.clone(),
            success: false,
            connect_time_secs: 0.0,
            bytes_transferred: 0,
            error: Some(format!("Failed to write config: {}", e)),
        };
    }

    let mut child = match Command::new("xray.exe")
        .args(&["run", "-c", &temp_file])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_file(&temp_file);
            return TestResult {
                link: parsed.raw_link.clone(),
                endpoint: endpoint.clone(),
                success: false,
                connect_time_secs: 0.0,
                bytes_transferred: 0,
                error: Some(format!("Failed to start xray: {}", e)),
            };
        }
    };

    thread::sleep(Duration::from_secs(5));

    let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port);

    // Build client with proper error handling for proxy
    let client_result = ClientBuilder::new()
        .timeout(Duration::from_secs(config.tier2_timeout_seconds))
        .danger_accept_invalid_certs(true);

    let client = match reqwest::Proxy::all(&proxy_url) {
        Ok(proxy) => client_result.proxy(proxy).build(),
        Err(_) => client_result.build(),
    };

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            let _ = child.kill();
            let _ = fs::remove_file(&temp_file);
            return TestResult {
                link: parsed.raw_link.clone(),
                endpoint: endpoint.clone(),
                success: false,
                connect_time_secs: 0.0,
                bytes_transferred: 0,
                error: Some(format!("Failed to build HTTP client: {}", e)),
            };
        }
    };

    let test_start = Instant::now();
    let result = client.get(PSIPHON_TEST_URL).send();
    let connect_time = test_start.elapsed().as_secs_f64();

    let (success, bytes_transferred, error) = match result {
        Ok(resp) => {
            let bytes = resp.text().unwrap_or_default().len();
            if bytes >= config.min_bytes_for_success {
                (true, bytes, None)
            } else {
                (false, bytes, Some(format!("Only received {} bytes, min required {}", bytes, config.min_bytes_for_success)))
            }
        }
        Err(e) => (false, 0, Some(e.to_string())),
    };

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&temp_file);

    TestResult {
        link: parsed.raw_link.clone(),
        endpoint,
        success,
        connect_time_secs: connect_time,
        bytes_transferred,
        error,
    }
}

fn test_single_config(
    link: &str,
    socks_port: u16,
    config: &AppConfig,
    hot_pool: &HotPool,
    history: &SentHistory,
    tx: &Sender<AppEvent>,
) -> Option<TestResult> {
    if history.was_tested_recently(link, 30) {
        let _ = tx.send(AppEvent::Log(LogLevel::Debug, format!("⏭️ Skipping recently tested: {}", link)));
        return None;
    }

    let parsed = match parse_config_link(link) {
        Some(p) => p,
        None => {
            let _ = tx.send(AppEvent::Log(LogLevel::Warning, format!("⚠️ Failed to parse: {}", link)));
            return None;
        }
    };

    let endpoint = format!("{}:{}", parsed.host, parsed.port);

    if hot_pool.is_endpoint_tested_recently(&endpoint, 60) {
        let _ = tx.send(AppEvent::Log(LogLevel::Info, format!("📌 Endpoint {} recently verified, marking as working", endpoint)));
        return Some(TestResult {
            link: link.to_string(),
            endpoint,
            success: true,
            connect_time_secs: 0.0,
            bytes_transferred: 0,
            error: None,
        });
    }

    let _ = tx.send(AppEvent::Log(LogLevel::Debug, format!("🔍 Tier 1 testing: {}", link)));
    if !tier1_quick_test(&parsed, config.tier1_timeout_seconds) {
        let _ = tx.send(AppEvent::Log(LogLevel::Debug, format!("❌ Tier 1 failed: {}", link)));
        return Some(TestResult {
            link: link.to_string(),
            endpoint,
            success: false,
            connect_time_secs: 0.0,
            bytes_transferred: 0,
            error: Some("Tier 1: TCP connection failed".to_string()),
        });
    }

    let _ = tx.send(AppEvent::Log(LogLevel::Info, format!("🧪 Tier 2 testing: {}", link)));
    let result = tier2_full_test(&parsed, socks_port, config, tx);

    let status = if result.success { "✅ WORKING" } else { "❌ FAILED" };
    let _ = tx.send(AppEvent::Log(
        if result.success { LogLevel::Success } else { LogLevel::Warning },
        format!("{} {} ({} bytes, {:.1}s)", status, link, result.bytes_transferred, result.connect_time_secs)
    ));

    Some(result)
}


// =============================================================
// CONCURRENT TESTING WITH BANDWIDTH MANAGEMENT
// =============================================================

fn test_configs_batch(
    links: &[String],
    config: &AppConfig,
    hot_pool: &mut HotPool,
    history: &mut SentHistory,
    tx: &Sender<AppEvent>,
) -> Vec<TestResult> {
    if links.is_empty() { return vec![]; }

    let max_concurrent = config.max_concurrent_tests.clamp(1, 4);
    let base_port = 20000u16;
    let mut results = vec![];

    let _ = tx.send(AppEvent::Log(LogLevel::Info, format!("🧪 Starting batch test: {} configs, max {} concurrent", links.len(), max_concurrent)));

    for (chunk_idx, chunk) in links.chunks(max_concurrent).enumerate() {
        let chunk_start = chunk_idx * max_concurrent;

        let _ = tx.send(AppEvent::TestingProgress { 
            current: chunk_start, 
            total: links.len() 
        });

        let mut handles = vec![];
        for (i, link) in chunk.iter().enumerate() {
            let link_for_thread = link.clone();
            let config = config.clone();
            let hot_pool = hot_pool.clone();
            let history = history.clone();
            let tx = tx.clone();
            let port = base_port + (chunk_start + i) as u16;

            let handle = thread::spawn(move || {
                test_single_config(&link_for_thread, port, &config, &hot_pool, &history, &tx)
            });
            handles.push((link.clone(), handle));
        }

        for (link, handle) in handles {
            match handle.join() {
                Ok(Some(result)) => {
                    history.mark_tested(&link);
                    hot_pool.update_or_add(&link, &result.endpoint, result.success, result.connect_time_secs);
                    results.push(result);
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = tx.send(AppEvent::Log(LogLevel::Error, format!("💥 Thread panic for {}: {:?}", link, e)));
                }
            }
        }

        thread::sleep(Duration::from_secs(3));
    }

    let _ = tx.send(AppEvent::TestingProgress { current: links.len(), total: links.len() });
    results
}

fn write_working_configs(results: &[TestResult], output_dir: &str) -> Result<usize> {
    fs::create_dir_all(output_dir)?;

    let mut by_protocol: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for result in results.iter().filter(|r| r.success) {
        if let Some(proto) = result.link.split("://").next() {
            by_protocol.entry(proto.to_string()).or_default().insert(result.link.clone());
        }
    }

    let mut total_written = 0;

    for (proto, links) in &by_protocol {
        let path = Path::new(output_dir).join(format!("working_{}.txt", proto));
        let mut existing = read_existing_set(&path).unwrap_or_default();
        existing.extend(links.iter().cloned());

        let lines: Vec<String> = existing.into_iter().collect();
        fs::write(&path, lines.join("\n"))?;
        total_written += links.len();
    }

    let mixed_path = Path::new(output_dir).join("working_mixed.txt");
    let mut mixed_existing = read_existing_set(&mixed_path).unwrap_or_default();
    for result in results.iter().filter(|r| r.success) {
        mixed_existing.insert(result.link.clone());
    }
    let mixed_lines: Vec<String> = mixed_existing.into_iter().collect();
    fs::write(mixed_path, mixed_lines.join("\n"))?;

    Ok(total_written)
}

fn write_new_only(output_dir: &str, configs: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let mut all_links = vec![];
    for (proto, links) in configs {
        if links.is_empty() { continue; }
        let lines: Vec<String> = links.iter().cloned().collect();
        fs::write(Path::new(output_dir).join(format!("{}.txt", proto)), lines.join("\n"))?;
        all_links.extend(lines);
    }

    if !all_links.is_empty() {
        fs::write(Path::new(output_dir).join("mixed.txt"), all_links.join("\n"))?;
    }

    Ok(())
}

fn write_append_unique(output_dir: &str, configs: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    for (proto, links) in configs {
        if links.is_empty() { continue; }
        let path = Path::new(output_dir).join(format!("{}.txt", proto));
        let mut existing = read_existing_set(&path).unwrap_or_default();
        existing.extend(links.iter().cloned());
        let lines: Vec<String> = existing.into_iter().collect();
        fs::write(&path, lines.join("\n"))?;
    }

    Ok(())
}

fn read_existing_set(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() { return Ok(BTreeSet::new()); }
    let raw = fs::read_to_string(path)?;
    Ok(raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(ToOwned::to_owned).collect())
}

fn run_worker(
    config: AppConfig, 
    channels_raw: String, 
    stop: Arc<AtomicBool>, 
    tx: Sender<AppEvent>
) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    let regex_pattern = r#"(?i)(vless|vmess|trojan|ss)://[^\s<>`"'\\]+"#;
    let regex = Regex::new(regex_pattern).unwrap();
    let date_regex = Regex::new(r#"<time datetime="([^"]+)""#).unwrap();

    let mut history = SentHistory::load();
    let mut hot_pool = HotPool::load();
    let threshold_date = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));

    log_worker(&tx, LogLevel::Info, format!(
        "🚀 Worker Started | Channels: {} | Psiphon: {}:{} | Hot Pool: {} configs",
        channels.len(), config.psiphon_http_host, config.psiphon_http_port, hot_pool.entries.len()
    ));

    loop {
        if stop.load(Ordering::SeqCst) { break; }

        history.prune(config.lookback_days);

        match test_psiphon_alone(&config) {
            Ok(_) => {
                let _ = tx.send(AppEvent::PsiphonHealth { ok: true, detail: "Healthy".to_string() });
            }
            Err(e) => {
                let _ = tx.send(AppEvent::PsiphonHealth { ok: false, detail: e.to_string() });
                log_worker(&tx, LogLevel::Error, format!("🚨 Psiphon not working! Waiting 60s..."));
                for _ in 0..60 {
                    if stop.load(Ordering::SeqCst) { break; }
                    thread::sleep(Duration::from_secs(1));
                }
                continue;
            }
        }

        log_worker(&tx, LogLevel::Info, "📡 Starting scraping phase...".to_string());
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total_scraped = 0;

        for channel in &channels {
            if stop.load(Ordering::SeqCst) { break; }
            log_worker(&tx, LogLevel::Info, format!("📡 Scanning @{}...", channel));

            let mut before: Option<String> = None;
            let mut channel_new = 0;

            for page in 1..=config.max_pages_per_channel {
                if stop.load(Ordering::SeqCst) { break; }

                let mut url = format!("https://t.me/s/{}", channel);
                if let Some(ref id) = before { url.push_str(&format!("?before={}", id)); }

                match fetch_html(&url, &config) {
                    Ok(html) => {
                        let decoded = html.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
                        let mut found_in_page = 0;
                        let mut next_before = None;

                        let next_regex = Regex::new(r#"data-post="[^/]+/(\d+)""#).unwrap();
                        for cap in next_regex.captures_iter(&decoded) { next_before = Some(cap[1].to_string()); }

                        let blocks: Vec<&str> = decoded.split("tgme_widget_message ").collect();

                        for block in blocks {
                            let mut is_recent = true;
                            if let Some(caps) = date_regex.captures(block) {
                                if let Ok(parsed_date) = DateTime::parse_from_rfc3339(&caps[1]) {
                                    if parsed_date.with_timezone(&Utc) < threshold_date {
                                        is_recent = false;
                                    }
                                }
                            }

                            if is_recent {
                                for m in regex.find_iter(block) {
                                    let clean = m.as_str().trim_end_matches(&['(', ')', '[', ']', ' ', '!', '.', ',', ';', '\'', '"', '<', '>'][..]);
                                    if let Some(proto) = clean.split("://").next() {
                                        let proto_lower = proto.to_lowercase();
                                        if config.protocol_rules.get(&proto_lower).map_or(false, |r| r.enabled) {
                                            if !history.sent_at.contains_key(clean) {
                                                gathered.entry(proto_lower).or_default().insert(clean.to_string());
                                                found_in_page += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if found_in_page > 0 {
                            log_worker(&tx, LogLevel::Success, format!("  ✔️ Page {}: {} new configs", page, found_in_page));
                            channel_new += found_in_page;
                        } else if next_before.is_none() {
                            break;
                        }

                        before = next_before;
                    }
                    Err(e) => {
                        log_worker(&tx, LogLevel::Warning, format!("  ⚠️ Page {} failed: {}", page, e));
                    }
                }

                thread::sleep(Duration::from_secs(2));
            }

            total_scraped += channel_new;
        }

        for (proto, links) in gathered.iter_mut() {
            if let Some(rule) = config.protocol_rules.get(proto) {
                if links.len() > rule.max_count {
                    *links = links.iter().take(rule.max_count).cloned().collect();
                }
            }
        }

        log_worker(&tx, LogLevel::Info, format!("📊 Scraped {} unique configs across all protocols", total_scraped));

        let mut new_configs: Vec<String> = vec![];
        for (_, links) in &gathered {
            for link in links {
                if !history.sent_at.contains_key(link) && !history.was_tested_recently(link, 60) {
                    new_configs.push(link.clone());
                    history.sent_at.insert(link.clone(), Utc::now());
                }
            }
        }

        if new_configs.len() > 100 {
            log_worker(&tx, LogLevel::Warning, format!("⚠️ Found {} configs, limiting to 100 for this cycle", new_configs.len()));
            new_configs.truncate(100);
        }

        if config.output_new_only_enabled && !gathered.is_empty() {
            let _ = write_new_only(OUTPUT_NEW_DIR, &gathered);
        }
        if config.output_append_unique_enabled && !gathered.is_empty() {
            let _ = write_append_unique(OUTPUT_APPEND_DIR, &gathered);
        }

        let mut working_count = 0;
        if config.test_configs_enabled && !new_configs.is_empty() {
            log_worker(&tx, LogLevel::Info, format!("🧪 Starting testing phase for {} configs...", new_configs.len()));

            let results = test_configs_batch(&new_configs, &config, &mut hot_pool, &mut history, &tx);

            working_count = results.iter().filter(|r| r.success).count();

            let _ = write_working_configs(&results, OUTPUT_WORKING_DIR);

            let _ = hot_pool.save();

            log_worker(&tx, LogLevel::Success, format!("🏆 Testing complete: {}/{} working", working_count, new_configs.len()));
        }

        let working_from_pool = hot_pool.get_working(120);
        if !working_from_pool.is_empty() {
            log_worker(&tx, LogLevel::Info, format!("🔥 Adding {} configs from hot pool", working_from_pool.len()));
            let pool_results: Vec<TestResult> = working_from_pool.iter().map(|e| TestResult {
                link: e.link.clone(),
                endpoint: e.endpoint.clone(),
                success: true,
                connect_time_secs: e.avg_connect_time_secs,
                bytes_transferred: 1000,
                error: None,
            }).collect();
            let _ = write_working_configs(&pool_results, OUTPUT_WORKING_DIR);
            working_count += working_from_pool.len();
        }

        let mut by_protocol: BTreeMap<String, usize> = BTreeMap::new();
        for link in &new_configs {
            if let Some(proto) = link.split("://").next() {
                *by_protocol.entry(proto.to_string()).or_insert(0) += 1;
            }
        }

        let _ = tx.send(AppEvent::Stats { 
            total: new_configs.len(), 
            working: working_count, 
            by_protocol,
            hot_pool_size: hot_pool.entries.len(),
        });

        let _ = history.save();

        log_worker(&tx, LogLevel::Info, format!("💤 Cycle complete. Sleeping {} minutes...", config.interval_minutes));
        for _ in 0..(config.interval_minutes * 60) {
            if stop.load(Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}

fn log_worker(tx: &Sender<AppEvent>, level: LogLevel, text: String) {
    let _ = tx.send(AppEvent::Log(level, text));
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
