#![windows_subsystem = "windows"]

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use eframe::egui;
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use url::Url;

const APP_CONFIG_PATH: &str = "config/app_config.toml";
const CHANNELS_PATH: &str = "config/channels.txt";
const OUTPUT_NEW_DIR: &str = "output/new_only";
const OUTPUT_APPEND_DIR: &str = "output/append_unique";
const OUTPUT_TESTED_DIR: &str = "output/tested_working";
const HISTORY_PATH: &str = "output/sent_history.json";
const CREATE_NO_WINDOW: u32 = 0x08000000;

const DEFAULT_PROTOCOLS: [&str; 27] =[
    "vmess", "vless", "trojan", "ss", "ssr", "tuic", "hysteria", "hysteria2", "hy2", "juicity",
    "snell", "anytls", "ssh", "wireguard", "wg", "warp", "socks", "socks4", "socks5", "tg", "dns",
    "nm-dns", "nm-vless", "slipnet-enc", "slipnet", "slipstream", "dnstt",
];

fn generate_icon() -> egui::IconData {
    let width = 32;
    let height = 32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    for _y in 0..height {
        for _x in 0..width {
            rgba.push(30);  rgba.push(160); rgba.push(100); rgba.push(255);
        }
    }
    egui::IconData { rgba, width, height }
}

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1050.0, 700.0])
            .with_min_inner_size([850.0, 550.0])
            .with_icon(generate_icon()),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "⚡ Config Collector Pro (Windows Edition)",
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
    test_configs_enabled: bool,
    protocol_rules: BTreeMap<String, ProtocolRule>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut protocol_rules = BTreeMap::new();
        for p in DEFAULT_PROTOCOLS {
            protocol_rules.insert(
                p.to_string(),
                ProtocolRule { enabled: true, max_count: 500 },
            );
        }
        Self {
            interval_minutes: 15,
            max_pages_per_channel: 5,
            lookback_days: 2,
            engine: ScrapingEngine::Reqwest, // Using Reqwest by default as it worked for you
            proxy_type: ProxyType::Http,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 10880, // Pointing to Psiphon by default
            performance: PerformanceProfile::MediumPC,
            ignore_ssl_errors: true,
            remote_dns: true,
            output_new_only_enabled: true,
            output_append_unique_enabled: true,
            test_configs_enabled: true,
            protocol_rules,
        }
    }
}

impl AppConfig {
    fn load_or_create() -> Self {
        if let Ok(raw) = fs::read_to_string(APP_CONFIG_PATH) {
            if let Ok(mut cfg) = toml::from_str::<Self>(&raw) {
                for p in DEFAULT_PROTOCOLS {
                    cfg.protocol_rules.entry(p.to_string()).or_insert(ProtocolRule { enabled: true, max_count: 500 });
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
struct SentHistory { sent_at: BTreeMap<String, DateTime<Utc>> }

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
    }
    fn save(&self) -> Result<()> {
        if let Some(parent) = Path::new(HISTORY_PATH).parent() { fs::create_dir_all(parent)?; }
        fs::write(HISTORY_PATH, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum LogLevel { Debug, Info, Success, Warning, Error }

#[derive(Clone, Debug)]
struct LogMessage { time: String, level: LogLevel, text: String }

#[derive(Clone, Debug)]
enum AppEvent {
    Log(LogLevel, String),
    Stats { total: usize, working: usize, by_protocol: BTreeMap<String, usize> },
    PingResult { ok: bool, detail: String },
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
    working_configs: usize,
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
            channels_text: fs::read_to_string(CHANNELS_PATH).unwrap_or_else(|_| "IranProxyPlus\nfilembad".to_string()),
            active_tab: 0,
            proxy_access_status: "Awaiting test...".to_string(),
            proxy_access_ok: None,
            logs: vec![LogMessage { time: Local::now().format("%H:%M:%S").to_string(), level: LogLevel::Info, text: "🖥️ System Boot: Engine & Xray Anti-Hang mechanisms loaded.".to_string() }],
            total_configs: 0,
            working_configs: 0,
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

    fn start(&mut self) {
        if self.running { return; }
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
                let _ = tx.send(AppEvent::Log(LogLevel::Error, format!("🔥 CRASH: {}", err)));
            }
            let _ = tx.send(AppEvent::WorkerStopped);
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.add_log(LogLevel::Warning, "🛑 Stop signal sent. Wrapping up current task safely...".to_string());
    }

    fn add_log(&mut self, level: LogLevel, text: String) {
        self.logs.push(LogMessage { time: Local::now().format("%H:%M:%S").to_string(), level, text });
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::Log(level, msg) => self.add_log(level, msg),
                AppEvent::Stats { total, working, by_protocol } => {
                    self.total_configs += total;
                    self.working_configs += working;
                    self.by_protocol = by_protocol;
                }
                AppEvent::PingResult { ok, detail } => {
                    self.proxy_access_ok = Some(ok);
                    self.proxy_access_status = detail;
                }
                AppEvent::WorkerStopped => {
                    self.running = false;
                    self.add_log(LogLevel::Warning, "💤 Worker thread successfully terminated.".to_string());
                }
            }
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = Command::new("cmd").args(&["/C", "taskkill /F /IM msedge.exe /FI \"WINDOWTITLE eq \""]).creation_flags(CREATE_NO_WINDOW).output();
        let _ = Command::new("cmd").args(&["/C", "taskkill /F /IM chrome.exe /FI \"WINDOWTITLE eq \""]).creation_flags(CREATE_NO_WINDOW).output();
        let _ = Command::new("cmd").args(&["/C", "taskkill /F /IM xray.exe /FI \"WINDOWTITLE eq \""]).creation_flags(CREATE_NO_WINDOW).output();
    }
}

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

        egui::TopBottomPanel::top("header").exact_height(75.0).frame(egui::Frame::default().fill(egui::Color32::from_rgb(18, 20, 30)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("⚡ Config Collector & Tester").size(26.0).strong().color(egui::Color32::from_rgb(230, 240, 255)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.running {
                        if ui.add(egui::Button::new(egui::RichText::new("🛑 Stop Process").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(200, 40, 40))).clicked() { self.stop(); }
                        ui.spinner();
                    } else {
                        if ui.add(egui::Button::new(egui::RichText::new("▶ Start Engine").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(30, 160, 100))).clicked() { self.start(); }
                        if ui.button("🔄 Test Network").clicked() { self.test_connection(); }
                    }
                });
            });
        });

        egui::SidePanel::left("sidebar").default_width(340.0).frame(egui::Frame::default().fill(egui::Color32::from_rgb(18, 20, 30)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, 0, "Main");
                ui.selectable_value(&mut self.active_tab, 1, "Targets");
                ui.selectable_value(&mut self.active_tab, 2, "Filters");
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    0 => {
                        ui.heading(egui::RichText::new("🚀 Scraping Engine").color(egui::Color32::LIGHT_BLUE));
                        egui::ComboBox::from_label("Type").selected_text(match self.config.engine {
                            ScrapingEngine::RealBrowser => "Browser (Stealth/Bypass)",
                            ScrapingEngine::Reqwest => "API (Fast/Unsafe)",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.config.engine, ScrapingEngine::Reqwest, "API (Fast/Unsafe)");
                            ui.selectable_value(&mut self.config.engine, ScrapingEngine::RealBrowser, "Browser (Stealth/Bypass)");
                        });

                        ui.add_space(10.0);
                        ui.heading(egui::RichText::new("💻 Performance Profile").color(egui::Color32::GOLD));
                        egui::ComboBox::from_label("PC Power").selected_text(match self.config.performance {
                            PerformanceProfile::WeakPC => "Weak PC (Safe/Slow)",
                            PerformanceProfile::MediumPC => "Medium PC (Balanced)",
                            PerformanceProfile::StrongPC => "Strong PC (Fast/Heavy)",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.config.performance, PerformanceProfile::WeakPC, "Weak PC (Safe/Slow)");
                            ui.selectable_value(&mut self.config.performance, PerformanceProfile::MediumPC, "Medium PC (Balanced)");
                            ui.selectable_value(&mut self.config.performance, PerformanceProfile::StrongPC, "Strong PC (Fast/Heavy)");
                        });

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("🌐 Network & Proxy").color(egui::Color32::LIGHT_BLUE));
                        egui::ComboBox::from_label("Proxy").selected_text(match self.config.proxy_type {
                            ProxyType::None => "Direct", ProxyType::System => "System Auto", ProxyType::Http => "HTTP", ProxyType::Socks5 => "SOCKS5",
                        }).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.config.proxy_type, ProxyType::Http, "HTTP");
                            ui.selectable_value(&mut self.config.proxy_type, ProxyType::Socks5, "SOCKS5");
                            ui.selectable_value(&mut self.config.proxy_type, ProxyType::System, "System Auto");
                            ui.selectable_value(&mut self.config.proxy_type, ProxyType::None, "Direct");
                        });

                        if matches!(self.config.proxy_type, ProxyType::Http | ProxyType::Socks5) {
                            ui.horizontal(|ui| { ui.label("IP:"); ui.text_edit_singleline(&mut self.config.proxy_host); });
                            ui.horizontal(|ui| { ui.label("Port:"); ui.add(egui::DragValue::new(&mut self.config.proxy_port).range(1..=65535)); });
                        }
                        ui.checkbox(&mut self.config.ignore_ssl_errors, "Bypass SSL/TLS Filter (For VPNs)");

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("⏱️ Scheduler & Dates").color(egui::Color32::LIGHT_BLUE));
                        ui.horizontal(|ui| { ui.label("Interval (Min):"); ui.add(egui::DragValue::new(&mut self.config.interval_minutes).range(1..=240)); });
                        ui.horizontal(|ui| { ui.label("Max Pages:"); ui.add(egui::DragValue::new(&mut self.config.max_pages_per_channel).range(1..=100)); });
                        ui.horizontal(|ui| { ui.label("Lookback Days:"); ui.add(egui::DragValue::new(&mut self.config.lookback_days).range(1..=30)); });

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("💾 Output & Testing Settings").color(egui::Color32::LIGHT_BLUE));
                        ui.checkbox(&mut self.config.output_new_only_enabled, "Extract New Configs Only");
                        ui.checkbox(&mut self.config.output_append_unique_enabled, "Backup All Unique Configs");
                        ui.checkbox(&mut self.config.test_configs_enabled, "✅ Enable Isolated Xray Tester (Tests VLESS configs)");
                    }
                    1 => {
                        ui.heading(egui::RichText::new("📡 Target Channels").color(egui::Color32::LIGHT_BLUE));
                        ui.add_sized([ui.available_width(), ui.available_height() - 20.0], egui::TextEdit::multiline(&mut self.channels_text).font(egui::TextStyle::Monospace));
                    }
                    2 => {
                        ui.heading(egui::RichText::new("🎯 Protocols Filter").color(egui::Color32::LIGHT_BLUE));
                        for (name, rule) in &mut self.config.protocol_rules {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut rule.enabled, name);
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.add(egui::DragValue::new(&mut rule.max_count).range(1..=50000)); });
                            });
                        }
                    }
                    _ => {}
                }
            });
        });

        egui::CentralPanel::default().frame(egui::Frame::default().fill(egui::Color32::from_rgb(13, 15, 23)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Extracted Total:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(self.total_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(30, 180, 120)));
                });
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Tested & Working:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(self.working_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(255, 215, 0)));
                });
                let proxy_color = match self.proxy_access_ok { Some(true) => egui::Color32::from_rgb(30, 180, 120), Some(false) => egui::Color32::from_rgb(220, 60, 60), None => egui::Color32::from_rgb(200, 150, 40) };
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Connection:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(&self.proxy_access_status).size(14.0).strong().color(proxy_color));
                });
            });

            ui.add_space(10.0);
            egui::Frame::none().fill(egui::Color32::from_rgb(8, 10, 15)).rounding(8.0).inner_margin(10.0).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(egui::RichText::new("Terminal Log").color(egui::Color32::WHITE));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Clear").clicked() { self.logs.clear(); }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false; 2]).show(ui, |ui| {
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
// Network Core (Updated Timeouts & Flags)
// =============================================================

fn get_performance_settings(profile: &PerformanceProfile) -> (Duration, u64) {
    match profile {
        // Significantly increased timeouts for DPI / Psiphon environments
        PerformanceProfile::WeakPC => (Duration::from_secs(5), 60000),
        PerformanceProfile::MediumPC => (Duration::from_secs(3), 45000),
        PerformanceProfile::StrongPC => (Duration::from_secs(2), 30000),
    }
}

fn fetch_html(url: &str, config: &AppConfig) -> Result<String> {
    match config.engine {
        ScrapingEngine::RealBrowser => fetch_with_safe_browser(url, config),
        ScrapingEngine::Reqwest => fetch_with_reqwest(url, config),
    }
}

fn fetch_with_safe_browser(url: &str, config: &AppConfig) -> Result<String> {
    let (_, timeout_ms) = get_performance_settings(&config.performance);

    let mut args = vec![
        "--headless=new".to_string(),
        "--dump-dom".to_string(),
        "--disable-gpu".to_string(),
        "--no-sandbox".to_string(),
        "--disable-dev-shm-usage".to_string(),
        "--disable-extensions".to_string(),
        "--mute-audio".to_string(),
        "--ignore-certificate-errors".to_string(),
        "--ignore-ssl-errors".to_string(),
        "--blink-settings=imagesEnabled=false".to_string(), // Crucial for bandwidth!
        "--window-size=1920,1080".to_string(),
        format!("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    ];

    match config.proxy_type {
        ProxyType::System => {}
        ProxyType::None => { args.push("--no-proxy-server".to_string()); }
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = if config.proxy_type == ProxyType::Socks5 { "socks5" } else { "http" };
            let host = if config.proxy_host.is_empty() { "127.0.0.1" } else { &config.proxy_host };
            args.push(format!("--proxy-server={}://{}:{}", scheme, host, config.proxy_port));
        }
    }

    args.push(url.to_string());

    let browsers =["msedge.exe", "chrome.exe", r#"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"#, r#"C:\Program Files\Google\Chrome\Application\chrome.exe"#];

    for browser in browsers {
        let mut child_proc = match Command::new(browser).args(&args).creation_flags(CREATE_NO_WINDOW).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
            Ok(child) => child, Err(_) => continue,
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
                    Ok(n) => { stdout_str.push_str(&String::from_utf8_lossy(&buffer[..n])); }
                    Err(_) => break,
                }
                thread::sleep(Duration::from_millis(50));
            }
        }

        if !is_completed { let _ = child_proc.kill(); return Err(anyhow::anyhow!("Browser timeout exceeded ({}ms).", timeout_ms)); }
        let _ = child_proc.wait();
        if stdout_str.len() > 50 { return Ok(stdout_str); }
    }
    anyhow::bail!("Failed to execute browser or received empty response.")
}

fn fetch_with_reqwest(url: &str, config: &AppConfig) -> Result<String> {
    let mut b = ClientBuilder::new()
        .timeout(Duration::from_secs(20))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
        .danger_accept_invalid_certs(config.ignore_ssl_errors)
        .trust_dns(true); // Prevents local DNS leaks!

    match config.proxy_type {
        ProxyType::None => { b = b.no_proxy(); }
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
// ISOLATED XRAY TESTER
// =============================================================

fn generate_vless_json(link: &str, test_port: u16) -> Option<String> {
    let parsed = Url::parse(link).ok()?;
    let uuid = parsed.username();
    let host = parsed.host_str()?;
    let port = parsed.port()?;
    
    let queries: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    let network = queries.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let security = queries.get("security").map(|s| s.as_str()).unwrap_or("none");
    let sni = queries.get("sni").unwrap_or(&host.to_string()).to_string();
    let path = queries.get("path").map(|s| s.as_str()).unwrap_or("/");
    let flow = queries.get("flow").map(|s| s.as_str()).unwrap_or("");
    let pbk = queries.get("pbk").map(|s| s.as_str()).unwrap_or("");
    let sid = queries.get("sid").map(|s| s.as_str()).unwrap_or("");

    let xray_config = json!({
        "log": { "loglevel": "error" },
        "inbounds":[{
            "port": test_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": { "udp": true }
        }],
        "outbounds":[{
            "protocol": "vless",
            "settings": {
                "vnext":[{
                    "address": host,
                    "port": port,
                    "users": [{ "id": uuid, "encryption": "none", "flow": flow }]
                }]
            },
            "streamSettings": {
                "network": network,
                "security": security,
                "tlsSettings": if security == "tls" { json!({ "serverName": sni }) } else { json!(null) },
                "realitySettings": if security == "reality" { json!({ "serverName": sni, "publicKey": pbk, "shortId": sid }) } else { json!(null) },
                "wsSettings": if network == "ws" { json!({ "path": path, "headers": { "Host": sni } }) } else { json!(null) },
                "grpcSettings": if network == "grpc" { json!({ "serviceName": path }) } else { json!(null) }
            }
        }]
    });

    Some(serde_json::to_string_pretty(&xray_config).unwrap())
}

fn test_config_safely(vless_link: &str, tx: &Sender<AppEvent>) -> bool {
    let test_port = 10090; // Isolated port, completely separate from Psiphon
    
    let json_config = match generate_vless_json(vless_link, test_port) {
        Some(c) => c,
        None => return false,
    };

    let temp_file = format!("temp_test_config_{}.json", test_port);
    let _ = fs::write(&temp_file, json_config);

    let mut child = match Command::new("xray.exe")
        .args(&["run", "-c", &temp_file])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn() {
            Ok(c) => c,
            Err(_) => {
                log_worker(tx, LogLevel::Error, "xray.exe not found! Please download Xray core and put it in the same folder.".to_string());
                let _ = fs::remove_file(&temp_file);
                return false;
            }
        };

    // Give the core 5 seconds to establish TLS/Reality handshakes
    thread::sleep(Duration::from_secs(5));

    let proxy_url = format!("socks5h://127.0.0.1:{}", test_port);
    let result = reqwest::blocking::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
        .timeout(Duration::from_secs(35)) // Wait up to 35 seconds to load Telegram via this config
        .build()
        .unwrap()
        .get("https://api.telegram.org")
        .send();

    let is_working = match result {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    };

    // Kill core and clean up
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&temp_file);

    is_working
}

// =============================================================
// Worker
// =============================================================

fn run_worker(config: AppConfig, channels_raw: String, stop: Arc<AtomicBool>, tx: Sender<AppEvent>) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    let (delay, _) = get_performance_settings(&config.performance);

    let regex_pattern = r"(?i)(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2|juicity|snell|anytls|ssh|wireguard|wg|warp|socks|socks4|socks5|tg|dns|nm-dns|nm-vless|slipnet-enc|slipnet|slipstream|dnstt)://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,%;=]+";
    let regex = Regex::new(regex_pattern).unwrap();
    let date_regex = Regex::new(r#"<time datetime="([^"]+)""#).unwrap();

    let mut history = SentHistory::load();
    let threshold_date = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));

    log_worker(&tx, LogLevel::Info, format!("🚀 Crawler Started | Engine: {:?} | Psiphon Port: {}", config.engine, config.proxy_port));

   loop {
        if stop.load(Ordering::SeqCst) { break; }
        history.prune(config.lookback_days);
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total_run_configs = 0;

        for channel in &channels {
            if stop.load(Ordering::SeqCst) { break; }
            log_worker(&tx, LogLevel::Info, format!("📡 Scanning channel: @{}", channel));

            let mut before: Option<String> = None;
            let mut channel_configs = 0;

            for page in 1..=config.max_pages_per_channel {
                if stop.load(Ordering::SeqCst) { break; }
                let mut url = format!("https://t.me/s/{}", channel);
                if let Some(ref id) = before { url.push_str(&format!("?before={}", id)); }

                match fetch_html(&url, &config) {
                    Ok(raw_html) => {
                        let mut found_in_page = 0;
                        let mut next_before = None;

                        let decoded_html = raw_html.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"");
                        let next_regex = Regex::new(r#"data-post="[^/]+/(\d+)""#).unwrap();
                        for cap in next_regex.captures_iter(&decoded_html) { next_before = Some(cap[1].to_string()); }

                        let blocks: Vec<&str> = decoded_html.split("tgme_widget_message ").collect();
                        
                        for block in blocks {
                            let mut is_valid_date = true;
                            if let Some(caps) = date_regex.captures(block) {
                                if let Ok(parsed_date) = DateTime::parse_from_rfc3339(&caps[1]) {
                                    if parsed_date.with_timezone(&Utc) < threshold_date { is_valid_date = false; }
                                }
                            }

                            if is_valid_date {
                                for m in regex.find_iter(block) {
                                    let clean_link = m.as_str().trim_end_matches(&['(', ')', '[', ']', ' ', '!', '.', ',', ';', '\'', '"', '<', '>'][..]).to_string();
                                    if let Some(proto) = clean_link.split("://").next() {
                                        found_in_page += 1;
                                        gathered.entry(proto.to_lowercase()).or_default().insert(clean_link);
                                    }
                                }
                            }
                        }

                        if found_in_page > 0 {
                            log_worker(&tx, LogLevel::Success, format!("    ✔️ Page {}: {} configs extracted.", page, found_in_page));
                        } else {
                            if next_before.is_none() { break; }
                        }
                        channel_configs += found_in_page;
                        before = next_before;
                    }
                    Err(e) => {
                        log_worker(&tx, LogLevel::Warning, format!("    ⚠️ Page {} failed to load over Psiphon. Retrying later.", page));
                    }
                }
                thread::sleep(delay);
            }

            total_run_configs += channel_configs;
            thread::sleep(Duration::from_secs(2));
        }

        apply_protocol_limits(&mut gathered, &config.protocol_rules);

        let mut new_only: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut total_new = 0;

        for (proto, links) in &gathered {
            for link in links {
                if !history.sent_at.contains_key(link) {
                    history.sent_at.insert(link.clone(), Utc::now());
                    new_only.entry(proto.clone()).or_default().insert(link.clone());
                    total_new += 1;
                }
            }
        }

        if config.output_new_only_enabled && !new_only.is_empty() {
            let _ = write_outputs_replace(OUTPUT_NEW_DIR, &new_only);
        }
        if config.output_append_unique_enabled && !gathered.is_empty() {
            let _ = write_outputs_append_unique(OUTPUT_APPEND_DIR, &gathered);
        }

        // ==========================================
        // SILENT TESTING PHASE (Tests ONLY New configs)
        // ==========================================
        let mut newly_working_count = 0;
        
        if config.test_configs_enabled && !new_only.is_empty() {
            log_worker(&tx, LogLevel::Info, format!("🔍 Starting background test on {} new configs...", total_new));
            fs::create_dir_all(OUTPUT_TESTED_DIR)?;
            
            for (proto, links) in &new_only {
                // Currently only tests VLESS. You can expand `generate_vless_json` to support others later.
                if proto == "vless" {
                    for link in links {
                        if stop.load(Ordering::SeqCst) { break; }
                        log_worker(&tx, LogLevel::Debug, "    🧪 Testing a VLESS config...".to_string());
                        
                        if test_config_safely(link, &tx) {
                            newly_working_count += 1;
                            log_worker(&tx, LogLevel::Success, "    🟢 SUCCESS! Config loads Telegram.".to_string());
                            
                            // Save working config immediately
                            let path = Path::new(OUTPUT_TESTED_DIR).join("working_vless.txt");
                            let mut combined = read_existing_set(&path).unwrap_or_default();
                            combined.insert(link.clone());
                            let lines: Vec<String> = combined.into_iter().collect();
                            let _ = fs::write(&path, lines.join("\n"));
                        } else {
                            log_worker(&tx, LogLevel::Warning, "    🔴 FAILED: Config is dead or blocked.".to_string());
                        }
                    }
                }
            }
            if newly_working_count > 0 {
                log_worker(&tx, LogLevel::Success, format!("🏆 Testing complete: Found {} working configs!", newly_working_count));
            } else {
                log_worker(&tx, LogLevel::Warning, "📉 Testing complete: All new configs were dead.".to_string());
            }
        }

        let mut by_protocol = BTreeMap::new();
        for (k, v) in &new_only { by_protocol.insert(k.clone(), v.len()); }

        let _ = history.save();
        let _ = tx.send(AppEvent::Stats { total: total_new, working: newly_working_count, by_protocol });

        log_worker(&tx, LogLevel::Success, format!("🎉 Cycle Complete! {} extracted, {} were NEW.", total_run_configs, total_new));
        log_worker(&tx, LogLevel::Info, format!("💤 Sleeping for {} minutes...", config.interval_minutes));

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

fn apply_protocol_limits(store: &mut BTreeMap<String, BTreeSet<String>>, rules: &BTreeMap<String, ProtocolRule>) {
    for (proto, links) in store.iter_mut() {
        if let Some(rule) = rules.get(proto) {
            if links.len() > rule.max_count { *links = links.iter().take(rule.max_count).cloned().collect(); }
        }
    }
}

fn write_outputs_replace(base_dir: &str, store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    if store.is_empty() { return Ok(()); }
    fs::create_dir_all(base_dir)?;
    let mut mixed = Vec::new();
    for (p, links) in store {
        if links.is_empty() { continue; }
        let lines: Vec<String> = links.iter().cloned().collect();
        fs::write(Path::new(base_dir).join(format!("{p}.txt")), lines.join("\n"))?;
        mixed.extend(lines);
    }
    if !mixed.is_empty() { fs::write(Path::new(base_dir).join("mixed.txt"), mixed.join("\n"))?; }
    Ok(())
}

fn write_outputs_append_unique(base_dir: &str, store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    if store.is_empty() { return Ok(()); }
    fs::create_dir_all(base_dir)?;
    for (p, links) in store {
        if links.is_empty() { continue; }
        let path = Path::new(base_dir).join(format!("{p}.txt"));
        let mut combined = read_existing_set(&path)?;
        combined.extend(links.iter().cloned());
        let lines: Vec<String> = combined.into_iter().collect();
        fs::write(&path, lines.join("\n"))?;
    }
    let path_mixed = Path::new(base_dir).join("mixed.txt");
    let mut mixed = read_existing_set(&path_mixed)?;
    for links in store.values() { mixed.extend(links.iter().cloned()); }
    if !mixed.is_empty() {
        let mixed_lines: Vec<String> = mixed.into_iter().collect();
        fs::write(path_mixed, mixed_lines.join("\n"))?;
    }
    Ok(())
}

fn read_existing_set(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() { return Ok(BTreeSet::new()); }
    let raw = fs::read_to_string(path)?;
    Ok(raw.lines().map(str::trim).filter(|l| !l.is_empty()).map(ToOwned::to_owned).collect())
}

fn parse_channels(raw: &str) -> Vec<String> {
    raw.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|line| {
        if let Some(rest) = line.strip_prefix('@') { return Some(rest.to_string()); }
        if line.contains("t.me/") { return line.split("t.me/").nth(1).map(|x| x.split('?').next().unwrap_or_default().trim_matches('/').to_string()); }
        Some(line.to_string())
    }).filter(|s| !s.is_empty()).collect()
}
