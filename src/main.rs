use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use eframe::egui;
use regex::Regex;
use reqwest::blocking::ClientBuilder;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::windows::process::CommandExt; // برای اجرای مخفیانه مرورگر در ویندوز
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

const CREATE_NO_WINDOW: u32 = 0x08000000; // جلوگیری از باز شدن پنجره CMD سیاه

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ScrapingEngine {
    RealBrowser, // اجرای مخفی Edge/Chrome (تضمینی)
    Reqwest,     // موتور استاندارد (سریع اما حساس به فیلترینگ)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum ProxyType {
    None,
    System,
    Http,
    Socks5,
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
    engine: ScrapingEngine, // موتور جدید
    proxy_type: ProxyType,
    proxy_host: String,
    proxy_port: u16,
    proxy_username: String,
    proxy_password: String,
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
            protocol_rules.insert(p.to_string(), ProtocolRule { enabled: true, max_count: 500 });
        }
        Self {
            interval_minutes: 5,
            max_pages_per_channel: 15,
            lookback_days: 2,
            engine: ScrapingEngine::RealBrowser, // پیش‌فرض روی مرورگر واقعی تنظیم شد
            proxy_type: ProxyType::System,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 10808,
            proxy_username: String::new(),
            proxy_password: String::new(),
            ignore_ssl_errors: true,
            remote_dns: true,
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
        ensure_parent(APP_CONFIG_PATH)?;
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
            if let Ok(v) = serde_json::from_str::<Self>(&raw) { return v; }
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
enum LogLevel { Info, Success, Warning, Error }

#[derive(Clone, Debug)]
struct LogMessage {
    time: String,
    level: LogLevel,
    text: String,
}

#[derive(Clone, Debug)]
enum AppEvent {
    Log(LogLevel, String),
    Stats { total: usize, by_protocol: BTreeMap<String, usize> },
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
    by_protocol: BTreeMap<String, usize>,
    running: bool,
    stop_flag: Arc<AtomicBool>,
    worker_handle: Option<thread::JoinHandle<()>>,
    event_tx: Sender<AppEvent>,
    event_rx: Receiver<AppEvent>,
    last_network_hash: u64, // برای تشخیص تغییرات تنظیمات شبکه
}

impl AppState {
    fn bootstrap() -> Self {
        let (tx, rx) = mpsc::channel();
        let mut state = Self {
            config: AppConfig::load_or_create(),
            channels_text: fs::read_to_string(CHANNELS_PATH).unwrap_or_else(|_| "IranProxyPlus".to_string()),
            active_tab: 0,
            proxy_access_status: "Initializing...".to_string(),
            proxy_access_ok: None,
            logs: vec![LogMessage { time: Local::now().format("%H:%M:%S").to_string(), level: LogLevel::Info, text: "System initialized.".to_string() }],
            total_configs: 0,
            by_protocol: BTreeMap::new(),
            running: false,
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
            event_tx: tx,
            event_rx: rx,
            last_network_hash: 0,
        };
        // یک هش اولیه تولید می‌کنیم تا پینگ اولیه سریعاً اجرا شود
        state.check_network_changes();
        state
    }

    // محاسبه هش تنظیمات شبکه برای اجرای پینگ زنده در صورت تغییر تنظیمات
    fn calculate_network_hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.config.engine.hash(&mut hasher);
        self.config.proxy_type.hash(&mut hasher);
        self.config.proxy_host.hash(&mut hasher);
        self.config.proxy_port.hash(&mut hasher);
        hasher.finish()
    }

    fn check_network_changes(&mut self) {
        let current_hash = self.calculate_network_hash();
        if current_hash != self.last_network_hash {
            self.last_network_hash = current_hash;
            self.proxy_access_status = "Testing connection...".to_string();
            self.proxy_access_ok = None;
            
            let tx = self.event_tx.clone();
            let config = self.config.clone();
            
            thread::spawn(move || {
                match fetch_html("https://t.me/s/telegram", &config) {
                    Ok(_) => {
                        let _ = tx.send(AppEvent::PingResult { ok: true, detail: "Connection: Online 🟢".to_string() });
                    }
                    Err(e) => {
                        let _ = tx.send(AppEvent::PingResult { ok: false, detail: "Connection: Failed 🔴".to_string() });
                        let _ = tx.send(AppEvent::Log(LogLevel::Warning, format!("Ping failed: {}", extract_error_msg(&e))));
                    }
                }
            });
        }
    }

    fn start(&mut self) {
        if self.running { return; }
        let _ = save_channels(&self.channels_text).and_then(|_| self.config.save());
        self.stop_flag.store(false, Ordering::SeqCst);
        self.running = true;
        
        let tx = self.event_tx.clone();
        let cfg = self.config.clone();
        let channels_raw = self.channels_text.clone();
        let stop_flag = self.stop_flag.clone();

        self.worker_handle = Some(thread::spawn(move || {
            if let Err(err) = run_worker(cfg, channels_raw, stop_flag, tx.clone()) {
                let _ = tx.send(AppEvent::Log(LogLevel::Error, format!("Critical error: {}", err)));
            }
            let _ = tx.send(AppEvent::WorkerStopped);
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.add_log(LogLevel::Warning, "Stop requested. Waiting for worker...".to_string());
    }

    fn add_log(&mut self, level: LogLevel, text: String) {
        self.logs.push(LogMessage { time: Local::now().format("%H:%M:%S").to_string(), level, text });
    }

    fn poll_events(&mut self) {
        let mut events = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() { events.push(event); }

        for event in events {
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
                    self.add_log(LogLevel::Warning, "Worker thread has stopped.".to_string());
                }
            }
        }
    }
}

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
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        self.check_network_changes(); // چک کردن تغییرات تنظیمات برای پینگ زنده
        apply_modern_theme(ctx);

        egui::TopBottomPanel::top("header").exact_height(70.0).frame(egui::Frame::default().fill(egui::Color32::from_rgb(20, 23, 33)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🚀 Telegram Config Collector").size(24.0).strong().color(egui::Color32::from_rgb(240, 240, 240)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.running {
                        if ui.add(egui::Button::new(egui::RichText::new("⏹ Stop Process").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(220, 38, 38))).clicked() { self.stop(); }
                        ui.spinner();
                        ui.label(egui::RichText::new("Scraping in progress...").color(egui::Color32::from_rgb(59, 130, 246)));
                    } else {
                        if ui.add(egui::Button::new(egui::RichText::new("▶ Start Scraping").strong().color(egui::Color32::WHITE)).fill(egui::Color32::from_rgb(16, 185, 129))).clicked() { self.start(); }
                        if ui.button("💾 Save Configs").clicked() {
                            let _ = save_channels(&self.channels_text);
                            let _ = self.config.save();
                            self.add_log(LogLevel::Success, "Settings saved successfully.".to_string());
                        }
                    }
                });
            });
        });

        egui::SidePanel::left("sidebar").default_width(320.0).frame(egui::Frame::default().fill(egui::Color32::from_rgb(20, 23, 33)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, 0, "📡 Settings");
                ui.selectable_value(&mut self.active_tab, 1, "📝 Channels");
                ui.selectable_value(&mut self.active_tab, 2, "⚙️ Protocols");
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.active_tab {
                    0 => {
                        ui.heading(egui::RichText::new("Engine (Crucial)").color(egui::Color32::LIGHT_BLUE));
                        ui.add_space(5.0);
                        egui::ComboBox::from_label("Scraping Engine")
                            .selected_text(match self.config.engine {
                                ScrapingEngine::RealBrowser => "Real Browser (MS Edge/Chrome) - 100% Bypass",
                                ScrapingEngine::Reqwest => "Standard (Reqwest) - Fast",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.engine, ScrapingEngine::RealBrowser, "Real Browser (MS Edge/Chrome) - 100% Bypass");
                                ui.selectable_value(&mut self.config.engine, ScrapingEngine::Reqwest, "Standard (Reqwest) - Fast");
                            });
                        ui.label(egui::RichText::new("If Standard fails in Iran, use 'Real Browser'. It opens a hidden Chrome/Edge instance to load the page exactly like you do manually!").small().color(egui::Color32::GRAY));

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("Network & Proxy").color(egui::Color32::LIGHT_BLUE));
                        egui::ComboBox::from_label("Mode")
                            .selected_text(match self.config.proxy_type {
                                ProxyType::None => "Direct (No Proxy)",
                                ProxyType::System => "System Proxy (Auto)",
                                ProxyType::Http => "HTTP Proxy",
                                ProxyType::Socks5 => "SOCKS5 Proxy",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::System, "System Proxy (Auto)");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::Socks5, "SOCKS5 Proxy");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::Http, "HTTP Proxy");
                                ui.selectable_value(&mut self.config.proxy_type, ProxyType::None, "Direct (No Proxy)");
                            });

                        if matches!(self.config.proxy_type, ProxyType::Http | ProxyType::Socks5) {
                            ui.horizontal(|ui| { ui.label("IP:"); ui.text_edit_singleline(&mut self.config.proxy_host); });
                            ui.horizontal(|ui| { ui.label("Port:"); ui.add(egui::DragValue::new(&mut self.config.proxy_port).range(1..=65535)); });
                        }

                        ui.add_space(15.0);
                        ui.heading(egui::RichText::new("Scraping Rules").color(egui::Color32::LIGHT_BLUE));
                        ui.horizontal(|ui| { ui.label("Interval (Min):"); ui.add(egui::DragValue::new(&mut self.config.interval_minutes).range(1..=240)); });
                        ui.horizontal(|ui| { ui.label("Max Pages:"); ui.add(egui::DragValue::new(&mut self.config.max_pages_per_channel).range(1..=100)); });
                        ui.horizontal(|ui| { ui.label("Lookback Days:"); ui.add(egui::DragValue::new(&mut self.config.lookback_days).range(1..=30)); });
                    }
                    1 => {
                        ui.heading(egui::RichText::new("Target Channels").color(egui::Color32::LIGHT_BLUE));
                        ui.add_sized([ui.available_width(), ui.available_height() - 20.0], egui::TextEdit::multiline(&mut self.channels_text).font(egui::TextStyle::Monospace));
                    }
                    2 => {
                        ui.heading(egui::RichText::new("Protocols Filter").color(egui::Color32::LIGHT_BLUE));
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

        egui::CentralPanel::default().frame(egui::Frame::default().fill(egui::Color32::from_rgb(15, 17, 26)).inner_margin(15.0)).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Total Extracted:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(self.total_configs.to_string()).size(20.0).strong().color(egui::Color32::from_rgb(16, 185, 129)));
                });
                let proxy_color = match self.proxy_access_ok {
                    Some(true) => egui::Color32::from_rgb(16, 185, 129),
                    Some(false) => egui::Color32::from_rgb(239, 68, 68),
                    None => egui::Color32::from_rgb(251, 191, 36),
                };
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Live Connection:").color(egui::Color32::GRAY));
                    ui.label(egui::RichText::new(&self.proxy_access_status).size(14.0).strong().color(proxy_color));
                });
            });

            ui.add_space(10.0);
            egui::Frame::none().fill(egui::Color32::from_rgb(10, 12, 16)).rounding(10.0).inner_margin(10.0).show(ui, |ui| {
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
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false; 2]).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    for log in self.logs.iter().rev().take(300).rev() {
                        let color = match log.level {
                            LogLevel::Info => egui::Color32::from_rgb(156, 163, 175),
                            LogLevel::Success => egui::Color32::from_rgb(52, 211, 153),
                            LogLevel::Warning => egui::Color32::from_rgb(251, 191, 36),
                            LogLevel::Error => egui::Color32::from_rgb(248, 113, 113),
                        };
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("[{}]", log.time)).color(egui::Color32::from_rgb(75, 85, 99)).monospace());
                            ui.label(egui::RichText::new(&log.text).color(color).monospace());
                        });
                    }
                });
            });
        });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

// -------------------------------------------------------------
// Core Network & HTML Fetching Abstraction
// -------------------------------------------------------------

// سیستم قدرتمند جدید: انتخاب دینامیک بین مرورگر واقعی یا ریکوئست خام
fn fetch_html(url: &str, config: &AppConfig) -> Result<String> {
    match config.engine {
        ScrapingEngine::RealBrowser => fetch_with_cli_browser(url, config),
        ScrapingEngine::Reqwest => fetch_with_reqwest(url, config),
    }
}

// موتور مرورگر واقعی: استفاده از Microsoft Edge یا Chrome نصب شده در ویندوز به صورت مخفی (Headless)
fn fetch_with_cli_browser(url: &str, config: &AppConfig) -> Result<String> {
    let mut args = vec![
        "--headless=new".to_string(), // حالت جدید و سریع هِدلس کرومیوم
        "--dump-dom".to_string(),     // خروجی دادن کل HTML به ترمینال
        "--disable-gpu".to_string(),
        "--no-sandbox".to_string(),
        "--log-level=3".to_string(),
    ];

    match config.proxy_type {
        ProxyType::System => { /* کرومیوم به طور خودکار از پروکسی ویندوز استفاده می‌کند */ }
        ProxyType::None => { args.push("--no-proxy-server".to_string()); }
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = if config.proxy_type == ProxyType::Socks5 { "socks5" } else { "http" };
            let host = if config.proxy_host.is_empty() { "127.0.0.1" } else { &config.proxy_host };
            args.push(format!("--proxy-server={}://{}:{}", scheme, host, config.proxy_port));
        }
    }
    args.push(url.to_string());

    let browsers = [
        "msedge.exe", "chrome.exe", 
        r#"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"#,
        r#"C:\Program Files\Google\Chrome\Application\chrome.exe"#,
    ];

    for browser in browsers {
        if let Ok(output) = std::process::Command::new(browser)
            .args(&args)
            .creation_flags(CREATE_NO_WINDOW) // اجرا در پس‌زمینه بدون باز شدن هیچ پنجره‌ای
            .output() 
        {
            if output.status.success() {
                let html = String::from_utf8_lossy(&output.stdout).to_string();
                if html.contains("<html") || html.contains("tgme_widget_message") {
                    return Ok(html);
                }
            }
        }
    }
    anyhow::bail!("Failed to run Real Browser. Ensure MS Edge or Chrome is installed.")
}

// موتور ریکوئست قدیمی
fn fetch_with_reqwest(url: &str, config: &AppConfig) -> Result<String> {
    let mut b = ClientBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .danger_accept_invalid_certs(config.ignore_ssl_errors);

    match config.proxy_type {
        ProxyType::None => { b = b.no_proxy(); }
        ProxyType::System => {}
        ProxyType::Http | ProxyType::Socks5 => {
            let scheme = if config.proxy_type == ProxyType::Socks5 && config.remote_dns { "socks5h" } 
                         else if config.proxy_type == ProxyType::Socks5 { "socks5" } else { "http" };
            let host = if config.proxy_host.trim().is_empty() { "127.0.0.1" } else { config.proxy_host.trim() };
            b = b.proxy(reqwest::Proxy::all(&format!("{}://{}:{}", scheme, host, config.proxy_port))?);
        }
    }
    let client = b.build()?;
    let resp = client.get(url).send()?;
    if !resp.status().is_success() { anyhow::bail!("HTTP {}", resp.status()); }
    Ok(resp.text()?)
}

fn run_worker(config: AppConfig, channels_raw: String, stop: Arc<AtomicBool>, tx: Sender<AppEvent>) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    if channels.is_empty() {
        let _ = tx.send(AppEvent::Log(LogLevel::Error, "No valid channels provided.".to_string()));
        return Ok(());
    }

    let regex = build_protocol_regex()?;
    let mut history = SentHistory::load();

    log_worker(&tx, LogLevel::Info, format!("🚀 Scraping Engine: {:?}", config.engine));

    loop {
        if stop.load(Ordering::SeqCst) { break; }
        history.prune(config.lookback_days);
        let threshold = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for channel in &channels {
            if stop.load(Ordering::SeqCst) { break; }
            log_worker(&tx, LogLevel::Info, format!("📥 Scraping @{} ...", channel));
            
            match fetch_channel_configs(channel, config.max_pages_per_channel, threshold, &regex, &config.protocol_rules, &tx, &config) {
                Ok(map) => {
                    let mut count = 0;
                    for (p, links) in map { count += links.len(); gathered.entry(p).or_default().extend(links); }
                    if count > 0 { log_worker(&tx, LogLevel::Success, format!("Found {} raw configs from @{}", count, channel)); }
                }
                Err(e) => log_worker(&tx, LogLevel::Error, format!("Failed on @{}: {}", channel, extract_error_msg(&e))),
            }
            thread::sleep(Duration::from_secs(2)); 
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
        for (k, v) in &new_only { by_protocol.insert(k.clone(), v.len()); total_new += v.len(); }
        
        if config.output_new_only_enabled { let _ = write_outputs_replace(OUTPUT_NEW_DIR, &new_only); }
        if config.output_append_unique_enabled { let _ = write_outputs_append_unique(OUTPUT_APPEND_DIR, &new_only); }
        
        let _ = history.save();
        let _ = tx.send(AppEvent::Stats { total: total_new, by_protocol });
        
        log_worker(&tx, LogLevel::Success, format!("✅ Cycle complete. Saved {} NEW unique configs.", total_new));
        log_worker(&tx, LogLevel::Info, format!("💤 Sleeping for {} minutes...", config.interval_minutes));

        for _ in 0..(config.interval_minutes * 60) {
            if stop.load(Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn extract_error_msg(err: &anyhow::Error) -> String {
    let mut chain = Vec::new();
    let mut current = Some(err.as_ref() as &dyn std::error::Error);
    while let Some(e) = current { chain.push(e.to_string()); current = e.source(); }
    chain.join(" -> ")
}

fn fetch_channel_configs(channel: &str, max_pages: usize, threshold: DateTime<Utc>, pattern: &Regex, rules: &BTreeMap<String, ProtocolRule>, tx: &Sender<AppEvent>, config: &AppConfig) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let wrap_sel = Selector::parse("div.tgme_widget_message").unwrap();
    let text_sel = Selector::parse("div.tgme_widget_message_text").unwrap();
    let time_sel = Selector::parse("time").unwrap();
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut before: Option<String> = None;

    for _page in 1..=max_pages {
        let mut url = format!("https://t.me/s/{}", channel);
        if let Some(ref id) = before { url.push_str(&format!("?before={}", id)); }

        let body = match fetch_html(&url, config) {
            Ok(html) => html,
            Err(e) => anyhow::bail!("Fetch error: {}", extract_error_msg(&e)),
        };

        if body.contains("tgme_widget_message_error") && body.contains("not found") {
            anyhow::bail!("Channel not found.");
        }

        let doc = Html::parse_document(&body);
        let mut found_any = false;
        let mut next_before = None;
        let mut should_stop = false;

        for wrap in doc.select(&wrap_sel) {
            if let Some(post) = wrap.value().attr("data-post") { next_before = post.split('/').nth(1).map(|s| s.to_string()); }
            let msg_time = wrap.select(&time_sel).next().and_then(|t| t.value().attr("datetime")).and_then(|iso| DateTime::parse_from_rfc3339(iso).ok()).map(|t| t.with_timezone(&Utc));
            if let Some(mt) = msg_time {
                if mt < threshold { should_stop = true; continue; }
            }
            for text in wrap.select(&text_sel) {
                found_any = true;
                let content = text.text().collect::<Vec<_>>().join(" ");
                for m in pattern.find_iter(&content) {
                    if let Some(proto) = m.as_str().split("://").next() {
                        let p = proto.to_lowercase();
                        if let Some(rule) = rules.get(&p) {
                            if rule.enabled { result.entry(p).or_default().insert(m.as_str().to_string()); }
                        }
                    }
                }
            }
        }
        if !found_any || should_stop { break; }
        before = next_before;
        thread::sleep(Duration::from_millis(1500));
    }
    Ok(result)
}

fn log_worker(tx: &Sender<AppEvent>, level: LogLevel, text: String) { let _ = tx.send(AppEvent::Log(level, text)); }
fn apply_protocol_limits(store: &mut BTreeMap<String, BTreeSet<String>>, rules: &BTreeMap<String, ProtocolRule>) {
    for (proto, links) in store.iter_mut() {
        if let Some(rule) = rules.get(proto) {
            if links.len() > rule.max_count { *links = links.iter().take(rule.max_count).cloned().collect(); }
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
    Regex::new(r#"(?i)(vmess|vless|trojan|ssr?|tuic|hysteria2?|hy2|juicity|snell|anytls|ssh|wireguard|wg|warp|socks(?:4|5)?|tg|dns|nm-dns|nm-vless|slipnet-enc|slipnet|slipstream|dnstt)://[^\s<>'"]+"#).context("regex")
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
