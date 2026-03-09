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
const OUTPUT_DIR: &str = "output";
const LOG_FILE: &str = "logs/app.log";
const HISTORY_PATH: &str = "output/sent_history.json";
const DEFAULT_PROTOCOLS: [&str; 27] = [
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "tuic",
    "hysteria",
    "hysteria2",
    "hy2",
    "juicity",
    "snell",
    "anytls",
    "ssh",
    "wireguard",
    "wg",
    "warp",
    "socks",
    "socks4",
    "socks5",
    "tg",
    "dns",
    "nm-dns",
    "nm-vless",
    "slipnet-enc",
    "slipnet",
    "slipstream",
    "dnstt",
];

fn main() {
    let _ = eframe::run_native(
        "جمع‌آوری کانفیگ تلگرام",
        eframe::NativeOptions::default(),
        Box::new(|cc| {
            configure_persian_font(&cc.egui_ctx);
            Ok(Box::new(AppState::bootstrap()))
        }),
    );
}

fn configure_persian_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    if let Some(font_bytes) = load_persian_font_bytes() {
        fonts.font_data.insert(
            "persian_font".to_owned(),
            egui::FontData::from_owned(font_bytes).into(),
        );

        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "persian_font".to_owned());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("persian_font".to_owned());
    }

    ctx.set_fonts(fonts);
}

fn load_persian_font_bytes() -> Option<Vec<u8>> {
    let candidates = [
        r"C:\Windows\Fonts\tahoma.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/noto/NotoNaskhArabic-Regular.ttf",
    ];

    for path in candidates {
        if let Ok(bytes) = fs::read(path) {
            return Some(bytes);
        }
    }

    None
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProtocolRule {
    enabled: bool,
    max_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Language {
    Fa,
    En,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum ProxyType {
    None,
    Http,
    Socks5,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AppConfig {
    interval_minutes: u64,
    max_pages_per_channel: usize,
    lookback_days: i64,
    language: Language,
    proxy_type: ProxyType,
    proxy_host: String,
    proxy_port: u16,
    proxy_username: String,
    proxy_password: String,
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
            max_pages_per_channel: 8,
            lookback_days: 1,
            language: Language::Fa,
            proxy_type: ProxyType::None,
            proxy_host: String::new(),
            proxy_port: 1080,
            proxy_username: String::new(),
            proxy_password: String::new(),
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
enum WorkerEvent {
    Log(String),
    Stats {
        total: usize,
        by_protocol: BTreeMap<String, usize>,
    },
}

struct AppState {
    config: AppConfig,
    channels_text: String,
    logs: Vec<String>,
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
                "# هر خط یک کانال\n# @channel\n# https://t.me/channel".to_string()
            }),
            logs: vec!["برنامه آماده اجرا است.".to_string()],
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
            self.logs.push(format!("خطا در ذخیره تنظیمات: {e:#}"));
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
                let _ = tx.send(WorkerEvent::Log(format!("خطای بحرانی: {err:#}")));
            }
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.running = false;
        self.logs.push("درخواست توقف ثبت شد.".to_string());
    }

    fn poll_events(&mut self) {
        if let Some(rx) = &self.event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    WorkerEvent::Log(msg) => self.logs.push(msg),
                    WorkerEvent::Stats { total, by_protocol } => {
                        self.total_configs = total;
                        self.by_protocol = by_protocol;
                    }
                }
            }
        }
        if let Some(handle) = self.worker_handle.take() {
            if handle.is_finished() {
                let _ = handle.join();
                self.running = false;
            } else {
                self.worker_handle = Some(handle);
            }
        }
    }
}

impl AppState {
    fn tr(&self, fa: &str, en: &str) -> String {
        match self.config.language {
            Language::Fa => shape_rtl_text(fa),
            Language::En => en.to_string(),
        }
    }

    fn rtl(&self) -> bool {
        matches!(self.config.language, Language::Fa)
    }
}

fn shape_rtl_text(input: &str) -> String {
    input.chars().rev().collect()
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading(self.tr(
                "🛰️ جمع‌آوری هوشمند کانفیگ تلگرام",
                "🛰️ Telegram Config Collector",
            ));
        });

        egui::SidePanel::left("left")
            .min_width(360.0)
            .show(ctx, |ui| {
                let layout = if self.rtl() {
                    egui::Layout::right_to_left(egui::Align::TOP)
                } else {
                    egui::Layout::left_to_right(egui::Align::TOP)
                };
                ui.with_layout(layout, |ui| {
                    ui.heading(self.tr("تنظیمات اصلی", "Main Settings"));
                    ui.horizontal(|ui| {
                        ui.label(self.tr("زبان رابط:", "UI Language:"));
                        egui::ComboBox::from_id_source("language")
                            .selected_text(match self.config.language {
                                Language::Fa => self.tr("فارسی", "Persian"),
                                Language::En => "English".to_string(),
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.config.language,
                                    Language::Fa,
                                    self.tr("فارسی", "Persian"),
                                );
                                ui.selectable_value(
                                    &mut self.config.language,
                                    Language::En,
                                    "English",
                                );
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label(&self.tr("هر چند دقیقه چک شود:", "Check interval (minutes):"));
                        ui.add(
                            egui::DragValue::new(&mut self.config.interval_minutes).range(1..=240),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(&self.tr("حداکثر صفحات هر کانال:", "Max pages per channel:"));
                        ui.add(
                            egui::DragValue::new(&mut self.config.max_pages_per_channel)
                                .range(1..=100),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(&self.tr("بررسی پیام‌های چند روز اخیر:", "Look back days:"));
                        ui.add(egui::DragValue::new(&mut self.config.lookback_days).range(1..=30));
                    });

                    ui.separator();
                    ui.heading(&self.tr("پروکسی", "Proxy"));
                    egui::ComboBox::from_label(self.tr("نوع", "Type"))
                        .selected_text(match self.config.proxy_type {
                            ProxyType::None => self.tr("بدون پروکسی", "No proxy"),
                            ProxyType::Http => "HTTP",
                            ProxyType::Socks5 => "SOCKS5",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.config.proxy_type,
                                ProxyType::None,
                                self.tr("بدون پروکسی", "No proxy"),
                            );
                            ui.selectable_value(
                                &mut self.config.proxy_type,
                                ProxyType::Http,
                                "HTTP",
                            );
                            ui.selectable_value(
                                &mut self.config.proxy_type,
                                ProxyType::Socks5,
                                "SOCKS5",
                            );
                        });
                    ui.label(&self.tr("هاست پروکسی", "Proxy host"));
                    ui.text_edit_singleline(&mut self.config.proxy_host);
                    ui.horizontal(|ui| {
                        ui.label(&self.tr("پورت", "Port"));
                        ui.add(egui::DragValue::new(&mut self.config.proxy_port).range(1..=65535));
                    });
                    ui.label(&self.tr("یوزرنیم (اختیاری)", "Username (optional)"));
                    ui.text_edit_singleline(&mut self.config.proxy_username);
                    ui.label(&self.tr("پسورد (اختیاری)", "Password (optional)"));
                    ui.text_edit_singleline(&mut self.config.proxy_password);

                    ui.separator();
                    ui.heading(&self.tr(
                        "پروتکل‌ها (فعال/غیرفعال + سقف تعداد)",
                        "Protocols (Enable/Disable + Limit)",
                    ));
                    for (name, rule) in &mut self.config.protocol_rules {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut rule.enabled, name);
                            ui.label(&self.tr("حداکثر:", "Max:"));
                            ui.add(egui::DragValue::new(&mut rule.max_count).range(1..=50000));
                        });
                    }

                    ui.separator();
                    if ui
                        .button(
                            &self.tr("💾 ذخیره کانال‌ها و تنظیمات", "💾 Save channels & settings"),
                        )
                        .clicked()
                    {
                        match save_channels(&self.channels_text).and_then(|_| self.config.save()) {
                            Ok(_) => self.logs.push("تنظیمات ذخیره شد.".to_string()),
                            Err(e) => self.logs.push(format!("خطا در ذخیره: {e:#}")),
                        }
                    }
                    if !self.running {
                        if ui.button(&self.tr("▶️ شروع", "▶️ Start")).clicked() {
                            self.start();
                        }
                    } else if ui.button(&self.tr("⏹ توقف", "⏹ Stop")).clicked() {
                        self.stop();
                    }

                    ui.separator();
                    ui.label(match self.config.language {
                        Language::Fa => format!(
                            "{} :{}",
                            self.tr("مجموع جدیدها", "Total new"),
                            self.total_configs
                        ),
                        Language::En => format!("Total new: {}", self.total_configs),
                    });
                    for (k, v) in &self.by_protocol {
                        ui.label(format!("{k}: {v}"));
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let layout = if self.rtl() {
                egui::Layout::right_to_left(egui::Align::TOP)
            } else {
                egui::Layout::left_to_right(egui::Align::TOP)
            };
            ui.with_layout(layout, |ui| {
                ui.heading(&self.tr(
                    "لیست کانال‌ها (هر خط یک کانال)",
                    "Channels list (one per line)",
                ));
                ui.add_sized(
                    [ui.available_width(), 180.0],
                    egui::TextEdit::multiline(&mut self.channels_text),
                );
                ui.separator();
                ui.heading(&self.tr("لاگ حرفه‌ای", "Professional logs"));
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in self.logs.iter().rev().take(300).rev() {
                            if self.rtl() {
                                ui.label(shape_rtl_text(line));
                            } else {
                                ui.label(line);
                            }
                        }
                    });
            });
        });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

fn run_worker(
    config: AppConfig,
    channels_raw: String,
    stop: Arc<AtomicBool>,
    tx: Sender<WorkerEvent>,
) -> Result<()> {
    let channels = parse_channels(&channels_raw);
    if channels.is_empty() {
        let _ = tx.send(WorkerEvent::Log("کانال معتبری ثبت نشده است.".to_string()));
        return Ok(());
    }

    let client = build_client(&config)?;
    let regex = build_protocol_regex()?;
    let mut history = SentHistory::load();

    loop {
        if stop.load(Ordering::SeqCst) {
            log_event(&tx, "Worker متوقف شد.".to_string());
            break;
        }

        history.prune(config.lookback_days);
        let threshold = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for channel in &channels {
            log_event(&tx, format!("پردازش @{channel}"));
            let result = fetch_channel_configs(
                &client,
                channel,
                config.max_pages_per_channel,
                threshold,
                &regex,
                &config.protocol_rules,
            );
            match result {
                Ok(map) => {
                    for (p, links) in map {
                        gathered.entry(p).or_default().extend(links);
                    }
                }
                Err(e) => log_event(&tx, format!("خطا در @{channel}: {e:#}")),
            }
            thread::sleep(Duration::from_millis(700));
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
        write_outputs(&new_only)?;
        history.prune(config.lookback_days);
        history.save()?;

        let mut by_protocol = BTreeMap::new();
        let mut total = 0;
        for (k, v) in &new_only {
            by_protocol.insert(k.clone(), v.len());
            total += v.len();
        }
        let _ = tx.send(WorkerEvent::Stats { total, by_protocol });
        log_event(&tx, format!("تکمیل شد. تعداد کانفیگ جدید: {total}"));

        for _ in 0..(config.interval_minutes * 60) {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn fetch_channel_configs(
    client: &Client,
    channel: &str,
    max_pages: usize,
    threshold: DateTime<Utc>,
    pattern: &Regex,
    rules: &BTreeMap<String, ProtocolRule>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let wrap_sel = Selector::parse("div.tgme_widget_message").unwrap();
    let text_sel = Selector::parse("div.tgme_widget_message_text").unwrap();
    let time_sel = Selector::parse("time").unwrap();

    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut before: Option<String> = None;

    for _ in 0..max_pages {
        let mut url = format!("https://t.me/s/{channel}");
        if let Some(id) = &before {
            url.push_str(&format!("?before={id}"));
        }

        let resp = client.get(&url).send().context("ارسال درخواست")?;
        if !resp.status().is_success() {
            anyhow::bail!("status={}", resp.status());
        }
        let body = resp.text()?;
        let doc = Html::parse_document(&body);
        let mut found_any = false;
        let mut next_before = None;
        let mut should_stop_for_old = false;

        for wrap in doc.select(&wrap_sel) {
            if let Some(post) = wrap.value().attr("data-post") {
                next_before = post.split('/').nth(1).map(|s| s.to_string());
            }

            let msg_time = wrap
                .select(&time_sel)
                .next()
                .and_then(|t| t.value().attr("datetime"))
                .and_then(|iso| DateTime::parse_from_rfc3339(iso).ok())
                .map(|t| t.with_timezone(&Utc));

            if let Some(mt) = msg_time {
                if mt < threshold {
                    should_stop_for_old = true;
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
                            if !rule.enabled {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        result.entry(p).or_default().insert(m.as_str().to_string());
                    }
                }
            }
        }

        if !found_any || should_stop_for_old {
            break;
        }
        before = next_before;
        thread::sleep(Duration::from_millis(500));
    }

    Ok(result)
}

fn apply_protocol_limits(
    store: &mut BTreeMap<String, BTreeSet<String>>,
    rules: &BTreeMap<String, ProtocolRule>,
) {
    for (proto, links) in store.iter_mut() {
        if let Some(rule) = rules.get(proto) {
            if links.len() > rule.max_count {
                let limited: BTreeSet<String> =
                    links.iter().take(rule.max_count).cloned().collect();
                *links = limited;
            }
        }
    }
}

fn write_outputs(store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(OUTPUT_DIR)?;
    let mut mixed = Vec::new();
    for (p, links) in store {
        let lines: Vec<String> = links.iter().cloned().collect();
        fs::write(
            Path::new(OUTPUT_DIR).join(format!("{p}.txt")),
            lines.join("\n"),
        )?;
        mixed.extend(lines);
    }
    fs::write(Path::new(OUTPUT_DIR).join("mixed.txt"), mixed.join("\n"))?;
    Ok(())
}

fn parse_channels(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            if let Some(rest) = line.strip_prefix('@') {
                return Some(rest.to_string());
            }
            if line.contains("t.me/") {
                return line.split("t.me/").nth(1).map(|x| {
                    x.split('?')
                        .next()
                        .unwrap_or_default()
                        .trim_matches('/')
                        .to_string()
                });
            }
            Some(line.to_string())
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn build_client(config: &AppConfig) -> Result<Client> {
    let mut b = ClientBuilder::new()
        .timeout(Duration::from_secs(25))
        .user_agent("Mozilla/5.0 ConfigCollectorWindows/1.1");
    if config.proxy_type != ProxyType::None && !config.proxy_host.trim().is_empty() {
        let scheme = match config.proxy_type {
            ProxyType::Http => "http",
            ProxyType::Socks5 => "socks5h",
            ProxyType::None => "",
        };
        let proxy = if config.proxy_username.trim().is_empty() {
            format!(
                "{scheme}://{}:{}",
                config.proxy_host.trim(),
                config.proxy_port
            )
        } else {
            format!(
                "{scheme}://{}:{}@{}:{}",
                url::form_urlencoded::byte_serialize(config.proxy_username.as_bytes())
                    .collect::<String>(),
                url::form_urlencoded::byte_serialize(config.proxy_password.as_bytes())
                    .collect::<String>(),
                config.proxy_host.trim(),
                config.proxy_port
            )
        };
        b = b.proxy(reqwest::Proxy::all(&proxy)?);
    }
    Ok(b.build()?)
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

fn log_event(tx: &Sender<WorkerEvent>, msg: String) {
    let line = format!("[{}] {}", Local::now().format("%Y-%m-%d %H:%M:%S"), msg);
    let _ = append_log(&line);
    let _ = tx.send(WorkerEvent::Log(line));
}

fn append_log(line: &str) -> Result<()> {
    use std::io::Write;
    ensure_parent(LOG_FILE)?;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(LOG_FILE)?;
    writeln!(f, "{line}")?;
    Ok(())
}

fn ensure_parent(path: &str) -> Result<()> {
    let parent: PathBuf = Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(parent)?;
    Ok(())
}
