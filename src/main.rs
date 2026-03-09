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
        "Telegram Config Collector",
        eframe::NativeOptions::default(),
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
            max_pages_per_channel: 8,
            lookback_days: 1,
            proxy_type: ProxyType::None,
            proxy_host: String::new(),
            proxy_port: 1080,
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
                "# one channel per line\n# @channel\n# https://t.me/channel".to_string()
            }),
            logs: vec!["Application is ready.".to_string()],
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
            self.logs.push(format!("Failed to save settings: {e:#}"));
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
                let _ = tx.send(WorkerEvent::Log(format!("Critical error: {err:#}")));
            }
        }));
    }

    fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.running = false;
        self.logs.push("Stop requested.".to_string());
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

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        let mut visuals = egui::Visuals::dark();
        visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
        visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
        visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
        visuals.widgets.active.rounding = egui::Rounding::same(8.0);
        visuals.override_text_color = Some(egui::Color32::from_rgb(230, 233, 238));
        visuals.selection.bg_fill = egui::Color32::from_rgb(57, 119, 255);
        visuals.panel_fill = egui::Color32::from_rgb(18, 20, 26);
        visuals.extreme_bg_color = egui::Color32::from_rgb(12, 13, 18);
        ctx.set_visuals(visuals);

        ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(8.0, 8.0);
            style.spacing.button_padding = egui::vec2(10.0, 6.0);
            style.spacing.indent = 14.0;
        });

        egui::TopBottomPanel::top("header")
            .exact_height(68.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.heading("🛰️ Telegram Config Collector");
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!("Total new: {}", self.total_configs)).strong(),
                    );

                    if !self.running {
                        if ui
                            .add(
                                egui::Button::new("▶ Start Collection")
                                    .fill(egui::Color32::from_rgb(36, 116, 242)),
                            )
                            .clicked()
                        {
                            self.start();
                        }
                    } else if ui
                        .add(egui::Button::new("⏹ Stop").fill(egui::Color32::from_rgb(170, 54, 54)))
                        .clicked()
                    {
                        self.stop();
                    }

                    if ui.button("💾 Save Settings").clicked() {
                        match save_channels(&self.channels_text).and_then(|_| self.config.save()) {
                            Ok(_) => self.logs.push("Settings saved.".to_string()),
                            Err(e) => self.logs.push(format!("Save failed: {e:#}")),
                        }
                    }
                });
            });

        egui::SidePanel::left("settings_panel")
            .resizable(true)
            .default_width(370.0)
            .min_width(320.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.group(|ui| {
                        ui.heading("Main Settings");
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label("Check interval (minutes)");
                            ui.add(
                                egui::DragValue::new(&mut self.config.interval_minutes)
                                    .range(1..=240),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Max pages per channel");
                            ui.add(
                                egui::DragValue::new(&mut self.config.max_pages_per_channel)
                                    .range(1..=100),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Look back days");
                            ui.add(
                                egui::DragValue::new(&mut self.config.lookback_days).range(1..=30),
                            );
                        });
                    });

                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.heading("Proxy");
                        ui.separator();
                        egui::ComboBox::from_label("Type")
                            .selected_text(match self.config.proxy_type {
                                ProxyType::None => "No proxy",
                                ProxyType::System => "System proxy",
                                ProxyType::Http => "HTTP",
                                ProxyType::Socks5 => "SOCKS5",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.config.proxy_type,
                                    ProxyType::None,
                                    "No proxy",
                                );
                                ui.selectable_value(
                                    &mut self.config.proxy_type,
                                    ProxyType::System,
                                    "System proxy",
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

                        if matches!(self.config.proxy_type, ProxyType::Http | ProxyType::Socks5) {
                            ui.label("Proxy host");
                            ui.text_edit_singleline(&mut self.config.proxy_host);
                            ui.horizontal(|ui| {
                                ui.label("Port");
                                ui.add(
                                    egui::DragValue::new(&mut self.config.proxy_port)
                                        .range(1..=65535),
                                );
                            });
                            ui.label("Username (optional)");
                            ui.text_edit_singleline(&mut self.config.proxy_username);
                            ui.label("Password (optional)");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.config.proxy_password)
                                    .password(true),
                            );
                        }
                    });

                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.heading("Output Modes");
                        ui.separator();
                        ui.checkbox(
                            &mut self.config.output_new_only_enabled,
                            "Replace with new-only output (output/new_only)",
                        );
                        ui.checkbox(
                            &mut self.config.output_append_unique_enabled,
                            "Append unique output (output/append_unique)",
                        );
                    });

                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.heading("Protocols (Enable/Disable + Limit)");
                        ui.separator();
                        for (name, rule) in &mut self.config.protocol_rules {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut rule.enabled, name);
                                ui.add_space(4.0);
                                ui.label("Max");
                                ui.add(egui::DragValue::new(&mut rule.max_count).range(1..=50000));
                            });
                        }
                    });
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |columns| {
                columns[0].group(|ui| {
                    ui.heading("Channels");
                    ui.label("One channel per line (@channel or https://t.me/channel)");
                    ui.add_space(4.0);
                    ui.add_sized(
                        [ui.available_width(), ui.available_height() - 12.0],
                        egui::TextEdit::multiline(&mut self.channels_text),
                    );
                });

                columns[1].group(|ui| {
                    ui.heading("Live Logs");
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in self.logs.iter().rev().take(400).rev() {
                                ui.label(line);
                            }
                        });
                    ui.separator();
                    ui.heading("By protocol");
                    for (k, v) in &self.by_protocol {
                        ui.label(format!("{k}: {v}"));
                    }
                });
            });
        });

        ctx.request_repaint_after(Duration::from_millis(200));
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
        let _ = tx.send(WorkerEvent::Log(
            "No valid channels were provided.".to_string(),
        ));
        return Ok(());
    }

    let client = build_client(&config)?;
    let regex = build_protocol_regex()?;
    let mut history = SentHistory::load();

    loop {
        if stop.load(Ordering::SeqCst) {
            log_event(&tx, "Worker stopped.".to_string());
            break;
        }

        history.prune(config.lookback_days);
        let threshold = Utc::now() - ChronoDuration::days(config.lookback_days.max(1));
        let mut gathered: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for channel in &channels {
            log_event(&tx, format!("Processing @{channel}"));
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
                Err(e) => log_event(&tx, format!("Error on @{channel}: {e:#}")),
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
        if config.output_new_only_enabled {
            write_outputs_replace(OUTPUT_NEW_DIR, &new_only)?;
        }
        if config.output_append_unique_enabled {
            write_outputs_append_unique(OUTPUT_APPEND_DIR, &new_only)?;
        }
        if !config.output_new_only_enabled && !config.output_append_unique_enabled {
            log_event(
                &tx,
                "No output mode enabled; skipping file writes.".to_string(),
            );
        }
        history.prune(config.lookback_days);
        history.save()?;

        let mut by_protocol = BTreeMap::new();
        let mut total = 0;
        for (k, v) in &new_only {
            by_protocol.insert(k.clone(), v.len());
            total += v.len();
        }
        let _ = tx.send(WorkerEvent::Stats { total, by_protocol });
        log_event(&tx, format!("Completed. New configs found: {total}"));

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

        let resp = client.get(&url).send().context("request failed")?;
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

fn write_outputs_replace(base_dir: &str, store: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    fs::create_dir_all(base_dir)?;
    let mut mixed = Vec::new();
    for (p, links) in store {
        let lines: Vec<String> = links.iter().cloned().collect();
        fs::write(
            Path::new(base_dir).join(format!("{p}.txt")),
            lines.join("\n"),
        )?;
        mixed.extend(lines);
    }
    fs::write(Path::new(base_dir).join("mixed.txt"), mixed.join("\n"))?;
    Ok(())
}

fn write_outputs_append_unique(
    base_dir: &str,
    store: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    fs::create_dir_all(base_dir)?;

    for (p, links) in store {
        let path = Path::new(base_dir).join(format!("{p}.txt"));
        let mut combined = read_existing_set(&path)?;
        combined.extend(links.iter().cloned());
        let lines: Vec<String> = combined.into_iter().collect();
        fs::write(&path, lines.join("\n"))?;
    }

    let mixed_path = Path::new(base_dir).join("mixed.txt");
    let mut mixed = read_existing_set(&mixed_path)?;
    for links in store.values() {
        mixed.extend(links.iter().cloned());
    }
    let mixed_lines: Vec<String> = mixed.into_iter().collect();
    fs::write(mixed_path, mixed_lines.join("\n"))?;

    Ok(())
}

fn read_existing_set(path: &Path) -> Result<BTreeSet<String>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let raw = fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect())
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

    match config.proxy_type {
        ProxyType::None => {
            b = b.no_proxy();
        }
        ProxyType::System => {}
        ProxyType::Http | ProxyType::Socks5 => {
            if config.proxy_host.trim().is_empty() {
                anyhow::bail!("Proxy host is required for HTTP/SOCKS5 proxy mode");
            }
            b = b.no_proxy();
            let scheme = match config.proxy_type {
                ProxyType::Http => "http",
                ProxyType::Socks5 => "socks5h",
                ProxyType::None | ProxyType::System => unreachable!(),
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
