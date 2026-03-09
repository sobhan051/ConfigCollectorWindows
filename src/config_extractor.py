import os
import re
import base64
import logging
import html
import json
import copy
import shutil
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# ==========================================
# تنظیمات لاگ‌گیری حرفه‌ای (Professional Logging)
# ==========================================
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(asctime)s - [%(levelname)s] - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_str + reset,
        logging.INFO: green + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

logger = logging.getLogger("Extractor")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

def get_repo_context():
    repo = os.getenv("GITHUB_REPOSITORY", "ConfigCollectorWindows/ConfigCollectorWindows")
    branch = os.getenv("GITHUB_REF_NAME", "main")
    return repo, branch


def build_raw_url(path):
    repo, branch = get_repo_context()
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{path.lstrip('/')}"


# ==========================================
# تنظیمات کاربر (لینک‌های جهت تقسیم‌بندی)
# ==========================================
SPLIT_SOURCES = [
    {'path': 'sub/tested/ping_passed.txt', 'url': build_raw_url('sub/tested/ping_passed.txt'), 'name': 'ping_passed', 'chunk_size': 500, 'allow_remote_fallback': False},
    {'path': 'sub/all/mixed.txt', 'url': build_raw_url('sub/all/mixed.txt'), 'name': 'mixed', 'chunk_size': 500, 'allow_remote_fallback': False},
    {'path': 'sub/all/vless.txt', 'url': build_raw_url('sub/all/vless.txt'), 'name': 'vless', 'chunk_size': 500, 'allow_remote_fallback': False},
    {'path': 'sub/all/vmess.txt', 'url': build_raw_url('sub/all/vmess.txt'), 'name': 'vmess', 'chunk_size': 500, 'allow_remote_fallback': False},
    {'path': 'sub/all/trojan.txt', 'url': build_raw_url('sub/all/trojan.txt'), 'name': 'trojan', 'chunk_size': 500, 'allow_remote_fallback': False},
    {'path': 'sub/all/ss.txt', 'url': build_raw_url('sub/all/ss.txt'), 'name': 'ss', 'chunk_size': 500, 'allow_remote_fallback': False},
]

# ==========================================
# تنظیمات پروتکل‌ها و الگوها
# ==========================================
PROTOCOLS = [
    'vmess', 'vless', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2',
    'hy2', 'juicity', 'snell', 'anytls', 'ssh', 'wireguard', 'wg',
    'warp', 'socks', 'socks4', 'socks5', 'tg',
    'dns', 'nm-dns', 'nm-vless', 'slipnet-enc', 'slipnet', 'slipstream', 'dnstt'
]

NON_MIXED_PROTOCOLS = {'tg', 'dns', 'nm-dns', 'nm-vless', 'slipnet-enc', 'slipnet', 'slipstream', 'dnstt'}
NON_VALIDATED_PROTOCOLS = NON_MIXED_PROTOCOLS.copy()

CLOUDFLARE_DOMAINS = ('.workers.dev', '.pages.dev', '.trycloudflare.com', 'chatgpt.com')

NEXT_CONFIG_LOOKAHEAD = r'(?=' + '|'.join([rf'{re.escape(p)}:(?:\/\/|\/)' for p in PROTOCOLS if p != 'tg']) + r'|https:\/\/t\.me\/(?:proxy|socks)\?|tg:\/\/(?:proxy|socks)\?|[()\[\]"\'\s])'

BLOCKED_SERVERS = ("127.0.0.1", "0.0.0.0", "localhost", "t.me", "github.com", "raw.githubusercontent.com", "google.com")
VALID_SS_CIPHERS = {
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
    "aes-128-gcm-siv", "aes-256-gcm-siv",
    "chacha20-ietf", "chacha20", "xchacha20",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
    "rabbit128-poly1305", "aegis-128l", "aegis-256", "aez-384",
    "deoxys-ii-256-128", "rc4-md5", "none"
}


# ==========================================
# توابع کمکی (Helper Functions)
# ==========================================



def normalize_b64(raw):
    if not raw:
        return None
    raw = raw.strip().replace('-', '+').replace('_', '/')
    raw += '=' * ((4 - len(raw) % 4) % 4)
    try:
        return base64.b64decode(raw).decode('utf-8')
    except Exception:
        return None


def parse_proxy_min(link):
    link = link.strip()
    low = link.lower()
    try:
        if low.startswith('vmess://'):
            payload = normalize_b64(link[8:])
            if not payload:
                return None
            data = json.loads(payload)
            return {'type': 'vmess', 'server': data.get('add', ''), 'port': int(data.get('port', 0) or 0), 'uuid': data.get('id', '')}

        if low.startswith('vless://'):
            u = urlparse(re.sub(r'^vless://', 'http://', link, flags=re.IGNORECASE))
            q = parse_qs(u.query)
            return {
                'type': 'vless', 'server': u.hostname or '', 'port': u.port or 0, 'uuid': u.username or '',
                'security': (q.get('security') or [''])[0],
                'reality_public_key': (q.get('pbk') or [''])[0],
                'reality_short_id': (q.get('sid') or [''])[0],
            }

        if low.startswith('trojan://'):
            u = urlparse(re.sub(r'^trojan://', 'http://', link, flags=re.IGNORECASE))
            return {'type': 'trojan', 'server': u.hostname or '', 'port': u.port or 0, 'password': u.username or ''}

        if low.startswith('tuic://'):
            u = urlparse(re.sub(r'^tuic://', 'http://', link, flags=re.IGNORECASE))
            return {'type': 'tuic', 'server': u.hostname or '', 'port': u.port or 0, 'uuid': u.username or '', 'password': u.password or ''}

        if low.startswith('hysteria2://') or low.startswith('hy2://'):
            u = urlparse(re.sub(r'^(hysteria2|hy2)://', 'http://', link, flags=re.IGNORECASE))
            return {'type': 'hysteria2', 'server': u.hostname or '', 'port': u.port or 0, 'password': u.username or ''}

        if low.startswith('hysteria://'):
            u = urlparse(re.sub(r'^hysteria://', 'http://', link, flags=re.IGNORECASE))
            q = parse_qs(u.query)
            auth = (q.get('auth') or q.get('obfsParam') or [''])[0]
            return {'type': 'hysteria', 'server': u.hostname or '', 'port': u.port or 0, 'auth_str': auth}

        if low.startswith('wireguard://') or low.startswith('wg://'):
            u = urlparse(re.sub(r'^(wireguard|wg)://', 'http://', link, flags=re.IGNORECASE))
            q = parse_qs(u.query)
            return {'type': 'wireguard', 'server': u.hostname or '', 'port': u.port or 51820, 'private-key': u.username or (q.get('privateKey') or [''])[0]}

        if low.startswith('snell://'):
            u = urlparse(re.sub(r'^snell://', 'http://', link, flags=re.IGNORECASE))
            q = parse_qs(u.query)
            return {'type': 'snell', 'server': u.hostname or '', 'port': u.port or 0, 'psk': u.username or (q.get('psk') or [''])[0]}

        if low.startswith('ssh://'):
            u = urlparse(re.sub(r'^ssh://', 'http://', link, flags=re.IGNORECASE))
            q = parse_qs(u.query)
            return {
                'type': 'ssh', 'server': u.hostname or '', 'port': u.port or 22,
                'user': u.username or '', 'password': u.password or '', 'private-key': (q.get('private-key') or [''])[0]
            }

        if low.startswith('ss://'):
            ss = link[5:].split('#', 1)[0]
            if '@' in ss:
                auth, host_part = ss.split('@', 1)
                auth_decoded = normalize_b64(auth) or auth
            else:
                decoded = normalize_b64(ss)
                if not decoded or '@' not in decoded:
                    return None
                auth_decoded, host_part = decoded.split('@', 1)
            if ':' not in auth_decoded or ':' not in host_part:
                return None
            method, password = auth_decoded.split(':', 1)
            server, port = host_part.rsplit(':', 1)
            return {'type': 'ss', 'server': server, 'port': int(port or 0), 'cipher': method, 'password': password}

        if low.startswith('ssr://'):
            decoded = normalize_b64(link[6:])
            if not decoded:
                return None
            core = decoded.split('/', 1)[0]
            parts = core.split(':')
            if len(parts) < 6:
                return None
            server, port, protocol, method, obfs, b64_pass = parts[:6]
            password = normalize_b64(b64_pass) or b64_pass
            return {'type': 'ssr', 'server': server, 'port': int(port or 0), 'protocol': protocol, 'cipher': method, 'obfs': obfs, 'password': password}
    except Exception:
        return None

    return None


def is_problematic_proxy(link):
    p = parse_proxy_min(link)
    if not p:
        return True

    server = str(p.get('server', '')).strip().lower()
    port = p.get('port')
    if not server or not isinstance(port, int) or port < 1 or port > 65535:
        return True
    if any(b in server for b in BLOCKED_SERVERS):
        return True

    ptype = p.get('type')
    if ptype in {'vmess', 'vless'} and not p.get('uuid'):
        return True
    if ptype in {'trojan', 'hysteria2'} and not p.get('password'):
        return True
    if ptype == 'wireguard' and not p.get('private-key'):
        return True
    if ptype == 'hysteria' and not p.get('auth_str'):
        return True
    if ptype == 'tuic' and (not p.get('uuid') or not p.get('password')):
        return True
    if ptype == 'snell' and not p.get('psk'):
        return True
    if ptype == 'ssh' and (not p.get('user') or (not p.get('password') and not p.get('private-key'))):
        return True

    if ptype == 'ss':
        cipher = str(p.get('cipher', '')).lower()
        if not cipher or not p.get('password') or cipher not in VALID_SS_CIPHERS:
            return True
    if ptype == 'ssr':
        cipher = str(p.get('cipher', '')).lower()
        if not p.get('password') or not p.get('protocol') or not p.get('obfs') or cipher not in VALID_SS_CIPHERS:
            return True

    if ptype == 'vless' and str(p.get('security', '')).lower() == 'reality':
        pbk = str(p.get('reality_public_key', '')).replace('=', '').strip()
        sid = str(p.get('reality_short_id', '')).strip()
        if len(pbk) != 43 or not re.fullmatch(r'[A-Za-z0-9\-_]+', pbk):
            return True
        if sid and (len(sid) > 16 or len(sid) % 2 != 0 or not re.fullmatch(r'[0-9a-fA-F]+', sid)):
            return True

    return False


def filter_problematic_configs(data_map):
    filtered = {k: set() for k in data_map.keys()}
    removed = 0

    for proto, lines in data_map.items():
        if proto in NON_VALIDATED_PROTOCOLS:
            filtered[proto].update(lines)
            continue
        for line in lines:
            if is_problematic_proxy(line):
                removed += 1
            else:
                filtered[proto].add(line)

    logger.info(f"Problematic proxy filter: kept={sum(len(v) for v in filtered.values())}, removed={removed}")
    return filtered

def get_flexible_pattern(protocol_prefix):
    if protocol_prefix == 'tg':
        prefix = rf'(?:tg:\/\/(?:proxy|socks)\?|https:\/\/t\.me\/(?:proxy|socks)\?)'
    elif protocol_prefix == 'dns':
        prefix = r'(?<![A-Za-z0-9-])dns:(?:\/\/|\/)'
    else:
        escaped = re.escape(protocol_prefix)
        prefix = rf'{escaped}:(?:\/\/|\/)'
    return rf'{prefix}(?:(?!\s{{4,}}|[()\[\]]).)+?(?={NEXT_CONFIG_LOOKAHEAD}|$)'

def clean_telegram_link(link):
    """پاکسازی لینک تلگرام"""
    try:
        link = html.unescape(link)
        link = re.sub(r'[()\[\]\s!.,;\'"]+$', '', link)
        return link
    except Exception as e:
        logger.error(f"Error cleaning link: {e}")
        return link

def is_windows_compatible(link):
    """فیلتر سخت‌گیرانه برای ویندوز (Secret Check)"""
    try:
        secret_match = re.search(r"secret=([a-zA-Z0-9%_\-]+)", link)
        if not secret_match:
            return False
        
        secret = secret_match.group(1).lower()
        
        # 1. ویندوز کاراکترهای خاص را نمی‌خپذیرد
        if '%' in secret or '_' in secret or '-' in secret:
            return False
        # 2. ویندوز سکرت‌های obfuscated (شروع با ee) را پشتیبانی نمی‌کند
        if secret.startswith('ee'):
            return False
        # 3. چک کردن هگزادسیمال بودن
        if secret.startswith('dd'):
            actual_secret = secret[2:]
        else:
            actual_secret = secret
        
        if not re.fullmatch(r'[0-9a-f]{32}', actual_secret):
            return False
            
        return True
    except Exception:
        return False

def is_behind_cloudflare(link):
    """تشخیص کانفیگ‌های پشت کلادفلر"""
    def check_domain(domain):
        if not domain: return False
        domain = domain.lower()
        return domain == "chatgpt.com" or any(domain.endswith(d) for d in CLOUDFLARE_DOMAINS)

    try:
        if not link.startswith('vmess://'):
            parsed = urlparse(link)
            if check_domain(parsed.hostname):
                return True
            query = parse_qs(parsed.query)
            for param in ['sni', 'host', 'peer']:
                values = query.get(param, [])
                if any(check_domain(v) for v in values):
                    return True
            return False
        else:
            # دیکد کردن Vmess
            b64_str = link[8:]
            missing_padding = len(b64_str) % 4
            if missing_padding: b64_str += '=' * (4 - missing_padding)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8')
                data = json.loads(decoded)
                for field in ['add', 'host', 'sni']:
                    if check_domain(data.get(field)):
                        return True
            except:
                return False
    except:
        return False
    return False

def save_content(directory, filename, content_list):
    """ذخیره محتوا در فایل متنی و Base64"""
    if not content_list: 
        return
    
    try:
        os.makedirs(directory, exist_ok=True)
        content_sorted = sorted(list(set(content_list)))
        content_str = "\n".join(content_sorted)
        
        # ذخیره فایل عادی
        file_path = os.path.join(directory, f"{filename}.txt")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content_str)
        
        # ذخیره فایل Base64
        b64_str = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
        b64_path = os.path.join(directory, f"{filename}_base64.txt")
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(b64_str)
            
    except Exception as e:
        logger.error(f"Failed to save {filename} in {directory}: {e}")

def extract_configs_from_text(text):
    """استخراج تمام کانفیگ‌ها از متن"""
    patterns = {p: get_flexible_pattern(p) for p in PROTOCOLS}
    extracted_data = {k: set() for k in PROTOCOLS}
    
    count = 0
    for proto, pattern in patterns.items():
        matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            raw_link = match.group(0).strip()
            clean_link = clean_telegram_link(raw_link) if proto == 'tg' else raw_link
            if clean_link:
                extracted_data[proto].add(clean_link)
                count += 1
    
    return extracted_data, count

def merge_hysteria(data_map):
    """ترکیب hy2 و hysteria2"""
    hy2_combined = set()
    if 'hysteria2' in data_map: hy2_combined.update(data_map['hysteria2'])
    if 'hy2' in data_map: hy2_combined.update(data_map['hy2'])
    
    processed_map = copy.deepcopy(data_map)
    if 'hy2' in processed_map: del processed_map['hy2']
    processed_map['hysteria2'] = hy2_combined
    return processed_map

def write_files_standard(data_map, output_dir):
    """
    نوشتن فایل‌های خروجی با جداسازی دقیق تلگرام.
    - tg_windows: فقط سازگار با دسکتاپ
    - tg_android: فقط ناسازگار با دسکتاپ (بدون اشتراک با بالا)
    - tg: همه موارد (میکس)
    """
    final_map = filter_problematic_configs(merge_hysteria(data_map))
    
    if not any(final_map.values()): 
        logger.debug(f"No configs to write for {output_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)
    
    mixed_content = set()
    cloudflare_content = set()
    slipnet_mixed_content = set()
    
    for proto, lines in final_map.items():
        if not lines: continue
        
        if proto not in NON_MIXED_PROTOCOLS:
            # پردازش عادی سایر پروتکل‌ها
            mixed_content.update(lines)
            for line in lines:
                if is_behind_cloudflare(line):
                    cloudflare_content.add(line)
            save_content(output_dir, proto, lines)

        elif proto == 'tg':
            # --- منطق جداسازی تلگرام ---
            windows_tg = set()
            android_tg = set()
            
            for link in lines:
                if is_windows_compatible(link):
                    windows_tg.add(link)
                else:
                    android_tg.add(link)
            
            # ذخیره فایل‌ها
            save_content(output_dir, "tg_windows", windows_tg) # فقط ویندوز
            save_content(output_dir, "tg_android", android_tg) # فقط اندروید
            save_content(output_dir, "tg", lines)              # میکس (شامل همه)
            
            logger.info(f"Telegram Configs in {output_dir}: Total={len(lines)}, Win={len(windows_tg)}, Android={len(android_tg)}")

        else:
            # پروتکل‌های جمع‌آوری‌شده که نباید وارد mixed شوند
            if proto in {'slipnet', 'slipnet-enc'}:
                slipnet_mixed_content.update(lines)
            save_content(output_dir, proto, lines)

    if mixed_content:
        save_content(output_dir, "mixed", mixed_content)
    if cloudflare_content:
        save_content(output_dir, "cloudflare", cloudflare_content)
    if slipnet_mixed_content:
        save_content(output_dir, "slipnet_mixed", slipnet_mixed_content)

def auto_base64_all(directory):
    """تولید Base64 برای تمام فایل‌های متنی موجود"""
    if not os.path.exists(directory): return
    logger.info(f"Running Auto-Base64 on: {directory}")
    
    count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".txt") and not file.endswith("_base64.txt"):
                name_without_ext = file[:-4]
                base64_name = f"{name_without_ext}_base64.txt"
                if base64_name not in files:
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        if content.strip():
                            b64_data = base64.b64encode(content.encode("utf-8")).decode("utf-8")
                            with open(os.path.join(root, base64_name), "w", encoding="utf-8") as f:
                                f.write(b64_data)
                            count += 1
                    except Exception as e:
                        logger.error(f"Auto-base64 error for {file}: {e}")
    logger.info(f"Generated {count} missing base64 files.")

def cleanup_legacy_hy2(directory):
    """حذف فایل‌های قدیمی hy2"""
    if not os.path.exists(directory): return
    deleted_count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == "hy2.txt" or file == "hy2_base64.txt":
                try:
                    os.remove(os.path.join(root, file))
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Error deleting {file}: {e}")
    if deleted_count > 0:
        logger.info(f"Cleaned up {deleted_count} legacy hy2 files.")

def fetch_url_content(url):
    """دانلود محتوا از اینترنت"""
    try:
        logger.info(f"Fetching URL: {url}")
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return ""


def load_split_source_content(item):
    """اولویت با فایل لوکال است؛ در صورت نبودن از URL خوانده می‌شود."""
    local_path = item.get('path')
    if local_path and os.path.isfile(local_path):
        try:
            logger.info(f"Loading local split source: {local_path}")
            with open(local_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read local split source {local_path}: {e}")

    if not item.get('allow_remote_fallback', True):
        if local_path:
            logger.warning(f"Split source not found locally (remote fallback disabled): {local_path}")
        return ""

    url = item.get('url')
    if url:
        return fetch_url_content(url)
    return ""

def save_split_output(config_list, base_name, chunk_size):
    """ذخیره فایل‌های تقسیم‌بندی شده"""
    if not config_list:
        logger.warning(f"No configs found for split source: {base_name}")
        return
    
    unique_configs = sorted(list(set(config_list)))
    total_configs = len(unique_configs)
    
    path_normal = os.path.join("sub", "split", "normal", base_name)
    path_base64 = os.path.join("sub", "split", "base64", base_name)
    
    os.makedirs(path_normal, exist_ok=True)
    os.makedirs(path_base64, exist_ok=True)
    
    chunks = [unique_configs[i:i + chunk_size] for i in range(0, total_configs, chunk_size)]
    
    logger.info(f"Splitting '{base_name}': {total_configs} configs into {len(chunks)} parts.")
    
    for idx, chunk in enumerate(chunks):
        file_number = str(idx + 1)
        content_str = "\n".join(chunk)
        b64_str = base64.b64encode(content_str.encode("utf-8")).decode("utf-8")
        
        with open(os.path.join(path_normal, file_number), "w", encoding="utf-8") as f:
            f.write(content_str)
            
        with open(os.path.join(path_base64, file_number), "w", encoding="utf-8") as f:
            f.write(b64_str)

def process_split_mode():
    """اجرای حالت تقسیم‌بندی"""
    if not SPLIT_SOURCES:
        return

    logger.info("==========================================")
    logger.info("       STARTING SPLIT MODE PROCESS        ")
    logger.info("==========================================")
    
    for item in SPLIT_SOURCES:
        name = item.get('name')
        chunk_size = item.get('chunk_size', 50)
        
        if not name:
            continue
        
        content = load_split_source_content(item)
        if content:
            extracted, count = extract_configs_from_text(content)
            merged_data = filter_problematic_configs(merge_hysteria(extracted))
            
            all_configs = []
            for proto, lines in merged_data.items():
                if proto != 'tg': 
                    all_configs.extend(lines)
            
            save_split_output(all_configs, name, chunk_size)


def extract_iran_configs_from_tested(base_dir="sub/tested"):
    """استخراج خروجی‌های دارای ایموجی پرچم ایران از نتایج تست"""
    if not os.path.isdir(base_dir):
        logger.warning(f"Tested directory not found for IR extraction: {base_dir}")
        return

    target_files = [
        "ping_passed.txt",
        "speed_passed.txt",
    ]

    iran_tagged = set()
    for file_name in target_files:
        file_path = os.path.join(base_dir, file_name)
        if not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if line and "🇮🇷" in line:
                        iran_tagged.add(line)
        except Exception as e:
            logger.error(f"IR extraction failed for {file_path}: {e}")

    save_content(base_dir, "emoji_iran", iran_tagged)
    logger.info(f"IR emoji extraction complete. Found {len(iran_tagged)} configs.")

def main():
    logger.info("Starting Config Extractor...")
    
    # --- بخش 1: پردازش پوشه تلگرام ---
    src_dir = "src/telegram"
    out_dir = "sub"
    source_out_dir = os.path.join(out_dir, "source")
    global_collection = {k: set() for k in PROTOCOLS}
    
    logger.info("==========================================")
    logger.info("      PROCESSING TELEGRAM DIRECTORY       ")
    logger.info("==========================================")

    if os.path.exists(src_dir):
        channels = os.listdir(src_dir)
        logger.info(f"Found {len(channels)} items in {src_dir}")
        
        for channel_name in channels:
            channel_path = os.path.join(src_dir, channel_name)
            
            # تغییر کلیدی در این قسمت انجام شد: استفاده از فایل txt به جای md
            txt_file = os.path.join(channel_path, "messages.txt")
            
            if not os.path.isfile(txt_file):
                # برای اطمینان از سازگاری با فایل‌های قدیمی که هنوز حذف نشده‌اند
                md_fallback = os.path.join(channel_path, "messages.md")
                if os.path.isfile(md_fallback):
                    txt_file = md_fallback
                else:
                    continue
                
            try:
                with open(txt_file, "r", encoding="utf-8") as f:
                    content = f.read()
                
                channel_data, count = extract_configs_from_text(content)
                logger.info(f"Channel: {channel_name} -> Found {count} configs")
                
                # اضافه کردن به کالکشن کلی
                for p, s in channel_data.items():
                    global_collection[p].update(s)
                
                # نوشتن فایل کانال
                write_files_standard(channel_data, os.path.join(source_out_dir, channel_name))
                
            except Exception as e:
                logger.error(f"Error processing channel {channel_name}: {e}")
        
        # نوشتن فایل All نهایی
        total_global = sum(len(v) for v in global_collection.values())
        if total_global > 0:
            logger.info(f"Writing Global Collection (Total: {total_global} configs)...")
            write_files_standard(global_collection, os.path.join(out_dir, "all"))
        else:
            logger.warning("Global collection is empty! No configs found in telegram folder.")
            
    else:
        logger.error(f"Source directory not found: {src_dir}")
        logger.error("Skipping Telegram processing. Check if 'src/telegram' exists.")
    
    # --- بخش 2: پردازش لینک‌های اسپلیت ---
    process_split_mode()

    # --- بخش 3: استخراج خروجی‌های ایرانی از نتایج تست ---
    extract_iran_configs_from_tested("sub/tested")

    # --- بخش 4: نهایی‌سازی و پاکسازی ---
    logger.info("==========================================")
    logger.info("           FINALIZING OUTPUTS             ")
    logger.info("==========================================")
    auto_base64_all(out_dir)
    cleanup_legacy_hy2(out_dir)
    
    logger.info("Job Completed Successfully.")

if __name__ == "__main__":
    main()
