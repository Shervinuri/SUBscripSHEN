#!/usr/bin/env python3
# ☬SHΞN™ V2Ray Config Collector — Version 1.1  (single-folder)
# Description: Collects & normalizes VLESS/VMess/Shadowsocks configs from subscriptions
#              and saves *all* of them in one place (output/MainConfigs.txt).

import os, re, socket, json, base64, requests
from urllib.parse import urlparse, urlunparse

# ---------- Settings ----------
SOURCE_FILE   = "Source.txt"                 # لیست ساب‌لینک‌ها (یک URL در هر خط)
OUTPUT_DIR    = "output"                     # پوشهٔ مادرِ نهایی
OUTPUT_MAIN   = os.path.join(OUTPUT_DIR, "MainConfigs.txt")
IP_CACHE_FILE = "ip_cache.json"              # کش تشخیص کشور IP
HEADERS       = {"User-Agent": "ShenCollector/1.1"}
GEO_API       = "http://ip-api.com/json/{}?fields=countryCode"
TIMEOUT       = 15
# --------------------------------

# ---------- Helpers ----------
def is_base64(s: str) -> bool:
    s = s.strip()
    return len(s) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", s) is not None

def decode_b64(s: str) -> str:
    s += '=' * (-len(s) % 4)          # پَد برای طول‌های غیردقیق
    return base64.b64decode(s).decode("utf-8", errors="ignore")

def flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🏴‍☠️"
    return chr(127397 + ord(cc[0].upper())) + chr(127397 + ord(cc[1].upper()))

def geo_ip(ip: str, cache: dict) -> str:
    if not ip:
        return ""
    if ip in cache:
        return cache[ip]
    try:
        r = requests.get(GEO_API.format(ip), timeout=TIMEOUT, headers=HEADERS)
        cc = r.json().get("countryCode", "")
    except Exception:
        cc = ""
    cache[ip] = cc
    return cc

def nice_remark(proto: str, cc: str) -> str:
    return f"☬SHΞN™{flag(cc)}{proto}" if proto else f"☬SHΞN™{flag(cc)}"

def parse_lines(raw: str) -> list[str]:
    if is_base64(raw):
        raw = decode_b64(raw)
    return [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#")]

def transport_of(url: str, vmess_json: dict | None = None) -> str:
    if "type=" in url:
        m = re.search(r"type=([^&]+)", url)
        if m:
            return m.group(1)
    if vmess_json:
        return vmess_json.get("net", "")
    return "tcp"

def resolve_host(uri: str, vmess_json: dict | None = None) -> str | None:
    try:
        if uri.startswith("vmess://") and vmess_json:
            return vmess_json.get("add")
        host = urlparse(uri).hostname
        return socket.gethostbyname(host)
    except Exception:
        return None
# --------------------------------

def normalize(uri: str, ip_cache: dict) -> str | None:
    """برمی‌گرداند کانفیگ نهاییِ نرمال‌شده یا None اگر خطا داشت."""
    if uri.startswith("vmess://"):
        try:
            js = json.loads(decode_b64(uri[8:]))
            ip   = resolve_host(uri, js)
            cc   = geo_ip(ip, ip_cache)
            proto = transport_of("", js)
            js["ps"] = nice_remark(proto, cc)
            norm = base64.b64encode(json.dumps(js, separators=(",", ":")).encode()).decode()
            return "vmess://" + norm
        except Exception:
            return None

    if uri.startswith("vless://"):
        try:
            u     = urlparse(uri)
            ip    = resolve_host(uri)
            cc    = geo_ip(ip, ip_cache)
            proto = transport_of(uri)
            remark = nice_remark(proto, cc)
            return urlunparse((u.scheme, u.netloc, u.path, u.params, u.query, remark))
        except Exception:
            return None

    if uri.startswith("ss://"):
        try:
            base  = uri.split("#")[0]
            ip    = resolve_host(uri)
            cc    = geo_ip(ip, ip_cache)
            proto = transport_of(uri)
            return f"{base}#{nice_remark(proto, cc)}"
        except Exception:
            return None

    return None

# ---------- Main workflow ----------
def collect() -> None:
    if not os.path.exists(SOURCE_FILE):
        print(f"[ERR] File {SOURCE_FILE} not found.")
        return

    # اطمینان از وجود پوشهٔ خروجی
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # بارگذاری کش
    ip_cache = json.load(open(IP_CACHE_FILE)) if os.path.exists(IP_CACHE_FILE) else {}

    all_configs: set[str] = set()
    sub_urls = [u.strip() for u in open(SOURCE_FILE, encoding="utf-8") if u.strip()]

    for sub_url in sub_urls:
        try:
            resp  = requests.get(sub_url, timeout=TIMEOUT, headers=HEADERS)
            lines = parse_lines(resp.text)
            for line in lines:
                if line.startswith("trojan://"):   # نادیده گرفتن پروتکل‌های ناخواسته
                    continue
                norm = normalize(line, ip_cache)
                if norm and norm not in all_configs:
                    all_configs.add(norm)
        except Exception as e:
            print(f"[WARN] Skipping {sub_url}: {e}")

    # ذخیرهٔ خروجی واحد
    with open(OUTPUT_MAIN, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_configs)))

    # به‌روزرسانی کش IP
    with open(IP_CACHE_FILE, "w") as f:
        json.dump(ip_cache, f)

    print(f"[✓] Saved {len(all_configs)} unique configs to {OUTPUT_MAIN}")

# ---------- Entry ----------
if __name__ == "__main__":
    collect()
