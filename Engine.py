#!/usr/bin/env python3
# ☬SHΞN™ V2Ray Config Collector — Version 1.0
# Description: Collects and normalizes VLESS/VMess/Shadowsocks configs from subscriptions.

import os, re, socket, json, base64, requests
from urllib.parse import urlparse, parse_qs, urlunparse
from collections import defaultdict

SOURCE_FILE = "Source.txt"
OUTPUT_MAIN = "MainConfigs.txt"
IP_CACHE = "ip_cache.json"
HEADERS = {"User-Agent": "ShenCollector/1.0"}
GEO_API = "http://ip-api.com/json/{}?fields=countryCode"
TIMEOUT = 15

def is_base64(s):
    s = s.strip()
    return len(s) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", s)

def decode_b64(s):
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")

def get_flag(cc):
    if not cc or len(cc) != 2: return "🏴‍☠️"
    return chr(127397 + ord(cc[0].upper())) + chr(127397 + ord(cc[1].upper()))

def geo_ip(ip, cache):
    if ip in cache: return cache[ip]
    try:
        r = requests.get(GEO_API.format(ip), timeout=TIMEOUT, headers=HEADERS)
        cc = r.json().get("countryCode", "")
    except: cc = ""
    cache[ip] = cc
    return cc

def clean_remark(proto, cc):
    return f"☬SHΞN™{get_flag(cc)}{proto}" if proto else f"☬SHΞN™{get_flag(cc)}"

def parse_lines(raw):
    if is_base64(raw): raw = decode_b64(raw)
    return [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#")]

def get_transport(url, vmess_json=None):
    if "type=" in url: return re.search(r"type=([^&]+)", url).group(1)
    if vmess_json: return vmess_json.get("net", "")
    return "tcp"

def resolve_host(uri, vmess_json=None):
    try:
        if uri.startswith("vmess://") and vmess_json:
            return vmess_json.get("add")
        host = urlparse(uri).hostname
        return socket.gethostbyname(host)
    except:
        return None

def normalize(uri, ip_cache):
    if uri.startswith("vmess://"):
        try:
            js = json.loads(decode_b64(uri[8:]))
            ip = resolve_host(uri, js)
            cc = geo_ip(ip, ip_cache)
            proto = get_transport("", js)
            js["ps"] = clean_remark(proto, cc)
            norm = base64.b64encode(json.dumps(js, separators=(",", ":")).encode()).decode()
            return "vmess://" + norm, "vmess", cc
        except: return None
    elif uri.startswith("vless://"):
        try:
            u = urlparse(uri)
            ip = resolve_host(uri)
            cc = geo_ip(ip, ip_cache)
            proto = get_transport(uri)
            fragment = clean_remark(proto, cc)
            return urlunparse((u.scheme, u.netloc, u.path, u.params, u.query, fragment)), "vless", cc
        except: return None
    elif uri.startswith("ss://"):
        try:
            base = uri.split("#")[0]
            ip = resolve_host(uri)
            cc = geo_ip(ip, ip_cache)
            proto = get_transport(uri)
            return f"{base}#{clean_remark(proto, cc)}", "ss", cc
        except: return None
    return None

def collect():
    if not os.path.exists(SOURCE_FILE):
        print(f"[ERR] File {SOURCE_FILE} not found.")
        return

    urls = open(SOURCE_FILE).read().strip().splitlines()
    ip_cache = json.load(open(IP_CACHE)) if os.path.exists(IP_CACHE) else {}
    all_configs, by_proto, by_country = set(), defaultdict(list), defaultdict(list)

    for sub_url in urls:
        try:
            r = requests.get(sub_url.strip(), timeout=TIMEOUT, headers=HEADERS)
            lines = parse_lines(r.text)
            for line in lines:
                if line.startswith("trojan://"): continue
                result = normalize(line, ip_cache)
                if result:
                    norm, proto, cc = result
                    if norm in all_configs: continue
                    all_configs.add(norm)
                    by_proto[proto].append(norm)
                    by_country[cc or "Unknown"].append(norm)
        except Exception as e:
            print(f"[WARN] Skipping {sub_url}: {e}")

    # Write outputs
    with open(OUTPUT_MAIN, "w", encoding="utf-8") as f:
        f.write("\n".join(all_configs))
    for p in ["vless", "vmess", "ss"]:
        with open(f"{p.capitalize()}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(by_proto.get(p, [])))
    for cc, lst in by_country.items():
        with open(f"{cc}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lst))
    with open(IP_CACHE, "w") as f:
        json.dump(ip_cache, f)

    print(f"[✓] Total: {len(all_configs)} configs saved.")

if __name__ == "__main__":
    collect()
