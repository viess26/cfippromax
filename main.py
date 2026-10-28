#!/usr/bin/env python3
"""CF 优选 IP + 家宽 IP 收集器"""
import asyncio, ipaddress, json, random, re, ssl, statistics, time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "results"
OUT.mkdir(exist_ok=True)
CFG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
CONC = CFG.get("concurrency", 300)


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore")


async def tcp_latency(ip, port=443, tries=3, timeout=2.0):
    """返回 TCP 握手中位延迟(ms)，失败返回 None"""
    ts = []
    for _ in range(tries):
        t = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            ts.append((time.perf_counter() - t) * 1000)
            w.close()
        except Exception:
            return None
    return statistics.median(ts)


async def cf_colo(ip):
    """通过 /cdn-cgi/trace 获取 Cloudflare 数据中心代码"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname="speed.cloudflare.com"), 3)
        w.write(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n")
        data = await asyncio.wait_for(r.read(2048), 3)
        w.close()
        m = re.search(rb"colo=(\w+)", data)
        return m.group(1).decode() if m else ""
    except Exception:
        return ""


async def run_pool(items, fn):
    sem = asyncio.Semaphore(CONC)

    async def one(x):
        async with sem:
            return x, await fn(x)

    return await asyncio.gather(*(one(x) for x in items))


# ---------- 1. Cloudflare 优选 IP ----------
async def do_cf():
    cfg = CFG["cloudflare"]
    ips = []
    for ver in ("ips-v4",):
        for cidr in http_get(f"https://www.cloudflare.com/{ver}").split():
            net = ipaddress.ip_network(cidr)
            # 每个 /24 随机取样
            subs = [net] if net.prefixlen >= 24 else list(net.subnets(new_prefix=24))
            for s in subs:
                hosts = s.num_addresses - 2
                for _ in range(cfg["sample_per_24"]):
                    ips.append(str(s.network_address + random.randint(1, max(hosts, 1))))
    ips = list(set(ips))
    print(f"[CF] 测试 {len(ips)} 个 IP")
    res = await run_pool(ips, tcp_latency)
    ok = sorted([(l, ip) for ip, l in res if l is not None])[: cfg["top_n"]]
    colos = await run_pool([ip for _, ip in ok], cf_colo)
    colo_map = dict(colos)
    lines = [f"{ip}:443#{colo_map.get(ip) or 'CF'}-{lat:.0f}ms" for lat, ip in ok]
    (OUT / "cfip.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[CF] 输出 {len(lines)} 条 -> results/cfip.txt")


# ---------- 2. 家宽 IP ----------
IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?:[:,](\d{2,5}))?\b")  # 支持 ip:port 和 CSV 的 ip,port


def _add(found, ip, port, default):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return
    found[(ip, int(port or default))] = 1


def collect_sources():
    import os, socket, base64 as b64, urllib.parse
    cfg = CFG["residential"]
    dp = cfg["default_port"]
    found = {}

    # 1) 在线文本/CSV 列表
    for url in cfg["sources"]:
        try:
            for ip, port in IP_RE.findall(http_get(url)):
                _add(found, ip, port, dp)
        except Exception as e:
            print(f"[家宽] 源失败 {url}: {e}")

    # 2) 本地文件 my_sources.txt（自己收集的 IP，一行一个 ip 或 ip:port）
    f = ROOT / cfg.get("local_file", "my_sources.txt")
    if f.exists():
        for ip, port in IP_RE.findall(f.read_text(encoding="utf-8", errors="ignore")):
            _add(found, ip, port, dp)

    # 3) 域名解析：DDNS 域名 / 公开 ProxyIP 域名 -> A 记录 (支持 domain 或 domain:port)
    for d in cfg.get("domains", []):
        host, _, port = d.partition(":")
        try:
            for r in socket.getaddrinfo(host, None, socket.AF_INET):
                _add(found, r[4][0], port, dp)
        except Exception as e:
            print(f"[家宽] 域名解析失败 {d}: {e}")

    # 4) Shodan 搜索（需 SHODAN_KEY，付费会员才能用过滤器）
    key = os.environ.get("SHODAN_KEY")
    for q in cfg.get("shodan_queries", []) if key else []:
        try:
            u = "https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode({"key": key, "query": q})
            for m in json.loads(http_get(u, 30)).get("matches", []):
                _add(found, m["ip_str"], m.get("port"), dp)
        except Exception as e:
            print("[家宽] Shodan 失败:", e)

    # 5) FOFA 搜索（需 FOFA_EMAIL + FOFA_KEY）
    em, fk = os.environ.get("FOFA_EMAIL"), os.environ.get("FOFA_KEY")
    for q in cfg.get("fofa_queries", []) if (em and fk) else []:
        try:
            u = "https://fofa.info/api/v1/search/all?" + urllib.parse.urlencode({
                "email": em, "key": fk, "qbase64": b64.b64encode(q.encode()).decode(),
                "size": 500, "fields": "ip,port"})
            for ip, port in json.loads(http_get(u, 30)).get("results", []):
                _add(found, ip, port, dp)
        except Exception as e:
            print("[家宽] FOFA 失败:", e)

    return list(found)


def ipapi_batch(ips):
    """ip-api 免费批量接口: 每次 100 个，限 15 次/分钟，仅 HTTP、仅限非商业"""
    info = {}
    for i in range(0, len(ips), 100):
        body = json.dumps([{"query": ip, "fields": "query,status,countryCode,isp,hosting,mobile,proxy"}
                           for ip in ips[i:i + 100]]).encode()
        req = urllib.request.Request("http://ip-api.com/batch", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            for r in json.loads(urllib.request.urlopen(req, timeout=20).read()):
                if r.get("status") == "success":
                    info[r["query"]] = r
        except Exception as e:
            print("[家宽] ip-api 失败:", e)
        time.sleep(4.5)
    return info


async def do_residential():
    cfg = CFG["residential"]
    cands = collect_sources()
    print(f"[家宽] 候选 {len(cands)} 个")
    if not cands:
        return
    res = await run_pool(cands, lambda x: tcp_latency(x[0], x[1], tries=2))
    alive = [(x, l) for x, l in res if l is not None]
    info = ipapi_batch(sorted({x[0] for x, _ in alive}))
    resi = []
    for (ip, port), lat in sorted(alive, key=lambda a: a[1]):
        i = info.get(ip)
        if not i or i["hosting"] or (i["mobile"] and not cfg["allow_mobile"]):
            continue  # 机房 / 移动网络 -> 排除
        resi.append((ip, port, lat, i))
    # 反代判定：该 IP 的 443 能用 CF 域名 SNI 返回 /cdn-cgi/trace(colo=xxx)，说明它在反代 Cloudflare
    traces = dict(await run_pool([r[0] for r in resi], cf_colo))
    proxy, direct = [], []
    for ip, port, lat, i in resi:
        isp = re.sub(r"[^\w\-]", "", i["isp"])[:20]
        colo = traces.get(ip)
        if colo:
            proxy.append(f"{ip}:{port}#{i['countryCode']}-{isp}-{colo}-{lat:.0f}ms")
        else:
            direct.append(f"{ip}:{port}#{i['countryCode']}-{isp}-{lat:.0f}ms")
    n = cfg["top_n"]
    (OUT / "residential_proxy.txt").write_text("\n".join(proxy[:n]) + "\n", encoding="utf-8")
    (OUT / "residential_direct.txt").write_text("\n".join(direct[:n]) + "\n", encoding="utf-8")
    print(f"[家宽] 反代 {len(proxy)} 条 / 非反代 {len(direct)} 条")


# ---------- 3. 家宽 OpenVPN 隧道节点 (VPN Gate 志愿者节点) ----------
def do_openvpn():
    import base64, csv, io
    cfg = CFG["openvpn"]
    try:
        raw = http_get(cfg["api"], timeout=30)
    except Exception as e:
        print("[OpenVPN] 拉取失败:", e)
        return
    lines = raw.replace("\r", "").split("\n")
    # 第1行 *vpn_servers，第2行 #表头，末行 *
    header = lines[1].lstrip("#").split(",")
    rows = list(csv.DictReader(io.StringIO("\n".join(lines[2:])), fieldnames=header))
    rows = [r for r in rows if r.get("IP") and r.get("OpenVPN_ConfigData_Base64")]
    print(f"[OpenVPN] 获取 {len(rows)} 个节点")
    info = ipapi_batch(sorted({r["IP"] for r in rows}))
    ovpn_dir = OUT / "ovpn"
    ovpn_dir.mkdir(exist_ok=True)
    for f in ovpn_dir.glob("*.ovpn"):
        f.unlink()
    picked = []
    for r in rows:
        i = info.get(r["IP"])
        if not i or i["hosting"]:
            continue  # 机房 IP 排除，只留家宽
        if cfg.get("exclude_mobile", True) and i["mobile"]:
            continue
        try:
            conf = base64.b64decode(r["OpenVPN_ConfigData_Base64"]).decode("utf-8", "ignore")
        except Exception:
            continue
        proto = (re.search(r"^proto\s+(\w+)", conf, re.M) or [0, "?"])[1]
        port = (re.search(r"^remote\s+\S+\s+(\d+)", conf, re.M) or [0, "?"])[1]
        picked.append((int(r.get("Score") or 0), r, i, conf, proto, port))
    picked.sort(key=lambda x: -x[0])  # 按 VPN Gate 评分排序
    out = []
    for n, (score, r, i, conf, proto, port) in enumerate(picked[: cfg["top_n"]]):
        isp = re.sub(r"[^\w\-]", "", i["isp"])[:20]
        name = f"{r['CountryShort']}-{r['IP']}-{proto}{port}.ovpn"
        (ovpn_dir / name).write_text(conf, encoding="utf-8")
        mbps = int(r.get("Speed") or 0) / 1e6
        out.append(f"{r['IP']}:{port}/{proto}#{r['CountryShort']}-{isp}-{r.get('Ping')}ms-{mbps:.0f}Mbps")
    (OUT / "openvpn.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"[OpenVPN] 家宽节点 {len(out)} 个 -> results/openvpn.txt, results/ovpn/*.ovpn")


async def main():
    await do_cf()
    await do_residential()
    do_openvpn()


if __name__ == "__main__":
    asyncio.run(main())
