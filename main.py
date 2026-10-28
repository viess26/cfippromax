#!/usr/bin/env python3
"""Cloudflare 优选 IP 收集器"""
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
def _sample_cidr(cidr, per24):
    """从 CIDR 里每个 /24 随机取 per24 个 IP；单个 IP 原样返回"""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return []
    if net.version != 4:
        return []
    if net.num_addresses == 1:
        return [str(net.network_address)]
    out = []
    subs = [net] if net.prefixlen >= 24 else list(net.subnets(new_prefix=24))
    for sub in subs:
        hosts = max(sub.num_addresses - 2, 1)
        for _ in range(per24):
            out.append(str(sub.network_address + random.randint(1, hosts)))
    return out


def collect_cf_ips(cfg):
    per24 = cfg["sample_per_24"]
    ips = set()
    # 1) Cloudflare 官方 IPv4 段
    try:
        for cidr in http_get("https://www.cloudflare.com/ips-v4").split():
            ips.update(_sample_cidr(cidr, per24))
    except Exception as e:
        print("[CF] 官方 IP 段获取失败:", e)
    # 2) 额外在线源（每行一个 IP 或 CIDR）
    cidr_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    for url in cfg.get("extra_sources", []):
        try:
            n = 0
            for tok in cidr_re.findall(http_get(url)):
                got = _sample_cidr(tok, per24)
                ips.update(got)
                n += len(got)
            print(f"[CF] 源 {url} -> {n}")
        except Exception as e:
            print(f"[CF] 源失败 {url}: {e}")
    # 3) 本地文件
    f = ROOT / cfg.get("local_file", "my_cf.txt")
    if f.exists():
        for tok in cidr_re.findall(f.read_text(encoding="utf-8", errors="ignore")):
            ips.update(_sample_cidr(tok, per24))
    return sorted(ips)


async def do_cf():
    cfg = CFG["cloudflare"]
    ips = collect_cf_ips(cfg)
    print(f"[CF] 测试 {len(ips)} 个 IP")
    res = await run_pool(ips, tcp_latency)
    alive = sorted([(l, ip) for ip, l in res if l is not None])
    ok = alive[: cfg["top_n"]]
    colos = await run_pool([ip for _, ip in ok], cf_colo)
    colo_map = dict(colos)
    lines = [f"{ip}:443#{colo_map.get(ip) or 'CF'}-{lat:.0f}ms" for lat, ip in ok]
    (OUT / "cfip.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # 候选池：更多存活 IP，供本地 verify.py --per-colo 按地区挑选
    pool = [f"{ip}:443#{lat:.0f}ms" for lat, ip in alive[: cfg.get("pool_n", 500)]]
    (OUT / "cfip_all.txt").write_text("\n".join(pool) + "\n", encoding="utf-8")
    print(f"[CF] 输出 {len(lines)} 条 -> results/cfip.txt")


async def main():
    await do_cf()


if __name__ == "__main__":
    asyncio.run(main())
