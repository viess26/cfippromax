#!/usr/bin/env python3
"""本地验证 ProxyIP：用你自己的网络逐个测试，输出能真正连通 Cloudflare 的 IP。

用法:
  python verify.py                                   # 读取 results/residential_proxy.txt
  python verify.py results/cfip.txt                  # 指定本地文件
  python verify.py https://raw.githubusercontent.com/你/cfip/main/results/residential_proxy.txt
  python verify.py results/residential_direct.txt --tcp   # 只测端口连通和延迟(非反代/OpenVPN TCP节点)
  python verify.py results/openvpn.txt --tcp              # UDP 节点会被跳过，需用客户端实测
"""
import asyncio, re, ssl, statistics, sys, time, urllib.request
from pathlib import Path

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
TCP_MODE = "--tcp" in sys.argv
SRC = ARGS[0] if ARGS else "results/residential_proxy.txt"
OUT = Path("results/tcp_verified.txt" if TCP_MODE else "results/proxy_verified.txt")
CONC, TRIES, TIMEOUT = 100, 3, 4.0
LINE_RE = re.compile(r"^\s*((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?(?:/(\w+))?")


def load(src):
    if src.startswith("http"):
        text = urllib.request.urlopen(src, timeout=20).read().decode("utf-8", "ignore")
    else:
        text = Path(src).read_text(encoding="utf-8", errors="ignore")
    items = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            if (m.group(3) or "tcp").lower().startswith("udp"):
                print(f"跳过 UDP 节点 {m.group(1)}:{m.group(2)}（脚本无法测，请用客户端）")
                continue
            items.append((m.group(1), int(m.group(2) or 443)))
    return list(dict.fromkeys(items))


async def probe(ip, port):
    """一次完整请求：TLS 握手 + /cdn-cgi/trace，返回 (耗时ms, colo, loc)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname="speed.cloudflare.com"), TIMEOUT)
        w.write(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n")
        data = await asyncio.wait_for(r.read(4096), TIMEOUT)
        ms = (time.perf_counter() - t) * 1000
        w.close()
        colo = re.search(rb"colo=(\w+)", data)
        loc = re.search(rb"loc=(\w+)", data)
        if not colo:
            return None
        return ms, colo.group(1).decode(), (loc.group(1).decode() if loc else "?")
    except Exception:
        return None


async def tcp_probe(ip, port):
    t = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), TIMEOUT)
        ms = (time.perf_counter() - t) * 1000
        w.close()
        return ms, "-", "-"
    except Exception:
        return None


async def check(item, sem):
    ip, port = item
    fn = tcp_probe if TCP_MODE else probe
    async with sem:
        results = [await fn(ip, port) for _ in range(TRIES)]
    ok = [r for r in results if r]
    if len(ok) < TRIES:  # 要求每次都成功，过滤不稳定的
        return None
    return statistics.median(r[0] for r in ok), ok[0][1], ok[0][2], ip, port


async def main():
    items = load(SRC)
    print(f"读取 {len(items)} 个，开始用本地网络验证...")
    sem = asyncio.Semaphore(CONC)
    res = [r for r in await asyncio.gather(*(check(i, sem) for i in items)) if r]
    res.sort()
    OUT.parent.mkdir(exist_ok=True)
    fmt = (lambda ms, colo, loc, ip, port: f"{ip}:{port}#{ms:.0f}ms") if TCP_MODE else \
          (lambda ms, colo, loc, ip, port: f"{ip}:{port}#{loc}-{colo}-{ms:.0f}ms")
    OUT.write_text("".join(fmt(*r) + "\n" for r in res), encoding="utf-8")
    print(f"可用 {len(res)}/{len(items)} -> {OUT}")
    for ms, colo, loc, ip, port in res[:10]:
        print(f"  {ip}:{port}  {ms:.0f}ms" + ("" if TCP_MODE else f"  出口 {loc}/{colo}"))


asyncio.run(main())
