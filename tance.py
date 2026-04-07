#!/usr/bin/env python3
"""
网络存活主机扫描器 v2.1 Final
Windows 专用 | ICMP+TCP双探测 | 断点续扫 | 速率限制 | 大网段低内存
解决漏扫核心：自动重试 + 合理并发 + TCP兜底
用途：内网资产探测、主机存活扫描，仅限授权环境使用
"""

import argparse
import ipaddress
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────────────
# ANSI 颜色支持
# ──────────────────────────────────────────────────────
try:
    import ctypes
    _k32 = ctypes.windll.kernel32
    _k32.SetConsoleMode(_k32.GetStdHandle(-11), 7)
    COLOR = True
except Exception:
    COLOR = False

G = "\033[92m" if COLOR else ""
Y = "\033[93m" if COLOR else ""
R = "\033[91m" if COLOR else ""
C = "\033[96m" if COLOR else ""
D = "\033[2m"  if COLOR else ""
X = "\033[0m"  if COLOR else ""

# 隐藏 CMD 窗口
_STARTUPINFO = None
try:
    _si = subprocess.STARTUPINFO()
    _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _si.wShowWindow = subprocess.SW_HIDE
    _STARTUPINFO = _si
except AttributeError:
    pass

# ──────────────────────────────────────────────────────
# 探测核心（防漏扫最终版）
# ──────────────────────────────────────────────────────

def ping_icmp(ip: str, timeout_ms: int, retry: int = 2) -> tuple:
    """增强 ICMP 探测，最多重试 2 次，大幅降低丢包漏扫"""
    for _ in range(retry):
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                startupinfo=_STARTUPINFO,
                timeout=(timeout_ms / 1000) + 3,
            )
            out = result.stdout.decode("gbk", errors="ignore").upper()
            if "TTL=" in out:
                for token in out.split():
                    tl = token.lower()
                    if tl.startswith("time=") or tl.startswith("时间="):
                        try:
                            return True, float(tl.split("=")[1].rstrip("ms毫秒"))
                        except ValueError:
                            return True, -1.0
                return True, -1.0
        except Exception:
            continue
    return False, -1.0

TCP_PORTS = [80, 443, 135, 445, 22, 3389, 8080]

def ping_tcp(ip: str, timeout_s: float) -> tuple:
    """TCP 常用端口兜底探测，禁 ping 主机也能发现"""
    for port in TCP_PORTS:
        try:
            t0 = time.perf_counter()
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True, (time.perf_counter() - t0) * 1000
        except OSError:
            continue
    return False, -1.0

def probe(ip: str, timeout_ms: int, tcp_fallback: bool) -> tuple:
    ok, rtt = ping_icmp(ip, timeout_ms, retry=2)
    if ok:
        return True, rtt, "ICMP"
    if tcp_fallback:
        ok, rtt = ping_tcp(ip, timeout_ms / 1000)
        if ok:
            return True, rtt, "TCP"
    return False, -1.0, "-"

# ──────────────────────────────────────────────────────
# 网段解析
# ──────────────────────────────────────────────────────

def _parse_single(token: str) -> list:
    token = token.strip()
    if token.count("/") == 2 and "-" in token:
        idx = token.index("-")
        left_cidr = token[:idx].strip()
        right_cidr = token[idx+1:].strip()
        net_start = ipaddress.ip_network(left_cidr, strict=False)
        net_end = ipaddress.ip_network(right_cidr, strict=False)
        if net_start.prefixlen != net_end.prefixlen:
            raise ValueError("CIDR 前缀长度必须一致")
        if int(net_start.network_address) > int(net_end.network_address):
            raise ValueError("起始网段不能大于结束网段")
        ips = []
        cur = int(net_start.network_address)
        stop = int(net_end.network_address)
        step = net_start.num_addresses
        while cur <= stop:
            net = ipaddress.ip_network(
                f"{ipaddress.ip_address(cur)}/{net_start.prefixlen}", strict=False
            )
            ips.extend(str(h) for h in net.hosts())
            cur += step
        return ips
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        return [str(h) for h in net.hosts()] or [str(net.network_address)]
    if "-" in token:
        left, right = token.split("-", 1)
        start = ipaddress.ip_address(left.strip())
        right = right.strip()
        if "." not in right:
            right = ".".join(str(start).split(".")[:-1]) + "." + right
        end = ipaddress.ip_address(right)
        if int(end) < int(start):
            raise ValueError("结束IP不能小于起始IP")
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end)+1)]
    return [str(ipaddress.ip_address(token))]

def parse_target(target: str) -> list:
    res = []
    for t in target.split(","):
        t = t.strip()
        if t:
            res.extend(_parse_single(t))
    return res

def collect_ips(networks: list, excludes: list) -> list:
    seen = set()
    ordered = []
    for n in networks:
        for ip in parse_target(n):
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)
    if excludes:
        excl = set()
        for e in excludes:
            excl.update(parse_target(e))
        ordered = [ip for ip in ordered if ip not in excl]
    return ordered

# ──────────────────────────────────────────────────────
# 断点续扫
# ──────────────────────────────────────────────────────

def resume_state_path(output_file: str) -> Path:
    return Path(output_file).with_suffix(".progress")

def load_done_set(state_path: Path) -> set:
    if not state_path.exists():
        return set()
    done = set()
    with state_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                done.add(line)
    return done

def append_done(state_path: Path, ip: str, lock: threading.Lock):
    with lock:
        with state_path.open("a", encoding="utf-8") as f:
            f.write(ip + "\n")

def append_alive(output_path: Path, ip: str, rtt: float, method: str, lock: threading.Lock):
    rtt_str = f"{rtt:.1f}ms" if rtt >= 0 else "N/A"
    with lock:
        with output_path.open("a", encoding="utf-8") as f:
            f.write(f"{ip}\t{rtt_str}\t{method}\n")

# ──────────────────────────────────────────────────────
# 速率限制
# ──────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, rate: int):
        self.rate = rate
        self._tokens = float(rate) if rate > 0 else 0.0
        self._last = time.monotonic()
        self._lock = threading.Lock()
    def acquire(self):
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.rate, self._tokens + (now - self._last)*self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
            time.sleep(0.005)

# ──────────────────────────────────────────────────────
# 扫描引擎
# ──────────────────────────────────────────────────────

def run_scan(
    targets, timeout_ms, concurrency, tcp_fallback, verbose,
    output_file, resume, rate, excluded_count, batch_size=500
):
    total_raw = len(targets)
    out_path = Path(output_file) if output_file else None
    state_path = resume_state_path(output_file) if output_file else None

    done_set = set()
    if resume and state_path:
        done_set = load_done_set(state_path)
        skip = sum(1 for ip in targets if ip in done_set)
        if skip:
            print(f"{Y}[续扫] 跳过已扫 {skip} 个IP{X}")
        targets = [ip for ip in targets if ip not in done_set]

    total = len(targets)
    if total == 0:
        print(f"{G}[完成] 无待扫描IP{X}")
        return []

    alive_hosts = []
    file_lock = threading.Lock()
    state_lock = threading.Lock()
    print_lock = threading.Lock()
    counter = [0]
    start_time = time.monotonic()
    rate_limiter = RateLimiter(rate)
    stop_event = threading.Event()

    if out_path and not resume:
        out_path.write_text(
            f"# 扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# 格式: IP\t响应时间\t探测方式\n\n", encoding="utf-8"
        )

    print(f"\n{C}{'═'*62}{X}")
    print(f"{C}  网络存活主机扫描器 v2.1 Final  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    print(f"{C}{'═'*62}{X}")
    print(f"  目标IP总数   : {total_raw:,}")
    if excluded_count:
        print(f"  已排除IP数   : {Y}{excluded_count:,}{X}")
    print(f"  本次扫描数   : {total:,}")
    print(f"  超时(ms)     : {timeout_ms}")
    print(f"  并发线程数   : {concurrency}")
    print(f"  每秒探测上限 : {'无限制' if rate<=0 else rate}")
    print(f"  TCP兜底探测  : {'开启' if tcp_fallback else '关闭'}")
    print(f"  断点续扫     : {'开启' if resume else '关闭'}")
    if out_path:
        print(f"  输出文件     : {out_path}")
    print(f"{C}{'═'*62}{X}\n")

    original_sigint = signal.getsignal(signal.SIGINT)
    def _sigint(sig, frame):
        stop_event.set()
    signal.signal(signal.SIGINT, _sigint)

    def _progress(done):
        pct = done / total
        bar_len = 26
        filled = int(bar_len * pct)
        bar = "█"*filled + "░"*(bar_len-filled)
        elapsed = time.monotonic() - start_time
        speed = done / elapsed if elapsed>0 else 0
        eta_s = (total-done)/speed if speed>0 else 0
        if eta_s < 3600:
            eta = f"{int(eta_s//60)}m{int(eta_s%60):02d}s"
        else:
            eta = f"{int(eta_s//3600)}h{int((eta_s%3600)//60):02d}m"
        return (f"\r  [{bar}] {done:,}/{total:,} ({pct:.1%})"
                f"  存活:{G}{len(alive_hosts)}{X}  {speed:.0f}/s  ETA:{eta}   ")

    def worker(ip):
        if stop_event.is_set():
            return
        rate_limiter.acquire()
        alive, rtt, method = probe(ip, timeout_ms, tcp_fallback)
        with print_lock:
            counter[0] += 1
            sys.stdout.write(_progress(counter[0]))
            sys.stdout.flush()
            if alive:
                rtt_str = f"{rtt:.1f}ms" if rtt>=0 else "N/A"
                alive_hosts.append({"ip":ip, "rtt":rtt_str, "method":method})
                if verbose:
                    print(f"\n  {G}[+] {ip:<18} 存活  {rtt_str:<10} {method}{X}")
        if alive and out_path:
            append_alive(out_path, ip, rtt, method, file_lock)
        if state_path:
            append_done(state_path, ip, state_lock)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        i = 0
        while i < len(targets) and not stop_event.is_set():
            batch = targets[i:i+batch_size]
            futs = [executor.submit(worker, ip) for ip in batch]
            for f in as_completed(futs):
                pass
            i += batch_size

    signal.signal(signal.SIGINT, original_sigint)
    if stop_event.is_set():
        print(f"\n\n{Y}[中断] 安全停止，可使用 --resume 续扫{X}")
    else:
        print()

    alive_hosts.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
    elapsed_total = time.monotonic() - start_time

    print(f"\n{C}{'═'*62}{X}")
    print(f"{C}  扫描结果{X}")
    print(f"{C}{'═'*62}{X}")
    if alive_hosts:
        print(f"  {'IP地址':<20} {'响应时间':<12} 探测方式")
        print(f"  {D}{'-'*18}  {'-'*10}  {'-'*8}{X}")
        for h in alive_hosts:
            print(f"  {G}{h['ip']:<20}{X} {h['rtt']:<12} {h['method']}")
    else:
        print(f"  {Y}未发现存活主机{X}")

    scanned = counter[0]
    avg_speed = scanned / elapsed_total if elapsed_total>0 else 0
    print(f"\n  摘要: 扫描{scanned}个IP  存活{len(alive_hosts)}台  耗时{elapsed_total:.0f}s  平均{avg_speed:.0f}/s")
    print(f"{C}{'═'*62}{X}\n")

    if out_path:
        with out_path.open("a", encoding="utf-8") as f:
            f.write(f"\n# 结束：扫描{scanned}个IP，存活{len(alive_hosts)}台\n")
        print(f"{G}结果已保存: {out_path}{X}")
        if state_path and state_path.exists() and not stop_event.is_set():
            try:
                state_path.unlink()
            except:
                pass
    return alive_hosts

# ──────────────────────────────────────────────────────
# 命令行参数
# ──────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="network_scanner",
        description="网络存活主机扫描器 v2.1 Final | ICMP+TCP双探测 | 防漏扫稳定版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
推荐稳定命令（不漏IP）：
  python network_scanner.py -n 192.168.1.0/24 -c 100 --rate 120 -t 1000 --tcp-fallback -o alive.txt
B段大网段：
  python network_scanner.py -n 10.0.0.0/16 -c 100 --rate 120 -t 1000 --tcp-fallback -o alive.txt
断点续扫：
  python network_scanner.py -n 10.0.0.0/16 -c 100 --rate 120 -t 1000 --tcp-fallback -o alive.txt --resume
"""
    )
    p.add_argument("-n", "--networks", nargs="+", required=True, help="目标网段 CIDR/IP范围/多网段")
    p.add_argument("-e", "--exclude", nargs="+", default=[], help="排除IP/网段")
    p.add_argument("-t", "--timeout", type=int, default=1000, help="超时毫秒 默认1000")
    p.add_argument("-c", "--concurrency", type=int, default=100, help="并发线程 默认100")
    p.add_argument("--rate", type=int, default=120, help="每秒探测数 默认120")
    p.add_argument("--tcp-fallback", action="store_true", help="启用TCP兜底探测（强烈建议）")
    p.add_argument("-v", "--verbose", action="store_true", help="实时显示存活IP")
    p.add_argument("-o", "--output", help="保存结果到文件")
    p.add_argument("--resume", action="store_true", help="断点续扫")
    p.add_argument("--force", action="store_true", help="跳过大型网段确认")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not (50 <= args.timeout <= 10000):
        print(f"{R}超时必须在50-10000之间{X}")
        return
    if not (1 <= args.concurrency <= 512):
        print(f"{R}并发必须在1-512之间{X}")
        return
    if args.rate < 0:
        print(f"{R}速率不能为负{X}")
        return
    if args.resume and not args.output:
        print(f"{R}--resume 必须配合 -o 使用{X}")
        return

    try:
        all_ips = collect_ips(args.networks, args.exclude)
    except Exception as e:
        print(f"{R}解析失败: {e}{X}")
        return

    excluded_count = 0
    try:
        raw = sum(len(parse_target(n)) for n in args.networks)
        excluded_count = raw - len(all_ips)
    except:
        pass

    if not all_ips:
        print(f"{R}无有效IP{X}")
        return

    if len(all_ips) > 1024 and not args.force:
        print(f"{Y}目标IP数量: {len(all_ips):,}{X}")
        print("请确认已获得授权，输入 yes 继续，其他退出：")
        try:
            if input("> ").strip().lower() != "yes":
                print("已退出")
                return
        except:
            return

    run_scan(
        targets=all_ips,
        timeout_ms=args.timeout,
        concurrency=args.concurrency,
        tcp_fallback=args.tcp_fallback,
        verbose=args.verbose,
        output_file=args.output,
        resume=args.resume,
        rate=args.rate,
        excluded_count=excluded_count
    )

if __name__ == "__main__":
    main()
