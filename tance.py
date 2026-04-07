#!/usr/bin/env python3
"""
network_scanner.py  ─  Windows 网络存活主机扫描工具  v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
用途  : 内部网络资产发现 / 快速主机探活（B 段 / C 段均适用）
探测  : ICMP ping（Windows 原生命令），可选 TCP 备用端口
无端口扫描，无攻击性行为，仅用于授权网络。

新增（v2.0）
  ✦ 断点续扫  --resume      中断后从上次进度继续，无需重扫
  ✦ 速率限制  --rate        每秒最多发起 N 个探测，防止网络拥堵
  ✦ 实时落盘  --output      存活 IP 发现即追加写入，进程意外中断不丢数据
  ✦ 流式调度               IP 列表逐批投入线程池，B 段 6 万 IP 内存占用低
  ✦ 隐藏子窗口             大量 ping 进程不会在桌面闪烁
  ✦ ETA 预估               进度条实时显示剩余时间
  ✦ 大网段无需手动确认      通过 --force 跳过二次确认

快速上手（B 段示例）：
  python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt
  python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt --resume
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
# ANSI 颜色（Windows 10 v1511+ 终端原生支持）
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

# Windows 子进程启动标志：隐藏 CMD 窗口，避免 6 万次 ping 闪烁
_STARTUPINFO = None
try:
    _si = subprocess.STARTUPINFO()
    _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _si.wShowWindow = subprocess.SW_HIDE
    _STARTUPINFO = _si
except AttributeError:
    pass


# ──────────────────────────────────────────────────────
# 探测核心
# ──────────────────────────────────────────────────────

def ping_icmp(ip: str, timeout_ms: int) -> tuple:
    """Windows ping -n 1，返回 (alive, rtt_ms)。"""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            startupinfo=_STARTUPINFO,
            timeout=(timeout_ms / 1000) + 2,
        )
        out = result.stdout.decode("gbk", errors="ignore")
        if "TTL=" in out.upper():
            for token in out.split():
                tl = token.lower()
                if tl.startswith("time=") or tl.startswith("时间="):
                    try:
                        return True, float(tl.split("=")[1].rstrip("ms毫秒"))
                    except ValueError:
                        pass
            return True, -1.0
        return False, -1.0
    except Exception:
        return False, -1.0


TCP_PORTS = [80, 443, 135, 445, 22, 8080]

def ping_tcp(ip: str, timeout_s: float) -> tuple:
    """依次尝试常用端口 TCP 连接，任一成功即返回。"""
    for port in TCP_PORTS:
        try:
            t0 = time.perf_counter()
            with socket.create_connection((ip, port), timeout=timeout_s):
                return True, (time.perf_counter() - t0) * 1000
        except OSError:
            pass
    return False, -1.0


def probe(ip: str, timeout_ms: int, tcp_fallback: bool) -> tuple:
    """返回 (alive, rtt_ms, method)。"""
    ok, rtt = ping_icmp(ip, timeout_ms)
    if ok:
        return True, rtt, "ICMP"
    if tcp_fallback:
        ok, rtt = ping_tcp(ip, timeout_ms / 1000)
        if ok:
            return True, rtt, "TCP"
    return False, -1.0, "-"


# ──────────────────────────────────────────────────────
# 网段 / 排除解析
# ──────────────────────────────────────────────────────

def _parse_single(token: str) -> list:
    """
    解析单个网段 token，支持：
      ① 单 IP:          10.8.1.1
      ② CIDR:           10.8.0.0/16
      ③ IP 范围:        10.8.1.1-10.8.1.50  或简写  10.8.1.1-50
      ④ CIDR 范围:      10.18.50.0/24-10.18.100.0/24
         展开两个同前缀长度 CIDR 之间所有网段的全部主机 IP
    """
    token = token.strip()

    # ④ CIDR 范围：两个斜杠 + 一个连字符
    if token.count("/") == 2 and "-" in token:
        # 形如 "A.B.C.D/pA-E.F.G.H/pB"，以 "-" 分割（CIDR 本身无连字符）
        idx = token.index("-")
        left_cidr  = token[:idx].strip()
        right_cidr = token[idx+1:].strip()
        net_start = ipaddress.ip_network(left_cidr,  strict=False)
        net_end   = ipaddress.ip_network(right_cidr, strict=False)
        if net_start.prefixlen != net_end.prefixlen:
            raise ValueError(
                f"CIDR 范围两端前缀长度必须相同：{left_cidr} vs {right_cidr}"
            )
        if int(net_start.network_address) > int(net_end.network_address):
            raise ValueError(f"CIDR 范围起始 {left_cidr} 大于终止 {right_cidr}")
        ips = []
        cur  = int(net_start.network_address)
        stop = int(net_end.network_address)
        step = net_start.num_addresses
        while cur <= stop:
            net = ipaddress.ip_network(
                f"{ipaddress.ip_address(cur)}/{net_start.prefixlen}", strict=False
            )
            ips.extend(str(h) for h in net.hosts())
            cur += step
        return ips

    # ② 单 CIDR
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        return [str(h) for h in net.hosts()] or [str(net.network_address)]

    # ③ IP 范围
    if "-" in token:
        left, right = token.split("-", 1)
        start = ipaddress.ip_address(left.strip())
        right = right.strip()
        if "." not in right:
            right = ".".join(str(start).split(".")[:-1]) + "." + right
        end = ipaddress.ip_address(right)
        if int(end) < int(start):
            raise ValueError(f"范围终止 IP {end} 小于起始 IP {start}")
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]

    # ① 单 IP
    return [str(ipaddress.ip_address(token))]


def parse_target(target: str) -> list:
    """
    支持逗号分隔的多段字符串，每段交给 _parse_single 处理。
    如 '10.8.0.0/16,10.9.0.0/16' 或单个 '10.8.0.0/16' 均可。
    """
    results = []
    for token in target.split(","):
        token = token.strip()
        if token:
            results.extend(_parse_single(token))
    return results


def collect_ips(networks: list, excludes: list) -> list:
    """
    展开所有网段（每项支持逗号分隔），去重，过滤排除集，返回有序 IP 列表。
    """
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
        before = len(ordered)
        ordered = [ip for ip in ordered if ip not in excl]
        hit = before - len(ordered)
        print(f"{Y}[排除] 移除 {hit:,} 个 IP，剩余 {len(ordered):,} 个待扫描{X}")

    return ordered


# ──────────────────────────────────────────────────────
# 断点续扫：进度文件
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


def append_done(state_path: Path, ip: str, lock: threading.Lock) -> None:
    with lock:
        with state_path.open("a", encoding="utf-8") as f:
            f.write(ip + "\n")


def append_alive(output_path: Path, ip: str, rtt: float, method: str, lock: threading.Lock) -> None:
    """存活 IP 实时追加到输出文件。"""
    rtt_str = f"{rtt:.1f}ms" if rtt >= 0 else "N/A"
    with lock:
        with output_path.open("a", encoding="utf-8") as f:
            f.write(f"{ip}\t{rtt_str}\t{method}\n")


# ──────────────────────────────────────────────────────
# 速率限制器（令牌桶，线程安全）
# ──────────────────────────────────────────────────────

class RateLimiter:
    """每秒最多 rate 次 acquire()，超限则阻塞。"""
    def __init__(self, rate: int):
        self.rate = rate
        self._tokens = float(rate) if rate > 0 else 0.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.005)


# ──────────────────────────────────────────────────────
# 扫描引擎
# ──────────────────────────────────────────────────────

def run_scan(
    targets,
    timeout_ms,
    concurrency,
    tcp_fallback,
    verbose,
    output_file,
    resume,
    rate,
    excluded_count,
    batch_size=500,
):
    total_raw  = len(targets)
    out_path   = Path(output_file) if output_file else None
    state_path = resume_state_path(output_file) if output_file else None

    # 断点续扫：过滤已扫 IP
    done_set = set()
    if resume and state_path:
        done_set = load_done_set(state_path)
        skip = sum(1 for ip in targets if ip in done_set)
        if skip:
            print(f"{Y}[续扫] 跳过已扫 {skip} 个 IP，从第 {skip+1} 个继续{X}")
        targets = [ip for ip in targets if ip not in done_set]

    total = len(targets)
    if total == 0:
        print(f"{G}[完成] 所有 IP 均已在上次扫描中处理，无需重扫。{X}")
        return []

    alive_hosts  = []
    file_lock    = threading.Lock()
    state_lock   = threading.Lock()
    print_lock   = threading.Lock()
    counter      = [0]
    start_time   = time.monotonic()
    rate_limiter = RateLimiter(rate)
    stop_event   = threading.Event()

    # 初始化输出文件头（仅非续扫模式）
    if out_path and not resume:
        out_path.write_text(
            f"# 扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# 格式: IP\t响应时间\t探测方式\n\n",
            encoding="utf-8"
        )

    # 打印扫描头
    print(f"\n{C}{'═'*62}{X}")
    print(f"{C}  网络存活主机扫描器 v2.0  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    print(f"{C}{'═'*62}{X}")
    print(f"  目标 IP 总数  : {total_raw:,}")
    if excluded_count:
        print(f"  已排除 IP 数  : {Y}{excluded_count:,}{X}")
    if done_set:
        print(f"  续扫跳过数    : {Y}{len(done_set):,}{X}")
    print(f"  本次扫描数    : {total:,}")
    print(f"  超时(ms)      : {timeout_ms}")
    print(f"  并发线程数    : {concurrency}")
    print(f"  速率上限(/s)  : {'无限制' if rate <= 0 else rate}")
    print(f"  TCP 备用探测  : {'开启' if tcp_fallback else '关闭'}")
    print(f"  断点续扫      : {'开启' if resume else '关闭'}")
    if out_path:
        print(f"  输出文件      : {out_path}")
    print(f"{C}{'═'*62}{X}\n")

    # Ctrl+C 优雅退出
    original_sigint = signal.getsignal(signal.SIGINT)
    def _sigint(sig, frame):
        stop_event.set()
    signal.signal(signal.SIGINT, _sigint)

    def _progress(done):
        pct     = done / total
        bar_len = 26
        filled  = int(bar_len * pct)
        bar     = "█" * filled + "░" * (bar_len - filled)
        elapsed = time.monotonic() - start_time
        speed   = done / elapsed if elapsed > 0 else 0
        eta_s   = (total - done) / speed if speed > 0 else 0
        if eta_s < 3600:
            eta = f"{int(eta_s//60)}m{int(eta_s%60):02d}s"
        else:
            eta = f"{int(eta_s//3600)}h{int((eta_s%3600)//60):02d}m"
        return (f"\r  [{bar}] {done:,}/{total:,} ({pct:.1%})"
                f"  存活:{G}{len(alive_hosts)}{X}"
                f"  {speed:.0f}/s  ETA:{eta}   ")

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
                rtt_str = f"{rtt:.1f} ms" if rtt >= 0 else "N/A"
                alive_hosts.append({"ip": ip, "rtt": rtt_str, "method": method})
                if verbose:
                    print(f"\n  {G}[+] {ip:<18} 存活  RTT:{rtt_str:<10} {method}{X}")

        if alive and out_path:
            append_alive(out_path, ip, rtt, method, file_lock)
        if state_path:
            append_done(state_path, ip, state_lock)

    # 流式批量投入线程池
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        i = 0
        while i < len(targets) and not stop_event.is_set():
            batch = targets[i: i + batch_size]
            futs = [executor.submit(worker, ip) for ip in batch]
            for f in as_completed(futs):
                pass
            i += batch_size

    signal.signal(signal.SIGINT, original_sigint)

    if stop_event.is_set():
        print(f"\n\n{Y}[中断] 已安全停止。已扫 {counter[0]:,}/{total:,} 个 IP。{X}")
        if state_path:
            print(f"{Y}        下次加 --resume 从断点继续。{X}\n")
    else:
        print()

    # 排序
    alive_hosts.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])

    # 结果表格
    elapsed_total = time.monotonic() - start_time
    print(f"\n{C}{'═'*62}{X}")
    print(f"{C}  扫描结果{X}")
    print(f"{C}{'═'*62}{X}")
    if alive_hosts:
        print(f"  {'IP 地址':<20} {'响应时间':<12} {'探测方式'}")
        print(f"  {D}{'-'*18}  {'-'*10}  {'-'*8}{X}")
        for h in alive_hosts:
            print(f"  {G}{h['ip']:<20}{X} {h['rtt']:<12} {h['method']}")
    else:
        print(f"  {Y}未发现存活主机{X}")

    scanned = counter[0]
    avg_speed = scanned / elapsed_total if elapsed_total > 0 else 0
    print(f"\n  {C}摘要 → 本次扫描: {scanned:,} 个IP  存活: {len(alive_hosts)} 台  "
          f"耗时: {elapsed_total:.0f}s  平均速率: {avg_speed:.0f}/s{X}")
    print(f"{C}{'═'*62}{X}\n")

    if out_path:
        with out_path.open("a", encoding="utf-8") as f:
            f.write(f"\n# 摘要: 扫描 {scanned} 个IP，存活 {len(alive_hosts)} 台，"
                    f"耗时 {elapsed_total:.0f}s\n")
        print(f"  {G}存活 IP 已追加保存至: {out_path}{X}")
        if state_path and state_path.exists() and not stop_event.is_set():
            try:
                state_path.unlink()
                print(f"  {D}[续扫] 进度文件已清除: {state_path}{X}")
            except OSError:
                pass

    return alive_hosts


# ──────────────────────────────────────────────────────
# 命令行参数
# ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_scanner",
        description="Windows 网络存活主机扫描工具 v2.0（ICMP/TCP 探活，适用于 B/C 段大规模扫描）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
参数速查
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -n   --networks     目标网段（必填）支持: CIDR / 范围 / 单IP，可多个
  -e   --exclude      排除网段（可选）格式同上，可多个
  -t   --timeout      单次探测超时 ms（默认 800，范围 50-10000）
  -c   --concurrency  并发线程数（默认 64，范围 1-512）
       --rate         每秒最大探测数（默认 0=无限，推荐 B 段用 150-300）
       --tcp-fallback ICMP 失败后自动 TCP 探测（80/443/135/445/22/8080）
  -v   --verbose      实时打印每个存活 IP
  -o   --output       结果写入文件（实时追加，中断不丢数据）
       --resume       从上次中断处继续（需与 -o 配合使用）
       --force        跳过大网段（>1024 IP）二次确认提示

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
使用示例
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # B 段标准扫描（推荐）
  python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt

  # 中途 Ctrl+C 后断点续扫
  python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt --resume

  # B 段 + 排除子网 + TCP 备用探测
  python network_scanner.py -n 192.168.0.0/16 -e 192.168.0.0/24 192.168.255.0/24 ^
      -c 200 --rate 300 --tcp-fallback -o result.txt

  # C 段快速扫描
  python network_scanner.py -n 192.168.1.0/24 -v

  # 多网段 + 排除单 IP
  python network_scanner.py -n 10.0.0.0/16 172.16.0.0/16 -e 10.0.0.1 -t 600 -c 100 -o out.txt

  # 脚本自动化调用（跳过确认）
  python network_scanner.py -n 10.10.0.0/16 --force -c 150 --rate 200 -o alive.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
B 段推荐参数（平稳不中断约 6-12 分钟完成）:
  -c 150 --rate 200 -t 800
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""",
    )

    p.add_argument("-n", "--networks",
        nargs="+", required=True, metavar="NETWORK",
        help="目标网段，支持 CIDR(10.0.0.0/16) / IP范围(10.0.0.1-10.0.10.50) / 单IP，可多个")

    p.add_argument("-e", "--exclude",
        nargs="+", default=[], metavar="EXCLUDE",
        help="排除不扫描的网段/IP，格式同 -n，可多个")

    p.add_argument("-t", "--timeout",
        type=int, default=800, metavar="MS",
        help="ICMP/TCP 探测超时（毫秒），默认 800，范围 50-10000")

    p.add_argument("-c", "--concurrency",
        type=int, default=64, metavar="N",
        help="并发线程数，默认 64；B 段推荐 100-200")

    p.add_argument("--rate",
        type=int, default=0, metavar="N",
        help="每秒最多发起 N 次探测（令牌桶限速），0=不限制；B 段推荐 150-300")

    p.add_argument("--tcp-fallback",
        action="store_true",
        help="ICMP 无响应时依次尝试 TCP 80/443/135/445/22/8080 探测")

    p.add_argument("-v", "--verbose",
        action="store_true",
        help="实时打印每个发现的存活主机（默认只显示进度条）")

    p.add_argument("-o", "--output",
        metavar="FILE", default=None,
        help="存活 IP 实时写入指定文件（追加模式，中途中断不丢数据）")

    p.add_argument("--resume",
        action="store_true",
        help="断点续扫：跳过上次已扫描的 IP（需与 -o 配合使用）")

    p.add_argument("--force",
        action="store_true",
        help="跳过大网段（>1024 IP）的二次确认提示")

    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not (50 <= args.timeout <= 10000):
        parser.error("--timeout 应在 50-10000 毫秒之间")
    if not (1 <= args.concurrency <= 512):
        parser.error("--concurrency 应在 1-512 之间")
    if args.rate < 0:
        parser.error("--rate 不能为负数，0 表示不限速")
    if args.resume and not args.output:
        parser.error("--resume 必须配合 -o/--output 使用")

    try:
        all_ips = collect_ips(args.networks, args.exclude)
    except ValueError as e:
        print(f"{R}[错误] {e}{X}")
        sys.exit(1)

    excluded_count = 0
    if args.exclude:
        try:
            raw_count = sum(len(parse_target(n)) for n in args.networks)
            excluded_count = raw_count - len(all_ips)
        except ValueError:
            pass

    if not all_ips:
        print(f"{R}[错误] 解析后无有效 IP 地址{X}")
        sys.exit(1)

    if len(all_ips) > 1024 and not args.force:
        print(f"{Y}[警告] 目标包含 {len(all_ips):,} 个 IP（约 {len(all_ips)/256:.1f} 个 C 段）。")
        print(f"        请确认已获得授权再继续。加 --force 可跳过此提示。{X}")
        try:
            ans = input("  输入 yes 继续，其他任意键退出: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = ""
        if ans != "yes":
            print("已取消。")
            sys.exit(0)

    t0 = time.perf_counter()
    run_scan(
        targets        = all_ips,
        timeout_ms     = args.timeout,
        concurrency    = args.concurrency,
        tcp_fallback   = args.tcp_fallback,
        verbose        = args.verbose,
        output_file    = args.output,
        resume         = args.resume,
        rate           = args.rate,
        excluded_count = excluded_count,
    )
    print(f"  总耗时: {time.perf_counter() - t0:.1f} 秒\n")


if __name__ == "__main__":
    main()