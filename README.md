# 网络存活主机扫描器
Windows 平台专用、高性能、防漏扫内网主机探测工具

## 功能
- ICMP Ping 探测 + TCP 端口兜底，解决禁 ping 漏扫
- 自动重试机制，大幅降低丢包导致的漏 IP
- 大网段支持（B段 /16 轻松扫描）
- 断点续扫，意外退出不重来
- 速率限制 + 并发控制，稳定不卡顿
- 结果实时写入文件，不丢失数据

## 快速开始（最稳不漏扫）
```bash
# C段
python network_scanner.py -n 192.168.1.0/24 -c 100 --rate 120 -t 1000 --tcp-fallback -o alive.txt

# B段
python network_scanner.py -n 10.0.0.0/16 -c 100 --rate 120 -t 1000 --tcp-fallback -o alive.txt

# 续扫
python network_scanner.py -n 10.0.0.0/16 --resume -o alive.txt


## 完整参数说明

| 参数                   | 默认值      | 说明                                                      |
| ---------------------- | ----------- | --------------------------------------------------------- |
| `-n` / `--networks`    | **必填**    | 目标网段，支持 CIDR / IP范围 / 单IP，可多个               |
| `-e` / `--exclude`     | 无          | 排除不扫描的网段/IP，格式同 `-n`，可多个                  |
| `-t` / `--timeout`     | `800` ms    | 单次探测超时，范围 50–10000                               |
| `-c` / `--concurrency` | `64`        | 并发线程数，范围 1–512                                    |
| `--rate`               | `0`（无限） | 每秒最多发起 N 次探测（令牌桶限速），**B 段推荐 150–300** |
| `--tcp-fallback`       | 关闭        | ICMP 失败后依次尝试 TCP 80/443/135/445/22/8080            |
| `-v` / `--verbose`     | 关闭        | 实时打印每个发现的存活 IP                                 |
| `-o` / `--output`      | 无          | 存活 IP **实时追加**写入文件，中断不丢数据                |
| `--resume`             | 关闭        | **断点续扫**，跳过上次已扫 IP（须配合 `-o`）              |
| `--force`              | 关闭        | 跳过大网段二次确认提示，适合脚本自动化                    |





<img width="1728" height="867" alt="image" src="https://github.com/user-attachments/assets/3e1dfb8b-1f19-4a74-9b2a-d712a7f2168d" />
