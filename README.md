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

# 标准 B 段扫描（推荐参数，平稳约 6-12 分钟）
python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt

# 中途 Ctrl+C 中断后，下次续扫（自动跳过已扫部分）
python network_scanner.py -n 10.10.0.0/16 -c 150 --rate 200 -o alive.txt --resume

# B 段 + 排除网关段 + 开启 TCP 备用探测
python network_scanner.py -n 192.168.0.0/16 ^
    -e 192.168.0.0/24 192.168.255.0/24 ^
    -c 200 --rate 300 --tcp-fallback -o result.txt

# 跳过确认（自动化脚本调用）
python network_scanner.py -n 10.10.0.0/16 --force -c 150 --rate 200 -o alive.txt