from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pandas as pd

from src.utils import ensure_parent_dirs, init_project_dirs, write_csv_utf8sig


RANDOM_SEED = 20260615
TZ = timezone(timedelta(hours=8))


def _random_ip(rng: random.Random) -> str:
    return f"{rng.randint(23, 223)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _format_access_log_line(
    src_ip: str,
    event_time: datetime,
    method: str,
    uri: str,
    status_code: int,
    size: int,
    referer: str,
    user_agent: str,
    dst_ip: str,
) -> str:
    time_text = event_time.strftime("%d/%b/%Y:%H:%M:%S %z")
    return (
        f'{src_ip} - - [{time_text}] "{method} {uri} HTTP/1.1" {status_code} {size} '
        f'"{referer}" "{user_agent}" "{dst_ip}"'
    )


def _generate_assets(raw_dir: Path) -> dict[str, Any]:
    assets = pd.DataFrame(
        [
            {
                "asset_id": "AST-001",
                "asset_name": "Web-Server-01",
                "ip": "192.168.10.10",
                "system_type": "Nginx Web",
                "business_level": "core",
                "owner": "Web Team",
                "exposure": "public",
            },
            {
                "asset_id": "AST-002",
                "asset_name": "Login-Server-01",
                "ip": "192.168.10.20",
                "system_type": "Auth Service",
                "business_level": "core",
                "owner": "IAM Team",
                "exposure": "public",
            },
            {
                "asset_id": "AST-003",
                "asset_name": "DB-Server-01",
                "ip": "192.168.10.30",
                "system_type": "MySQL",
                "business_level": "high",
                "owner": "DBA Team",
                "exposure": "internal",
            },
            {
                "asset_id": "AST-004",
                "asset_name": "OA-System-01",
                "ip": "192.168.10.40",
                "system_type": "OA System",
                "business_level": "high",
                "owner": "Office IT",
                "exposure": "public",
            },
        ]
    )
    assets_path = raw_dir / "assets.csv"
    write_csv_utf8sig(assets, assets_path)
    return {"path": assets_path, "count": len(assets)}


def _generate_access_logs(raw_dir: Path, rng: random.Random) -> dict[str, Any]:
    start_time = datetime(2026, 6, 15, 8, 0, 0, tzinfo=TZ)
    normal_paths = [
        "/",
        "/index.html",
        "/products",
        "/products?id=1001",
        "/search?q=office",
        "/blog/2026/security-weekly",
        "/login",
        "/user/profile",
        "/assets/main.css",
        "/api/v1/orders?page=1",
        "/dashboard",
        "/contact",
        "/docs/api",
        "/status",
        "/download/manual.pdf",
    ]
    normal_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    suspicious_agents = [
        "sqlmap/1.7.9#stable",
        "Nikto/2.5.0",
        "dirbuster/1.0",
        "python-requests/2.31.0",
        "curl/8.6.0",
    ]
    web_targets = ["192.168.10.10", "192.168.10.40", "192.168.10.20"]
    lines: list[str] = []

    for index in range(980):
        event_time = start_time + timedelta(seconds=index * 25 + rng.randint(0, 8))
        src_ip = _random_ip(rng)
        uri = rng.choice(normal_paths)
        method = rng.choice(["GET", "GET", "GET", "POST"])
        status_code = rng.choices([200, 200, 200, 302, 304, 404], weights=[40, 35, 25, 8, 5, 2])[0]
        dst_ip = rng.choices(web_targets, weights=[60, 25, 15])[0]
        referer = "-" if rng.random() < 0.35 else "https://portal.example.local/"
        user_agent = rng.choice(normal_agents)
        size = rng.randint(256, 8192)
        lines.append(
            _format_access_log_line(
                src_ip=src_ip,
                event_time=event_time,
                method=method,
                uri=uri,
                status_code=status_code,
                size=size,
                referer=referer,
                user_agent=user_agent,
                dst_ip=dst_ip,
            )
        )

    sql_ip = "185.199.110.14"
    sql_payloads = [
        "/search?q=" + quote("' union select username,password from users--"),
        "/product?id=1%20or%201=1",
        "/api/report?id=10%20union%20select%20null,version()",
        "/search?q=" + quote("sleep(5)"),
        "/item?id=2%20and%20exists(select%201%20from%20information_schema.tables)",
    ]
    for offset in range(36):
        event_time = start_time + timedelta(hours=4, seconds=offset * 18)
        uri = sql_payloads[offset % len(sql_payloads)]
        status_code = [200, 403, 500][offset % 3]
        user_agent = suspicious_agents[offset % len(suspicious_agents)]
        lines.append(
            _format_access_log_line(
                src_ip=sql_ip,
                event_time=event_time,
                method="GET",
                uri=uri,
                status_code=status_code,
                size=rng.randint(300, 2400),
                referer="-",
                user_agent=user_agent,
                dst_ip="192.168.10.10",
            )
        )

    xss_ip = "103.44.76.155"
    xss_payloads = [
        "/comment?msg=" + quote("<script>alert(1)</script>"),
        "/search?q=" + quote('"><img src=x onerror=alert(1)>'),
        "/redirect?next=javascript:alert(1)",
        "/feedback?content=" + quote("<svg onload=alert(1)>"),
    ]
    for offset in range(28):
        event_time = start_time + timedelta(hours=5, minutes=15, seconds=offset * 21)
        uri = xss_payloads[offset % len(xss_payloads)]
        lines.append(
            _format_access_log_line(
                src_ip=xss_ip,
                event_time=event_time,
                method="GET",
                uri=uri,
                status_code=[200, 404, 403][offset % 3],
                size=rng.randint(200, 2200),
                referer="-",
                user_agent=normal_agents[offset % len(normal_agents)],
                dst_ip="192.168.10.40",
            )
        )

    sensitive_ip = "77.88.121.4"
    sensitive_paths = ["/.env", "/.git/config", "/backup.zip", "/config.php", "/wp-config.php"]
    for offset in range(30):
        event_time = start_time + timedelta(hours=2, minutes=40, seconds=offset * 15)
        lines.append(
            _format_access_log_line(
                src_ip=sensitive_ip,
                event_time=event_time,
                method="GET",
                uri=sensitive_paths[offset % len(sensitive_paths)],
                status_code=[404, 404, 403, 200, 500][offset % 5],
                size=rng.randint(128, 1200),
                referer="-",
                user_agent=suspicious_agents[offset % len(suspicious_agents)],
                dst_ip="192.168.10.10",
            )
        )

    upload_ip = "91.198.174.88"
    upload_paths = ["/upload/shell.php", "/upload/test.jsp", "/file/upload.php", "/api/upload/file.aspx"]
    for offset in range(24):
        event_time = start_time + timedelta(hours=6, minutes=20, seconds=offset * 17)
        lines.append(
            _format_access_log_line(
                src_ip=upload_ip,
                event_time=event_time,
                method="POST" if offset % 2 == 0 else "GET",
                uri=upload_paths[offset % len(upload_paths)],
                status_code=[403, 404, 500, 200][offset % 4],
                size=rng.randint(256, 3200),
                referer="-",
                user_agent=suspicious_agents[offset % len(suspicious_agents)],
                dst_ip="192.168.10.40",
            )
        )

    dirscan_ip = "45.77.200.10"
    dirscan_paths = ["/admin", "/test", "/backup", "/upload", "/old", "/api/debug"]
    for offset in range(48):
        event_time = start_time + timedelta(hours=7, minutes=5, seconds=offset * 6)
        lines.append(
            _format_access_log_line(
                src_ip=dirscan_ip,
                event_time=event_time,
                method="GET",
                uri=dirscan_paths[offset % len(dirscan_paths)],
                status_code=404 if offset % 7 else 403,
                size=rng.randint(128, 1024),
                referer="-",
                user_agent="dirbuster/1.0",
                dst_ip="192.168.10.10",
            )
        )

    misc_scanner_ip = "66.249.66.1"
    scanner_paths = ["/", "/robots.txt", "/.git/config", "/admin", "/search?q=test"]
    for offset in range(24):
        event_time = start_time + timedelta(hours=8, minutes=30, seconds=offset * 12)
        lines.append(
            _format_access_log_line(
                src_ip=misc_scanner_ip,
                event_time=event_time,
                method="GET",
                uri=scanner_paths[offset % len(scanner_paths)],
                status_code=[200, 404, 403][offset % 3],
                size=rng.randint(200, 1800),
                referer="-",
                user_agent=suspicious_agents[offset % len(suspicious_agents)],
                dst_ip="192.168.10.10",
            )
        )

    lines.sort(key=lambda item: datetime.strptime(item.split("[", 1)[1].split("]", 1)[0], "%d/%b/%Y:%H:%M:%S %z"))
    output_path = raw_dir / "access.log"
    ensure_parent_dirs(output_path)
    with output_path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))
    return {"path": output_path, "count": len(lines)}


def _generate_auth_logs(raw_dir: Path, rng: random.Random) -> dict[str, Any]:
    start_time = datetime(2026, 6, 15, 8, 0, 0)
    normal_users = ["alice", "bob", "charlie", "david", "emma", "frank", "grace", "helen"]
    target_users = ["admin", "root", "test"]
    lines: list[str] = []

    for index in range(280):
        event_time = start_time + timedelta(seconds=index * 55 + rng.randint(0, 12))
        src_ip = _random_ip(rng)
        dst_ip = "192.168.10.20" if rng.random() < 0.85 else "192.168.10.40"
        username = rng.choice(normal_users)
        auth_result = rng.choices(["success", "failed"], weights=[82, 18])[0]
        lines.append(
            f"{event_time:%Y-%m-%d %H:%M:%S} src_ip={src_ip} dst_ip={dst_ip} "
            f"username={username} auth_result={auth_result}"
        )

    brute_force_ip = "198.51.100.77"
    burst_start = start_time + timedelta(hours=3, minutes=10)
    for offset in range(36):
        event_time = burst_start + timedelta(seconds=offset * 8)
        username = target_users[offset % len(target_users)]
        lines.append(
            f"{event_time:%Y-%m-%d %H:%M:%S} src_ip={brute_force_ip} dst_ip=192.168.10.20 "
            f"username={username} auth_result=failed"
        )

    for offset in range(12):
        event_time = burst_start + timedelta(minutes=8, seconds=offset * 20)
        lines.append(
            f"{event_time:%Y-%m-%d %H:%M:%S} src_ip={brute_force_ip} dst_ip=192.168.10.20 "
            f"username=admin auth_result=success"
        )

    lines.sort()
    output_path = raw_dir / "auth.log"
    ensure_parent_dirs(output_path)
    with output_path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))
    return {"path": output_path, "count": len(lines)}


def _generate_suricata_logs(raw_dir: Path, rng: random.Random) -> dict[str, Any]:
    start_time = datetime(2026, 6, 15, 8, 0, 0, tzinfo=TZ)
    signatures = [
        ("ET WEB_SERVER Possible SQL Injection Attempt", 1),
        ("ET WEB_SERVER Possible XSS Attempt", 2),
        ("ET SCAN Nmap Scripting Engine User-Agent Detected", 2),
        ("ET POLICY Suspicious inbound to mySQL port 3306", 1),
        ("ET POLICY Curl User-Agent Outbound", 3),
    ]
    http_hosts = ["portal.example.local", "oa.example.local", "login.example.local"]
    records: list[str] = []

    for index in range(70):
        event_time = start_time + timedelta(seconds=index * 40 + rng.randint(0, 15))
        signature, severity = signatures[index % len(signatures)]
        dst_ip = ["192.168.10.10", "192.168.10.20", "192.168.10.30", "192.168.10.40"][index % 4]
        record = {
            "timestamp": event_time.isoformat(),
            "src_ip": _random_ip(rng),
            "dest_ip": dst_ip,
            "proto": "TCP",
            "event_type": "alert",
            "alert": {
                "signature": signature,
                "severity": severity,
                "category": "Attempted Information Leak",
            },
        }
        records.append(json.dumps(record, ensure_ascii=False))

    for index in range(20):
        event_time = start_time + timedelta(hours=2, seconds=index * 50)
        record = {
            "timestamp": event_time.isoformat(),
            "src_ip": _random_ip(rng),
            "dest_ip": "192.168.10.10",
            "proto": "TCP",
            "event_type": "http",
            "http": {
                "hostname": http_hosts[index % len(http_hosts)],
                "url": "/search?q=test",
                "http_user_agent": "Mozilla/5.0",
            },
        }
        records.append(json.dumps(record, ensure_ascii=False))

    for index in range(10):
        event_time = start_time + timedelta(hours=3, seconds=index * 90)
        record = {
            "timestamp": event_time.isoformat(),
            "src_ip": _random_ip(rng),
            "dest_ip": "192.168.10.30",
            "proto": "UDP",
            "event_type": "dns",
            "dns": {
                "rrname": f"api{index}.example.local",
                "type": "query",
            },
        }
        records.append(json.dumps(record, ensure_ascii=False))

    for index in range(10):
        event_time = start_time + timedelta(hours=4, seconds=index * 75)
        record = {
            "timestamp": event_time.isoformat(),
            "src_ip": _random_ip(rng),
            "dest_ip": "192.168.10.20",
            "proto": "TCP",
            "event_type": "flow",
            "flow": {
                "pkts_toserver": rng.randint(2, 20),
                "pkts_toclient": rng.randint(2, 20),
            },
        }
        records.append(json.dumps(record, ensure_ascii=False))

    output_path = raw_dir / "suricata_eve.json"
    ensure_parent_dirs(output_path)
    with output_path.open("w", encoding="utf-8") as file:
        file.write("\n".join(records))
    return {"path": output_path, "count": len(records)}


def generate_all_sample_data(base_dir: Path) -> dict[str, Any]:
    init_project_dirs()
    raw_dir = base_dir / "data" / "raw"
    rng = random.Random(RANDOM_SEED)
    assets_info = _generate_assets(raw_dir)
    access_info = _generate_access_logs(raw_dir, rng)
    auth_info = _generate_auth_logs(raw_dir, rng)
    suricata_info = _generate_suricata_logs(raw_dir, rng)
    return {
        "assets": assets_info,
        "access": access_info,
        "auth": auth_info,
        "suricata": suricata_info,
    }
