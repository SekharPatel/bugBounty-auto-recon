#!/usr/bin/env python3
"""
recon_pipeline.py

Program-aware recon pipeline for authorized security testing / bug bounty work.

What it does:
- Reads one TXT file per program from a targets/ directory
- Treats SQLite as the source of truth
- Keeps each program fully separated by program_id
- Runs one scan cycle per invocation:
    subfinder -> compare with previous results -> httpx alive check -> screenshot -> naabu -sV -> nuclei -> Telegram
- Saves all artifacts under per-program folders

Run it from a Linux service or timer to control scheduling externally.

Configuration is loaded from a .env file beside this script:
  TARGETS_DIR=targets
  DB_PATH=recon.db
  WORKDIR=work
  LOG_FILE=logs/recon_pipeline.log
  TELEGRAM_BOT_TOKEN=your_bot_token
  TELEGRAM_CHAT_ID=your_chat_id

Expected targets layout:
  targets/
    company_1.txt
    company_2.txt

Each file contains root domains / scope entries, one per line:
  example.com
  api.example.net

External tools expected in PATH:
  - subfinder
  - httpx
  - naabu
  - nuclei
Optional:
  - gowitness (if you want screenshots as a fallback)

Python stdlib only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


# -----------------------------
# Config
# -----------------------------

@dataclass
class Config:
    targets_dir: Path
    db_path: Path
    workdir: Path
    log_file: Path
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    subfinder_bin: str = "subfinder"
    httpx_bin: str = "httpx"
    naabu_bin: str = "naabu"
    nuclei_bin: str = "nuclei"
    gowitness_bin: str = "gowitness"
    nuclei_severities: str = "medium,high,critical"
    subfinder_timeout: int = 3600
    httpx_timeout: int = 1800
    naabu_timeout: int = 3600
    nuclei_timeout: int = 3600


SCRIPT_DIR = Path(__file__).resolve().parent


# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file),
        ],
    )


# -----------------------------
# SQLite schema
# -----------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    scope_file TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    scope_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_scanned_at TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scope_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    root_domain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(program_id, root_domain),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alive INTEGER NOT NULL DEFAULT 0,
    http_url TEXT,
    http_status INTEGER,
    http_title TEXT,
    http_tech TEXT,
    screenshot_path TEXT,
    last_httpx_at TEXT,
    last_naabu_at TEXT,
    last_nuclei_at TEXT,
    notes TEXT,
    UNIQUE(program_id, host),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS httpx_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    url TEXT,
    status_code INTEGER,
    title TEXT,
    tech TEXT,
    server TEXT,
    ip TEXT,
    cname TEXT,
    raw_json TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    version TEXT,
    raw_json TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    url TEXT,
    scanned_at TEXT NOT NULL,
    severity TEXT,
    template_id TEXT,
    name TEXT,
    matched_at TEXT,
    raw_json TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    meta TEXT,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    discovered INTEGER NOT NULL DEFAULT 0,
    new_subdomains INTEGER NOT NULL DEFAULT 0,
    live_subdomains INTEGER NOT NULL DEFAULT 0,
    nuclei_findings INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scope_program ON scope_domains(program_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program_id);
CREATE INDEX IF NOT EXISTS idx_httpx_program ON httpx_results(program_id);
CREATE INDEX IF NOT EXISTS idx_ports_program ON ports(program_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_program ON nuclei_findings(program_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_program ON artifacts(program_id);
"""


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# -----------------------------
# Helpers
# -----------------------------

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def safe_name(value: str) -> str:
    out = []
    for ch in value:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_")[:180] or "item"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s.rstrip("."))
    return lines


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = list(lines)
    path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")


def parse_domain_input(value: str) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for item in value.replace(",", " ").split():
        domain = item.strip().rstrip(".")
        if not domain or domain.startswith("#"):
            continue
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def default_program_name(domains: list[str]) -> str:
    if not domains:
        return "default"
    parts = domains[0].split(".")
    if len(parts) >= 2:
        return safe_name(parts[-2])
    return safe_name(domains[0])


def ensure_initial_targets(targets_dir: Path) -> None:
    if any(p.is_file() for p in targets_dir.glob("*.txt")):
        return

    if not sys.stdin.isatty():
        raise RuntimeError(
            f"No target files found in {targets_dir}. "
            "Run the script interactively once to create the first target, "
            "or create a targets/<program>.txt file manually."
        )

    print("No target files found. First-run target setup.")
    domains: list[str] = []
    while not domains:
        raw_domains = input("Enter root domain(s), separated by comma or space: ").strip()
        domains = parse_domain_input(raw_domains)
        if not domains:
            print("Please enter at least one domain.")

    suggested_name = default_program_name(domains)
    raw_name = input(f"Program name [{suggested_name}]: ").strip()
    program_name = safe_name(raw_name or suggested_name)
    target_file = targets_dir / f"{program_name}.txt"

    counter = 2
    while target_file.exists():
        target_file = targets_dir / f"{program_name}_{counter}.txt"
        counter += 1

    write_lines(target_file, domains)
    print(f"Created initial target file: {target_file}")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str], timeout: int, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    logging.info("Running: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def jsonl_lines(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def first_value(d: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def ensure_utf8_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def read_env_file(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE entries without modifying the process environment."""
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise ValueError(f"Invalid secret entry at {path}:{line_number}")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value

    return values





def normalize_url(host: str, url: Optional[str]) -> str:
    if url and isinstance(url, str) and url.startswith(("http://", "https://")):
        return url
    return f"https://{host}"


def host_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


# -----------------------------
# Telegram
# -----------------------------

def send_telegram(bot_token: str, chat_id: str, message: str) -> None:
    if not bot_token or not chat_id:
        return
    endpoint = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        _ = resp.read()


# -----------------------------
# Program sync
# -----------------------------

def sync_targets_dir(conn: sqlite3.Connection, targets_dir: Path) -> list[sqlite3.Row]:
    """
    Each *.txt file becomes one program.
    Filename stem is the program name.
    File contents are scope roots.
    """
    now = utc_now()
    cur = conn.cursor()
    programs: list[sqlite3.Row] = []

    txt_files = sorted([p for p in targets_dir.glob("*.txt") if p.is_file()])
    existing_names = {row["name"] for row in cur.execute("SELECT name FROM programs")}

    for scope_file in txt_files:
        program_name = scope_file.stem
        roots = read_lines(scope_file)
        scope_hash = hashlib.sha256("\n".join(sorted(set(roots))).encode("utf-8")).hexdigest()

        row = cur.execute("SELECT * FROM programs WHERE name=?", (program_name,)).fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO programs (name, scope_file, enabled, scope_hash, created_at, updated_at, notes)
                VALUES (?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    program_name,
                    str(scope_file),
                    scope_hash,
                    now,
                    now,
                    "auto-imported from targets directory",
                ),
            )
            program_id = cur.lastrowid
        else:
            program_id = row["id"]
            cur.execute(
                """
                UPDATE programs
                SET scope_file=?, enabled=1, scope_hash=?, updated_at=?
                WHERE id=?
                """,
                (str(scope_file), scope_hash, now, program_id),
            )
            cur.execute("DELETE FROM scope_domains WHERE program_id=?", (program_id,))

        for root in sorted(set(roots)):
            cur.execute(
                """
                INSERT OR IGNORE INTO scope_domains (program_id, root_domain, created_at)
                VALUES (?, ?, ?)
                """,
                (program_id, root, now),
            )

    # Keep existing programs if files disappear, but do not auto-delete them.
    conn.commit()

    for row in cur.execute("SELECT * FROM programs WHERE enabled=1 ORDER BY name"):
        programs.append(row)
    return programs


def scope_roots_for_program(conn: sqlite3.Connection, program_id: int) -> list[str]:
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT root_domain FROM scope_domains WHERE program_id=? ORDER BY root_domain ASC",
        (program_id,),
    ).fetchall()
    return [r["root_domain"] for r in rows]


# -----------------------------
# Discovery
# -----------------------------

def run_subfinder(cfg: Config, roots: list[str], job_dir: Path) -> set[str]:
    if not roots:
        return set()

    roots_file = job_dir / "roots.txt"
    roots_file.write_text("\n".join(roots) + "\n", encoding="utf-8")

    cmd = [
        cfg.subfinder_bin,
        "-dL", str(roots_file),
        "-silent",
    ]
    proc = run_cmd(cmd, timeout=cfg.subfinder_timeout)
    if proc.returncode != 0 and not proc.stdout.strip():
        logging.error("subfinder failed: %s", proc.stderr.strip())
        return set()

    subs: set[str] = set()
    for line in proc.stdout.splitlines():
        s = line.strip().rstrip(".")
        if not s:
            continue
        if s.startswith("{"):
            try:
                obj = json.loads(s)
                host = obj.get("host") or obj.get("name") or obj.get("subdomain")
                if host:
                    subs.add(str(host).strip().rstrip("."))
            except Exception:
                continue
        else:
            subs.add(s)
    return subs


def update_subdomains(conn: sqlite3.Connection, program_id: int, discovered: set[str]) -> tuple[list[str], list[str]]:
    now = utc_now()
    cur = conn.cursor()

    existing = {
        row["host"]
        for row in cur.execute("SELECT host FROM subdomains WHERE program_id=?", (program_id,))
    }
    new_hosts = sorted(discovered - existing)
    seen_hosts = sorted(discovered & existing)

    for host in seen_hosts:
        cur.execute(
            "UPDATE subdomains SET last_seen=? WHERE program_id=? AND host=?",
            (now, program_id, host),
        )

    for host in new_hosts:
        cur.execute(
            """
            INSERT INTO subdomains (
                program_id, host, first_seen, last_seen, alive, notes
            ) VALUES (?, ?, ?, ?, 0, ?)
            """,
            (program_id, host, now, now, "newly discovered"),
        )

    conn.commit()
    return new_hosts, seen_hosts


# -----------------------------
# httpx
# -----------------------------

def save_screenshot_fallback(job_dir: Path, host: str, url: str, cfg: Config) -> Optional[str]:
    """
    Best-effort screenshot fallback.
    Uses gowitness only if installed. Not mandatory.
    """
    if not shutil.which(cfg.gowitness_bin):
        return None

    screenshot_dir = ensure_dir(job_dir / "screenshots")
    output_dir = screenshot_dir / safe_name(host)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        cfg.gowitness_bin,
        "single",
        "--url", url,
        "--screenshot-path", str(output_dir),
    ]
    proc = run_cmd(cmd, timeout=cfg.httpx_timeout)
    if proc.returncode != 0:
        logging.warning("gowitness failed for %s: %s", host, proc.stderr.strip())
        return None

    # Return the newest png if present.
    pngs = sorted(output_dir.rglob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    if pngs:
        return str(pngs[0])
    return None


def run_httpx(cfg: Config, hosts: list[str], job_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not hosts:
        return [], []

    host_file = job_dir / "httpx_hosts.txt"
    host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = job_dir / "httpx.jsonl"
    cmd = [
        cfg.httpx_bin,
        "-l", str(host_file),
        "-json",
        "-sc",
        "-title",
        "-td",
        "-server",
        "-ip",
        "-cname",
        "-no-color",
        "-silent",
        "-o", str(out_file),
    ]
    proc = run_cmd(cmd, timeout=cfg.httpx_timeout)

    raw_lines: list[str] = []
    if out_file.exists():
        raw_lines.extend(out_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    if proc.stdout.strip():
        raw_lines.extend(proc.stdout.splitlines())

    results: list[dict[str, Any]] = []
    live_hosts: list[str] = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        host = str(first_value(obj, ["host", "input", "hostname", "domain"], "")).strip().rstrip(".")
        url = str(first_value(obj, ["url", "final_url", "matched_url"], "")).strip()
        status_code = first_value(obj, ["status_code", "status"], None)
        title = first_value(obj, ["title"], "")
        tech = first_value(obj, ["tech", "technologies", "technology"], [])
        server = first_value(obj, ["server", "webserver"], "")
        ip = first_value(obj, ["ip"], "")
        cname = first_value(obj, ["cname"], "")

        if not host and url:
            host = host_from_url(url)

        if not url and host:
            url = normalize_url(host, url)

        alive = False
        try:
            alive = int(status_code) > 0
        except Exception:
            alive = bool(url)

        screenshot_path = None
        # Best effort: if httpx exposes any screenshot-like field, save it.
        for key, value in obj.items():
            if "screenshot" in key.lower():
                if isinstance(value, str) and value.strip() and host:
                    # If value is a file path, copy it; if base64, attempt to decode.
                    candidate = Path(value)
                    if candidate.exists():
                        ss_dir = ensure_dir(job_dir / "screenshots")
                        dest = ss_dir / f"{safe_name(host)}.png"
                        shutil.copy2(candidate, dest)
                        screenshot_path = str(dest)
                        break

        if alive and host:
            live_hosts.append(host)

        results.append(
            {
                "subdomain": host,
                "url": url,
                "status_code": int(status_code) if isinstance(status_code, (int, float, str)) and str(status_code).isdigit() else None,
                "title": ensure_utf8_text(title),
                "tech": json.dumps(as_list(tech), ensure_ascii=False),
                "server": ensure_utf8_text(server),
                "ip": ensure_utf8_text(ip),
                "cname": ensure_utf8_text(cname),
                "screenshot_path": screenshot_path,
                "raw_json": json.dumps(obj, ensure_ascii=False),
                "alive": 1 if alive else 0,
            }
        )

    # Optional fallback screenshots for live hosts if none stored by httpx.
    if not any(r.get("screenshot_path") for r in results):
        for r in results:
            if r["alive"] and r["subdomain"] and r["url"]:
                fallback = save_screenshot_fallback(job_dir, r["subdomain"], r["url"], cfg)
                if fallback:
                    r["screenshot_path"] = fallback
                    break

    deduped_live = []
    seen = set()
    for h in live_hosts:
        if h not in seen:
            seen.add(h)
            deduped_live.append(h)

    return results, deduped_live


def store_httpx(conn: sqlite3.Connection, program_id: int, results: list[dict[str, Any]], job_dir: Path) -> None:
    now = utc_now()
    cur = conn.cursor()

    for r in results:
        sub = r["subdomain"]
        if not sub:
            continue

        cur.execute(
            """
            INSERT INTO httpx_results (
                program_id, subdomain, scanned_at, url, status_code, title, tech, server, ip, cname, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                r["url"],
                r["status_code"],
                r["title"],
                r["tech"],
                r["server"],
                r["ip"],
                r["cname"],
                r["raw_json"],
            ),
        )

        cur.execute(
            """
            UPDATE subdomains
            SET alive=?, http_url=?, http_status=?, http_title=?, http_tech=?, screenshot_path=?, last_httpx_at=?
            WHERE program_id=? AND host=?
            """,
            (
                r["alive"],
                r["url"],
                r["status_code"],
                r["title"],
                r["tech"],
                r["screenshot_path"],
                now,
                program_id,
                sub,
            ),
        )

        if r["screenshot_path"]:
            cur.execute(
                """
                INSERT INTO artifacts (program_id, subdomain, kind, path, created_at, meta)
                VALUES (?, ?, 'screenshot', ?, ?, ?)
                """,
                (program_id, sub, r["screenshot_path"], now, None),
            )

    conn.commit()


# -----------------------------
# naabu
# -----------------------------

def run_naabu(cfg: Config, hosts: list[str], job_dir: Path) -> list[dict[str, Any]]:
    if not hosts:
        return []

    host_file = job_dir / "naabu_hosts.txt"
    host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = job_dir / "naabu.jsonl"
    cmd = [
        cfg.naabu_bin,
        "-list", str(host_file),
        "-sV",
        "-json",
        "-silent",
        "-o", str(out_file),
    ]
    proc = run_cmd(cmd, timeout=cfg.naabu_timeout)

    raw_lines: list[str] = []
    if out_file.exists():
        raw_lines.extend(out_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    if proc.stdout.strip():
        raw_lines.extend(proc.stdout.splitlines())

    results: list[dict[str, Any]] = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        host = str(first_value(obj, ["host", "hostname", "input"], "")).strip().rstrip(".")
        ip = str(first_value(obj, ["ip", "ip_address"], "")).strip()
        port = first_value(obj, ["port"], None)
        protocol = str(first_value(obj, ["protocol", "proto"], "")).strip()
        service = str(first_value(obj, ["service", "name"], "")).strip()
        version = str(first_value(obj, ["version", "service_version", "banner", "cpe"], "")).strip()

        results.append(
            {
                "subdomain": host,
                "host": host,
                "ip": ip,
                "port": int(port) if isinstance(port, (int, float, str)) and str(port).isdigit() else None,
                "protocol": protocol,
                "service": service,
                "version": version,
                "raw_json": json.dumps(obj, ensure_ascii=False),
            }
        )

    return results


def store_ports(conn: sqlite3.Connection, program_id: int, port_results: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    for r in port_results:
        sub = r["subdomain"]
        if not sub:
            continue

        cur.execute(
            """
            INSERT INTO ports (
                program_id, subdomain, scanned_at, host, ip, port, protocol, service, version, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                r["host"],
                r["ip"],
                r["port"],
                r["protocol"],
                r["service"],
                r["version"],
                r["raw_json"],
            ),
        )

        cur.execute(
            "UPDATE subdomains SET last_naabu_at=? WHERE program_id=? AND host=?",
            (now, program_id, sub),
        )

    conn.commit()


# -----------------------------
# nuclei
# -----------------------------

def run_nuclei(cfg: Config, urls: list[str], job_dir: Path) -> list[dict[str, Any]]:
    if not urls:
        return []

    url_file = job_dir / "nuclei_urls.txt"
    url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    out_file = job_dir / "nuclei.jsonl"
    cmd = [
        cfg.nuclei_bin,
        "-l", str(url_file),
        "-severity", cfg.nuclei_severities,
        "-json",
        "-silent",
        "-no-color",
        "-o", str(out_file),
    ]
    proc = run_cmd(cmd, timeout=cfg.nuclei_timeout)

    raw_lines: list[str] = []
    if out_file.exists():
        raw_lines.extend(out_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    if proc.stdout.strip():
        raw_lines.extend(proc.stdout.splitlines())

    findings: list[dict[str, Any]] = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        url = str(first_value(obj, ["matched-at", "matched_at", "url", "host"], "")).strip()
        severity = str(first_value(obj, ["severity", "info.severity"], "")).strip()
        template_id = str(first_value(obj, ["template-id", "template_id", "id"], "")).strip()
        name = str(first_value(obj, ["name", "info.name", "template-name"], "")).strip()
        matched_at = str(first_value(obj, ["matched-at", "matched_at"], "")).strip()

        subdomain = host_from_url(url) if url else ""
        findings.append(
            {
                "subdomain": subdomain,
                "url": url,
                "severity": severity,
                "template_id": template_id,
                "name": name,
                "matched_at": matched_at,
                "raw_json": json.dumps(obj, ensure_ascii=False),
            }
        )

    return findings


def store_nuclei(conn: sqlite3.Connection, program_id: int, findings: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    for f in findings:
        if not f["subdomain"]:
            continue

        cur.execute(
            """
            INSERT INTO nuclei_findings (
                program_id, subdomain, url, scanned_at, severity, template_id, name, matched_at, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                f["subdomain"],
                f["url"],
                now,
                f["severity"],
                f["template_id"],
                f["name"],
                f["matched_at"],
                f["raw_json"],
            ),
        )

        cur.execute(
            "UPDATE subdomains SET last_nuclei_at=? WHERE program_id=? AND host=?",
            (now, program_id, f["subdomain"]),
        )

    conn.commit()


# -----------------------------
# Reporting
# -----------------------------

def build_host_report(conn: sqlite3.Connection, program_name: str, host: str, program_id: int) -> str:
    cur = conn.cursor()
    sub = cur.execute(
        "SELECT * FROM subdomains WHERE program_id=? AND host=?",
        (program_id, host),
    ).fetchone()
    if not sub:
        return ""

    latest_httpx = cur.execute(
        """
        SELECT * FROM httpx_results
        WHERE program_id=? AND subdomain=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (program_id, host),
    ).fetchone()

    ports = cur.execute(
        """
        SELECT port, protocol, service, version
        FROM ports
        WHERE program_id=? AND subdomain=?
        ORDER BY port ASC, id DESC
        """,
        (program_id, host),
    ).fetchall()

    nuclei_rows = cur.execute(
        """
        SELECT severity, template_id, name, url
        FROM nuclei_findings
        WHERE program_id=? AND subdomain=?
        ORDER BY id DESC
        LIMIT 20
        """,
        (program_id, host),
    ).fetchall()

    port_lines = []
    seen_ports = set()
    for p in ports:
        key = (p["port"], p["protocol"], p["service"], p["version"])
        if key in seen_ports:
            continue
        seen_ports.add(key)
        port_lines.append(f"{p['port'] or ''}/{p['protocol'] or ''} {p['service'] or ''} {p['version'] or ''}".strip())

    nuclei_by_sev: dict[str, int] = {}
    for n in nuclei_rows:
        sev = (n["severity"] or "unknown").lower()
        nuclei_by_sev[sev] = nuclei_by_sev.get(sev, 0) + 1

    title = sub["http_title"] or (latest_httpx["title"] if latest_httpx else "") or "N/A"
    url = sub["http_url"] or (latest_httpx["url"] if latest_httpx else "") or f"https://{host}"
    status = sub["http_status"] if sub["http_status"] is not None else (latest_httpx["status_code"] if latest_httpx else "N/A")
    tech = sub["http_tech"] or (latest_httpx["tech"] if latest_httpx else "[]")
    screenshot = sub["screenshot_path"] or "N/A"

    lines = [
        f"🆕 <b>{program_name}</b>",
        f"Host: <code>{host}</code>",
        f"URL: {url}",
        f"Alive: {'yes' if int(sub['alive']) == 1 else 'no'}",
        f"Status: {status}",
        f"Title: {title}",
        f"Tech: {tech}",
        f"Screenshot: {screenshot}",
        "",
        "<b>Open ports</b>",
    ]
    lines.extend([f"• <code>{line}</code>" for line in (port_lines or ["none"])])
    lines.append("")
    lines.append("<b>Nuclei summary</b>")
    if nuclei_by_sev:
        for sev, count in sorted(nuclei_by_sev.items()):
            lines.append(f"• {sev}: {count}")
    else:
        lines.append("• none")

    return "\n".join(lines)


TELEGRAM_MESSAGE_LIMIT = 3900
SUMMARY_HOST_LIMIT = 20
SUMMARY_LIST_LIMIT = 20


def clean_text(value: Any, max_chars: int = 160) -> str:
    text = ensure_utf8_text(value).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if not text:
        return "N/A"
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def html_text(value: Any, max_chars: int = 160) -> str:
    return html.escape(clean_text(value, max_chars), quote=False)


def html_code(value: Any, max_chars: int = 160) -> str:
    return f"<code>{html_text(value, max_chars)}</code>"


def split_telegram_message(message: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for line in message.splitlines():
        line_len = len(line) + 1
        if line_len > limit:
            if current:
                chunks.append("\n".join(current))
                current = []
                current_len = 0
            for start in range(0, len(line), limit):
                chunks.append(line[start : start + limit])
            continue

        if current and current_len + line_len > limit:
            chunks.append("\n".join(current))
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len

    if current:
        chunks.append("\n".join(current))
    return chunks or [message]


def format_code_list(items: list[str], limit: int = SUMMARY_LIST_LIMIT) -> str:
    shown = [html_code(item, 100) for item in items[:limit]]
    if len(items) > limit:
        shown.append(f"+{len(items) - limit} more")
    return ", ".join(shown) if shown else "none"


def format_tech(tech: Any) -> str:
    if isinstance(tech, str):
        try:
            values = as_list(json.loads(tech))
        except Exception:
            values = [tech]
    else:
        values = as_list(tech)

    cleaned = [clean_text(item, 40) for item in values if clean_text(item, 40) != "N/A"]
    if not cleaned:
        return "none"
    return html_text(", ".join(cleaned[:6]), 180)


def format_port_entry(port: dict[str, Any]) -> str:
    port_value = port.get("port") or "?"
    protocol = clean_text(port.get("protocol"), 20)
    service = clean_text(port.get("service"), 40)
    version = clean_text(port.get("version"), 80)

    endpoint = str(port_value)
    if protocol != "N/A":
        endpoint = f"{endpoint}/{protocol}"

    details = " ".join(part for part in (service, version) if part != "N/A")
    return clean_text(f"{endpoint} {details}".strip(), 120)


def format_ports(ports: list[dict[str, Any]], limit: int = 6) -> str:
    entries: list[str] = []
    seen: set[str] = set()
    for port in ports:
        entry = format_port_entry(port)
        if entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)

    shown = [html_code(entry, 120) for entry in entries[:limit]]
    if len(entries) > limit:
        shown.append(f"+{len(entries) - limit} more")
    return ", ".join(shown) if shown else "none"


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = clean_text(finding.get("severity") or "unknown", 30).lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def format_severity_counts(findings: list[dict[str, Any]]) -> str:
    counts = severity_counts(findings)
    if not counts:
        return "none"

    ordered = ["critical", "high", "medium", "low", "info", "unknown"]
    parts = [f"{sev}: {counts.pop(sev)}" for sev in ordered if sev in counts]
    parts.extend(f"{sev}: {count}" for sev, count in sorted(counts.items()))
    return ", ".join(parts)


def group_by_subdomain(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        host = str(item.get("subdomain") or "").strip()
        if not host:
            continue
        grouped.setdefault(host, []).append(item)
    return grouped


def build_program_summary_report(
    program_name: str,
    roots: list[str],
    job_dir: Path,
    discovered_count: int,
    new_hosts: list[str],
    seen_hosts: list[str],
    httpx_results: list[dict[str, Any]],
    live_hosts: list[str],
    port_results: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
) -> str:
    httpx_by_host = {str(r.get("subdomain") or ""): r for r in httpx_results}
    ports_by_host = group_by_subdomain(port_results)
    nuclei_by_host = group_by_subdomain(nuclei_findings)
    live_set = set(live_hosts)
    non_live_new_hosts = [host for host in new_hosts if host not in live_set]

    lines = [
        "<b>Recon Summary</b>",
        f"Program: {html_code(program_name)}",
        f"Time: {html_text(utc_now(), 40)}",
        f"Scope roots: {len(roots)} ({format_code_list(roots, 8)})",
        f"Artifacts: {html_code(str(job_dir), 240)}",
        "",
        "<b>Tool summary</b>",
        f"- Subfinder: {discovered_count} discovered, {len(new_hosts)} new, {len(seen_hosts)} already known",
        f"- HTTPX: {len(httpx_results)} checked, {len(live_hosts)} live",
        f"- Naabu: {len(port_results)} port/service result(s)",
        f"- Nuclei: {len(nuclei_findings)} finding(s) ({format_severity_counts(nuclei_findings)})",
        "",
        "<b>New subdomains</b>",
        format_code_list(new_hosts),
    ]

    if live_hosts:
        lines.extend(["", "<b>Live host details</b>"])
        for host in live_hosts[:SUMMARY_HOST_LIMIT]:
            httpx_result = httpx_by_host.get(host, {})
            title = httpx_result.get("title") or "N/A"
            status = httpx_result.get("status_code") or "N/A"
            url = httpx_result.get("url") or f"https://{host}"
            tech = format_tech(httpx_result.get("tech"))
            host_ports = ports_by_host.get(host, [])
            host_findings = nuclei_by_host.get(host, [])

            lines.extend(
                [
                    f"- {html_code(host)}",
                    f"  URL: {html_text(url, 220)}",
                    f"  HTTP: {html_text(status, 20)} - {html_text(title, 140)}",
                    f"  Tech: {tech}",
                    f"  Ports: {format_ports(host_ports)}",
                    f"  Nuclei: {format_severity_counts(host_findings)}",
                ]
            )

        if len(live_hosts) > SUMMARY_HOST_LIMIT:
            lines.append(f"- +{len(live_hosts) - SUMMARY_HOST_LIMIT} more live host(s)")
    else:
        lines.extend(["", "<b>Live host details</b>", "No live hosts found among new subdomains."])

    if non_live_new_hosts:
        lines.extend(
            [
                "",
                f"<b>New non-live subdomains</b> ({len(non_live_new_hosts)})",
                format_code_list(non_live_new_hosts),
            ]
        )

    return "\n".join(lines)


def send_telegram_report(bot_token: str, chat_id: str, report: str) -> None:
    chunks = split_telegram_message(report)
    total = len(chunks)
    for index, chunk in enumerate(chunks, start=1):
        if total > 1:
            chunk = f"<b>Recon Summary part {index}/{total}</b>\n{chunk}"
        send_telegram(bot_token, chat_id, chunk)


def notify_program_summary(
    bot_token: str,
    chat_id: str,
    program_name: str,
    roots: list[str],
    job_dir: Path,
    discovered_count: int,
    new_hosts: list[str],
    seen_hosts: list[str],
    httpx_results: list[dict[str, Any]],
    live_hosts: list[str],
    port_results: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
) -> None:
    if not bot_token or not chat_id:
        return

    report = build_program_summary_report(
        program_name=program_name,
        roots=roots,
        job_dir=job_dir,
        discovered_count=discovered_count,
        new_hosts=new_hosts,
        seen_hosts=seen_hosts,
        httpx_results=httpx_results,
        live_hosts=live_hosts,
        port_results=port_results,
        nuclei_findings=nuclei_findings,
    )
    try:
        send_telegram_report(bot_token, chat_id, report)
    except Exception as exc:
        logging.exception("Telegram summary send failed for %s: %s", program_name, exc)


# -----------------------------
# Program scan
# -----------------------------

def program_workdir(base: Path, program_name: str) -> Path:
    return ensure_dir(base / safe_name(program_name))


def run_program_cycle(cfg: Config, conn: sqlite3.Connection, program: sqlite3.Row) -> None:
    cur = conn.cursor()
    program_id = int(program["id"])
    program_name = str(program["name"])
    job_dir = ensure_dir(program_workdir(cfg.workdir, program_name) / dt.datetime.now().strftime("%Y%m%d_%H%M%S"))

    roots = scope_roots_for_program(conn, program_id)
    if not roots:
        logging.info("[%s] no scope roots found, skipping", program_name)
        return

    cur.execute(
        "INSERT INTO runs (program_id, started_at) VALUES (?, ?)",
        (program_id, utc_now()),
    )
    run_id = cur.lastrowid
    conn.commit()

    try:
        discovered = run_subfinder(cfg, roots, job_dir)
        logging.info("[%s] discovered %d hosts", program_name, len(discovered))

        new_hosts, seen_hosts = update_subdomains(conn, program_id, discovered)
        logging.info("[%s] new=%d seen=%d", program_name, len(new_hosts), len(seen_hosts))

        cur.execute(
            "UPDATE runs SET discovered=?, new_subdomains=? WHERE id=?",
            (len(discovered), len(new_hosts), run_id),
        )
        conn.commit()

        if not new_hosts:
            cur.execute(
                "UPDATE runs SET finished_at=?, status='ok' WHERE id=?",
                (utc_now(), run_id),
            )
            conn.commit()
            notify_program_summary(
                cfg.telegram_bot_token,
                cfg.telegram_chat_id,
                program_name,
                roots,
                job_dir,
                len(discovered),
                new_hosts,
                seen_hosts,
                [],
                [],
                [],
                [],
            )
            return

        (job_dir / "new_subdomains.txt").write_text("\n".join(new_hosts) + "\n", encoding="utf-8")

        httpx_results, live_hosts = run_httpx(cfg, new_hosts, job_dir)
        store_httpx(conn, program_id, httpx_results, job_dir)
        logging.info("[%s] httpx results=%d live=%d", program_name, len(httpx_results), len(live_hosts))

        live_urls = [r["url"] for r in httpx_results if r.get("alive") and r.get("url")]
        port_results: list[dict[str, Any]] = []
        if live_hosts:
            port_results = run_naabu(cfg, live_hosts, job_dir)
            store_ports(conn, program_id, port_results)
            logging.info("[%s] naabu results=%d", program_name, len(port_results))
        else:
            logging.info("[%s] no live hosts, skipping naabu", program_name)

        if live_urls:
            nuclei_findings = run_nuclei(cfg, live_urls, job_dir)
            store_nuclei(conn, program_id, nuclei_findings)
            logging.info("[%s] nuclei findings=%d", program_name, len(nuclei_findings))
        else:
            nuclei_findings = []
            logging.info("[%s] no live urls, skipping nuclei", program_name)

        cur.execute(
            """
            UPDATE runs
            SET finished_at=?, status='ok', live_subdomains=?, nuclei_findings=?
            WHERE id=?
            """,
            (utc_now(), len(live_hosts), len(nuclei_findings), run_id),
        )
        cur.execute(
            "UPDATE programs SET last_scanned_at=?, updated_at=? WHERE id=?",
            (utc_now(), utc_now(), program_id),
        )
        conn.commit()

        notify_program_summary(
            cfg.telegram_bot_token,
            cfg.telegram_chat_id,
            program_name,
            roots,
            job_dir,
            len(discovered),
            new_hosts,
            seen_hosts,
            httpx_results,
            live_hosts,
            port_results,
            nuclei_findings,
        )

    except Exception:
        cur.execute(
            "UPDATE runs SET finished_at=?, status='error' WHERE id=?",
            (utc_now(), run_id),
        )
        conn.commit()
        raise


# -----------------------------
def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="Program-aware recon scanner.")
    parser.add_argument("--targets-dir", default="targets", help="Directory with one TXT file per program.")
    parser.add_argument("--db", default="recon.db", help="SQLite database path.")
    parser.add_argument("--workdir", default="work", help="Artifact directory.")
    parser.add_argument("--log-file", default="logs/recon_watch.log", help="Log file path.")
    parser.add_argument(
        "--secret-file",
        default=os.environ.get("RECON_SECRET_FILE", str(Path(__file__).resolve().parent / ".secret")),
        help="Path to the KEY=VALUE secrets file (default: .secret beside the script).",
    )
    parser.add_argument("--subfinder-bin", default=os.environ.get("SUBFINDER_BIN", "subfinder"))
    parser.add_argument("--httpx-bin", default=os.environ.get("HTTPX_BIN", "httpx"))
    parser.add_argument("--naabu-bin", default=os.environ.get("NAABU_BIN", "naabu"))
    parser.add_argument("--nuclei-bin", default=os.environ.get("NUCLEI_BIN", "nuclei"))
    parser.add_argument("--gowitness-bin", default=os.environ.get("GOWITNESS_BIN", "gowitness"))
    parser.add_argument("--nuclei-severities", default=os.environ.get("NUCLEI_SEVERITIES", "medium,high,critical"))
    args = parser.parse_args()

    secret_file = Path(args.secret_file).expanduser()
    secrets = read_env_file(secret_file)
    telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", secrets.get("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", secrets.get("TELEGRAM_CHAT_ID", ""))

    return Config(
        targets_dir=Path(args.targets_dir).expanduser(),
        db_path=Path(args.db).expanduser(),
        workdir=Path(args.workdir).expanduser(),
        log_file=Path(args.log_file).expanduser(),
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        subfinder_bin=args.subfinder_bin,
        httpx_bin=args.httpx_bin,
        naabu_bin=args.naabu_bin,
        nuclei_bin=args.nuclei_bin,
        gowitness_bin=args.gowitness_bin,
        nuclei_severities=args.nuclei_severities,
    )


def run_cycle(cfg: Config) -> None:
    cfg.targets_dir.mkdir(parents=True, exist_ok=True)
    conn = connect_db(cfg.db_path)

    try:
        programs = sync_targets_dir(conn, cfg.targets_dir)
        logging.info("Loaded %d enabled program(s)", len(programs))

        for program in programs:
            run_program_cycle(cfg, conn, program)

    finally:
        conn.close()


def main() -> int:
    cfg = parse_args()
    setup_logging(cfg.log_file)

    if not cfg.targets_dir.exists():
        logging.error("Targets directory does not exist: %s", cfg.targets_dir)
        return 1

    connect_db(cfg.db_path).close()

    logging.info("Targets dir: %s", cfg.targets_dir)
    logging.info("Database: %s", cfg.db_path)
    logging.info("Workdir: %s", cfg.workdir)

    try:
        run_cycle(cfg)
    except subprocess.TimeoutExpired as exc:
        logging.exception("Timeout: %s", exc)
        return 1
    except Exception as exc:
        logging.exception("Scan failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
