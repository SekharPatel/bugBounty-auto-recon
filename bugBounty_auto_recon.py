#!/usr/bin/env python3
"""
bugBounty_auto_recon.py

Program-aware recon pipeline for authorized security testing / bug bounty work.

What it does:
- Reads one TXT file per program from a targets/ directory
- Treats SQLite as the source of truth
- Keeps each program fully separated by program_id
- Runs one scan cycle per invocation:
    subfinder -> compare with previous results -> httpx alive check -> [naabu + katana] (parallel) -> nuclei -> Telegram
- Saves all artifacts under per-program folders

Run it from a Linux service or timer to control scheduling externally.

Configuration:
  All settings are loaded from a .env file beside the script.
  Copy .env.example to .env and edit it before running.
  On first run (no targets found), the script will prompt you for a domain.

  .env keys:
    TARGETS_DIR          - Directory with one TXT file per program (default: targets)
    DB_PATH              - SQLite database path (default: recon.db)
    WORKDIR              - Artifact / work directory (default: work)
    LOG_FILE             - Log file path (default: logs/recon_watch.log)
    TELEGRAM_BOT_TOKEN   - Telegram bot token for notifications
    TELEGRAM_CHAT_ID     - Telegram chat ID for notifications
    SUBFINDER_BIN        - Path to subfinder binary (default: subfinder)
    HTTPX_BIN            - Path to httpx binary (default: httpx)
    NAABU_BIN            - Path to naabu binary (default: naabu)
    NUCLEI_BIN           - Path to nuclei binary (default: nuclei)
    KATANA_BIN           - Path to katana binary (default: katana)
    NUCLEI_SEVERITIES    - Nuclei severity filter (default: medium,high,critical)
    SUBFINDER_TIMEOUT    - Subfinder timeout in seconds (default: 3600)
    HTTPX_TIMEOUT        - HTTPX timeout in seconds (default: 1800)
    NAABU_TIMEOUT        - Naabu timeout in seconds (default: 3600)
    NUCLEI_TIMEOUT       - Nuclei timeout in seconds (default: 3600)
    KATANA_TIMEOUT       - Katana crawling timeout in seconds (default: 3600)
    KATANA_DEPTH         - Katana crawl depth (default: 3)
    KATANA_HEADLESS      - Enable katana headless browser mode (default: false)
    MAX_JOB_RETENTION_DAYS - Auto-delete scan artifacts older than N days (default: 30, 0=disable)
    DRY_RUN              - Skip external tool execution for testing (default: false)


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
  - katana

Python stdlib only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import logging
import logging.handlers
import shutil
import sqlite3
import subprocess
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


# -----------------------------
# Config
# -----------------------------

@dataclass
class Config:
    root_dir: Path
    
    @property
    def targets_dir(self) -> Path:
        return self.root_dir / "targets"
        
    @property
    def db_path(self) -> Path:
        return self.root_dir / "recon.db"
        
    @property
    def workdir(self) -> Path:
        return self.root_dir / "work"
        
    @property
    def log_file(self) -> Path:
        return self.root_dir / "logs" / "recon_watch.log"
        
    notify_bin: str = "notify"
    notify_id: str = ""
    notify_step_by_step: bool = False
    subfinder_bin: str = "subfinder"
    httpx_bin: str = "httpx"
    naabu_bin: str = "naabu"
    nuclei_bin: str = "nuclei"
    katana_bin: str = "katana"
    nuclei_severities: str = "medium,high,critical"
    subfinder_timeout: int = 3600
    httpx_timeout: int = 1800
    naabu_timeout: int = 3600
    nuclei_timeout: int = 3600
    katana_timeout: int = 3600
    katana_depth: int = 3
    katana_headless: bool = False
    max_job_retention_days: int = 30
    dry_run: bool = False


# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: Path) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5,
            ),
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

CREATE TABLE IF NOT EXISTS katana_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT,
    status_code INTEGER,
    source TEXT,
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

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_program ON scope_domains(program_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program_id);
CREATE INDEX IF NOT EXISTS idx_httpx_program ON httpx_results(program_id);
CREATE INDEX IF NOT EXISTS idx_ports_program ON ports(program_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_program ON nuclei_findings(program_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_program ON artifacts(program_id);
CREATE INDEX IF NOT EXISTS idx_katana_program ON katana_results(program_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nuclei_unique ON nuclei_findings(program_id, subdomain, template_id, url);
"""


CURRENT_SCHEMA_VERSION = 3


def run_migrations(conn: sqlite3.Connection) -> None:
    """Run incremental schema migrations based on schema_version table."""
    cur = conn.cursor()
    row = cur.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    current = row["version"] if row else 0

    if current < 1:
        cur.execute(
            "INSERT INTO schema_version (version, updated_at) VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, utc_now()),
        )
    else:
        if current < 3:
            # v3: add katana_urls column to runs table
            try:
                cur.execute("ALTER TABLE runs ADD COLUMN katana_urls INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass  # column already exists
        if current < CURRENT_SCHEMA_VERSION:
            cur.execute(
                "UPDATE schema_version SET version=?, updated_at=?",
                (CURRENT_SCHEMA_VERSION, utc_now()),
            )

    conn.commit()


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    run_migrations(conn)
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

def send_notify(cfg: Config, message: str) -> None:
    """Send a notification using ProjectDiscovery's notify tool via stdin."""
    if not message.strip():
        return

    cmd = [cfg.notify_bin, "-silent", "-bulk"]
    if cfg.notify_id:
        cmd.extend(["-id", cfg.notify_id])

    try:
        subprocess.run(
            cmd,
            input=message,
            text=True,
            timeout=60,
            check=False,
            capture_output=True
        )
    except Exception as exc:
        logging.error("Notify tool error: %s", exc)


# -----------------------------
# Program sync
# -----------------------------

def sync_targets_dir(conn: sqlite3.Connection, targets_dir: Path) -> list[sqlite3.Row]:
    """
    Each *.txt file becomes one program.
    Filename stem is the program name.
    File contents are scope roots.
    Only updates scope_domains when the scope file content has changed.
    """
    now = utc_now()
    cur = conn.cursor()
    programs: list[sqlite3.Row] = []

    target_files = sorted([p for p in targets_dir.iterdir() if p.is_file() and not p.name.startswith(".")])

    for scope_file in target_files:
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

            for root in sorted(set(roots)):
                cur.execute(
                    """
                    INSERT OR IGNORE INTO scope_domains (program_id, root_domain, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (program_id, root, now),
                )
        else:
            program_id = row["id"]
            old_hash = row["scope_hash"]

            if old_hash != scope_hash:
                logging.info("[%s] scope changed, updating domains", program_name)
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
            else:
                cur.execute(
                    "UPDATE programs SET scope_file=?, enabled=1, updated_at=? WHERE id=?",
                    (str(scope_file), now, program_id),
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
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping subfinder for %d roots", len(roots))
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

def run_httpx(cfg: Config, hosts: list[str], job_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not hosts:
        return [], []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping httpx for %d hosts", len(hosts))
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
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping naabu for %d hosts", len(hosts))
        return []

    host_file = job_dir / "naabu_hosts.txt"
    host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = job_dir / "naabu.jsonl"
    cmd = [
        cfg.naabu_bin,
        "-list", str(host_file),
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
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping nuclei for %d urls", len(urls))
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

        info = obj.get("info", {})
        url = str(first_value(obj, ["matched-at", "matched_at", "url", "host"], "")).strip()
        severity = str(first_value(obj, ["severity"], "") or info.get("severity", "")).strip()
        template_id = str(first_value(obj, ["template-id", "template_id"], "") or obj.get("id", "")).strip()
        name = str(first_value(obj, ["name"], "") or info.get("name", "")).strip()
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
            INSERT OR IGNORE INTO nuclei_findings (
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
# katana
# -----------------------------

def run_katana(cfg: Config, urls: list[str], job_dir: Path) -> list[str]:
    """Crawl live URLs with katana and return discovered endpoint URLs."""
    if not urls:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping katana for %d urls", len(urls))
        return []

    url_file = job_dir / "katana_input_urls.txt"
    url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    out_file = job_dir / "katana.jsonl"
    cmd = [
        cfg.katana_bin,
        "-list", str(url_file),
        "-depth", str(cfg.katana_depth),
        "-jsonl",
        "-silent",
        "-no-color",
        "-o", str(out_file),
    ]
    if cfg.katana_headless:
        cmd.extend(["-headless"])

    proc = run_cmd(cmd, timeout=cfg.katana_timeout)

    raw_lines: list[str] = []
    if out_file.exists():
        raw_lines.extend(out_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    if proc.stdout.strip():
        raw_lines.extend(proc.stdout.splitlines())

    discovered_urls: list[str] = []
    seen: set[str] = set()
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # Plain URL line (non-JSON mode fallback)
            if line.startswith("http"):
                if line not in seen:
                    seen.add(line)
                    discovered_urls.append(line)
            continue

        endpoint = str(
            first_value(obj, ["request", "endpoint", "url", "input"], "")
        ).strip()
        if endpoint.startswith("http") and endpoint not in seen:
            seen.add(endpoint)
            discovered_urls.append(endpoint)

    return discovered_urls


def parse_katana_results(job_dir: Path) -> list[dict[str, Any]]:
    """Parse katana JSONL output into structured dicts for DB storage."""
    out_file = job_dir / "katana.jsonl"
    if not out_file.exists():
        return []

    results: list[dict[str, Any]] = []
    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        endpoint = str(
            first_value(obj, ["request", "endpoint", "url", "input"], "")
        ).strip()
        if not endpoint:
            continue

        subdomain = host_from_url(endpoint) if endpoint else ""
        method = str(first_value(obj, ["method"], "")).strip().upper() or "GET"
        status_code = first_value(obj, ["status_code", "status-code"], None)
        source = str(first_value(obj, ["source"], "")).strip()

        results.append(
            {
                "subdomain": subdomain,
                "url": endpoint,
                "method": method,
                "status_code": int(status_code) if isinstance(status_code, (int, float, str)) and str(status_code).isdigit() else None,
                "source": source,
                "raw_json": json.dumps(obj, ensure_ascii=False),
            }
        )

    return results


def store_katana(conn: sqlite3.Connection, program_id: int, katana_results: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    for r in katana_results:
        sub = r.get("subdomain", "")
        if not sub:
            continue

        cur.execute(
            """
            INSERT INTO katana_results (
                program_id, subdomain, scanned_at, url, method, status_code, source, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                r["url"],
                r["method"],
                r["status_code"],
                r["source"],
                r["raw_json"],
            ),
        )

    conn.commit()


# -----------------------------
# Reporting
# -----------------------------

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


def md_text(value: Any, max_chars: int = 160) -> str:
    return clean_text(value, max_chars)


def md_code(value: Any, max_chars: int = 160) -> str:
    return f"`{md_text(value, max_chars)}`"


def format_code_list(items: list[str], limit: int = SUMMARY_LIST_LIMIT) -> str:
    shown = [md_code(item, 100) for item in items[:limit]]
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
    return md_text(", ".join(cleaned[:6]), 180)


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

    shown = [md_code(entry, 120) for entry in entries[:limit]]
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
    katana_urls_count: int = 0,
) -> str:
    httpx_by_host = {str(r.get("subdomain") or ""): r for r in httpx_results}
    ports_by_host = group_by_subdomain(port_results)
    nuclei_by_host = group_by_subdomain(nuclei_findings)
    live_set = set(live_hosts)
    non_live_new_hosts = [host for host in new_hosts if host not in live_set]

    lines = [
        "**Recon Summary**",
        f"Program: {md_code(program_name)}",
        f"Time: {md_text(utc_now(), 40)}",
        f"Scope roots: {len(roots)} ({format_code_list(roots, 8)})",
        f"Artifacts: {md_code(str(job_dir), 240)}",
        "",
        "**Tool summary**",
        f"- Subfinder: {discovered_count} discovered, {len(new_hosts)} new, {len(seen_hosts)} already known",
        f"- HTTPX: {len(httpx_results)} checked, {len(live_hosts)} live",
        f"- Naabu: {len(port_results)} port/service result(s)",
        f"- Katana: {katana_urls_count} crawled URL(s)",
        f"- Nuclei: {len(nuclei_findings)} finding(s) ({format_severity_counts(nuclei_findings)})",
        "",
        "**New subdomains**",
        format_code_list(new_hosts),
    ]

    if live_hosts:
        lines.extend(["", "**Live host details**"])
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
                    f"- {md_code(host)}",
                    f"  URL: {md_text(url, 220)}",
                    f"  HTTP: {md_text(status, 20)} - {md_text(title, 140)}",
                    f"  Tech: {tech}",
                    f"  Ports: {format_ports(host_ports)}",
                    f"  Nuclei: {format_severity_counts(host_findings)}",
                ]
            )

        if len(live_hosts) > SUMMARY_HOST_LIMIT:
            lines.append(f"- +{len(live_hosts) - SUMMARY_HOST_LIMIT} more live host(s)")
    else:
        lines.extend(["", "**Live host details**", "No live hosts found among new subdomains."])

    if non_live_new_hosts:
        lines.extend(
            [
                "",
                f"**New non-live subdomains** ({len(non_live_new_hosts)})",
                format_code_list(non_live_new_hosts),
            ]
        )

    return "\n".join(lines)


def notify_program_summary(
    cfg: Config,
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
    katana_urls_count: int = 0,
) -> None:
    if not cfg.notify_bin:
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
        katana_urls_count=katana_urls_count,
    )
    try:
        send_notify(cfg, report)
    except Exception as exc:
        logging.error("Notify summary send failed for %s: %s", program_name, exc)


# -----------------------------
# Program scan
# -----------------------------

def program_workdir(base: Path, program_name: str) -> Path:
    return ensure_dir(base / safe_name(program_name))


def run_program_cycle(cfg: Config, conn: sqlite3.Connection, program: sqlite3.Row) -> None:
    cur = conn.cursor()
    program_id = int(program["id"])
    program_name = str(program["name"])
    job_dir = ensure_dir(program_workdir(cfg.workdir, program_name) / dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f"))

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
        logging.info("[%s] Step 1 - subfinder completed successfully", program_name)

        new_hosts, seen_hosts = update_subdomains(conn, program_id, discovered)
        logging.info("[%s] Output saved successfully in file and database.", program_name)

        if cfg.notify_step_by_step:
            send_notify(cfg, f"[{program_name}] **Subfinder finished**: {len(discovered)} total, {len(new_hosts)} new subdomains.")

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
                cfg,
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
                0,
            )
            return

        (job_dir / "new_subdomains.txt").write_text("\n".join(new_hosts) + "\n", encoding="utf-8")

        httpx_results, live_hosts = run_httpx(cfg, new_hosts, job_dir)
        logging.info("[%s] Step 2 - httpx completed successfully", program_name)
        logging.info("[%s] Saving file", program_name)
        store_httpx(conn, program_id, httpx_results, job_dir)
        logging.info("[%s] Saved in database", program_name)

        if cfg.notify_step_by_step:
            send_notify(cfg, f"[{program_name}] **HTTPX finished**: {len(live_hosts)} out of {len(new_hosts)} are live.")

        live_urls = [r["url"] for r in httpx_results if r.get("alive") and r.get("url")]

        # --- Run naabu and katana in parallel ---
        port_results: list[dict[str, Any]] = []
        katana_urls: list[str] = []

        if live_hosts or live_urls:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = {}
                if live_hosts:
                    naabu_future = pool.submit(run_naabu, cfg, live_hosts, job_dir)
                    futures[naabu_future] = "naabu"
                if live_urls:
                    katana_future = pool.submit(run_katana, cfg, live_urls, job_dir)
                    futures[katana_future] = "katana"

                for future in as_completed(futures):
                    tool_name = futures[future]
                    if tool_name == "naabu":
                        port_results = future.result()
                        logging.info("[%s] Step 3 - naabu completed successfully", program_name)
                        logging.info("[%s] Saving file", program_name)
                        store_ports(conn, program_id, port_results)
                        logging.info("[%s] Saved in database", program_name)
                        
                        if cfg.notify_step_by_step:
                            host_ports: dict[str, list[str]] = {}
                            for p in port_results:
                                host = p.get("host")
                                if host:
                                    host_ports.setdefault(host, []).append(str(p.get("port")))
                            
                            lines = [f"[{program_name}] **Naabu finished**: {len(port_results)} port findings"]
                            for host, ports in list(host_ports.items())[:10]:
                                lines.append(f"- {host}: {', '.join(ports)}")
                            if len(host_ports) > 10:
                                lines.append(f"...and {len(host_ports) - 10} more hosts")
                            send_notify(cfg, "\n".join(lines))

                    elif tool_name == "katana":
                        katana_urls = future.result()
                        logging.info("[%s] Step 4 - katana completed successfully", program_name)
                        logging.info("[%s] Saving file", program_name)
                        katana_parsed = parse_katana_results(job_dir)
                        store_katana(conn, program_id, katana_parsed)
                        logging.info("[%s] Saved in database", program_name)
                        
                        if cfg.notify_step_by_step:
                            send_notify(cfg, f"[{program_name}] **Katana finished**: {len(katana_urls)} new URLs crawled.")
        else:
            logging.info("[%s] no live hosts/urls, skipping naabu and katana", program_name)

        # --- Merge live URLs + katana URLs using shell sort -u ---
        nuclei_findings: list[dict[str, Any]] = []
        if live_urls or katana_urls:
            httpx_url_file = job_dir / "httpx_live_urls.txt"
            httpx_url_file.write_text("\n".join(live_urls) + "\n", encoding="utf-8")

            katana_url_file = job_dir / "katana_crawled_urls.txt"
            katana_url_file.write_text("\n".join(katana_urls) + "\n", encoding="utf-8")

            merged_url_file = job_dir / "nuclei_urls.txt"
            merge_cmd = f"cat {httpx_url_file} {katana_url_file} | sort -u > {merged_url_file}"
            try:
                subprocess.run(
                    merge_cmd, shell=True, check=True, timeout=60,
                    capture_output=True, text=True,
                )
                logging.info("[%s] merged URLs via shell sort -u", program_name)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                logging.warning("[%s] shell merge failed, falling back to Python dedup: %s", program_name, exc)
                all_urls = sorted(set(live_urls + katana_urls))
                merged_url_file.write_text("\n".join(all_urls) + "\n", encoding="utf-8")

            # Read back the deduplicated URLs
            all_nuclei_urls = [
                line.strip() for line in merged_url_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            logging.info("[%s] nuclei target urls=%d (httpx=%d + katana=%d, after dedup)",
                         program_name, len(all_nuclei_urls), len(live_urls), len(katana_urls))

            if all_nuclei_urls:
                nuclei_findings = run_nuclei(cfg, all_nuclei_urls, job_dir)
                logging.info("[%s] Step 5 - nuclei completed successfully", program_name)
                logging.info("[%s] Saving file", program_name)
                store_nuclei(conn, program_id, nuclei_findings)
                logging.info("[%s] Saved in database", program_name)
                
                if cfg.notify_step_by_step:
                    send_notify(cfg, f"[{program_name}] **Nuclei finished**: {len(nuclei_findings)} vulnerabilities found.")
        else:
            logging.info("[%s] no urls for nuclei, skipping", program_name)

        cur.execute(
            """
            UPDATE runs
            SET finished_at=?, status='ok', live_subdomains=?, nuclei_findings=?, katana_urls=?
            WHERE id=?
            """,
            (utc_now(), len(live_hosts), len(nuclei_findings), len(katana_urls), run_id),
        )
        cur.execute(
            "UPDATE programs SET last_scanned_at=?, updated_at=? WHERE id=?",
            (utc_now(), utc_now(), program_id),
        )
        conn.commit()

        notify_program_summary(
                cfg,
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
                len(katana_urls),
            )

    except Exception:
        cur.execute(
            "UPDATE runs SET finished_at=?, status='error' WHERE id=?",
            (utc_now(), run_id),
        )
        conn.commit()
        raise


# -----------------------------
# .env file loader
# -----------------------------

def read_env_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE entries from a .env file without modifying os.environ."""
    if not path.exists():
        return {}

    env_vars: dict[str, str] = {}
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
            logging.warning(".env:%d: malformed line (no '=' found): %s", line_number, raw_line.strip())
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        env_vars[key] = value

    return env_vars


# All required .env keys and their descriptions
REQUIRED_ENV_KEYS = {
    # Paths & storage
    "ROOT_DIR":          "Base directory for all script data (logs, targets, work, db)",
    # Notifications
    "NOTIFY_BIN":        "Path to notify binary (projectdiscovery)",
    "NOTIFY_ID":         "Optional provider ID for notify (leave blank for default)",
    "NOTIFY_STEP_BY_STEP": "Send alerts after each step (true/false)",
    # Tool binaries
    "SUBFINDER_BIN":     "Path to subfinder binary",
    "HTTPX_BIN":         "Path to httpx binary",
    "NAABU_BIN":         "Path to naabu binary",
    "NUCLEI_BIN":        "Path to nuclei binary",
    "KATANA_BIN":        "Path to katana binary",
    # Scan options
    "NUCLEI_SEVERITIES": "Nuclei severity filter (e.g. medium,high,critical)",
    "KATANA_DEPTH":      "Katana crawl depth (default: 3)",
    "KATANA_HEADLESS":   "Enable katana headless browser mode (true/false)",
    # Timeouts
    "SUBFINDER_TIMEOUT": "Subfinder timeout in seconds",
    "HTTPX_TIMEOUT":     "HTTPX timeout in seconds",
    "NAABU_TIMEOUT":     "Naabu timeout in seconds",
    "NUCLEI_TIMEOUT":    "Nuclei timeout in seconds",
    "KATANA_TIMEOUT":    "Katana crawling timeout in seconds",
    # Maintenance
    "MAX_JOB_RETENTION_DAYS": "Auto-delete scan artifacts older than N days (0=disable)",
    # Debug
    "DRY_RUN":           "Skip running external tools (true/false)",
}


# Keys that must contain valid positive integers
TIMEOUT_KEYS = {
    "SUBFINDER_TIMEOUT", "HTTPX_TIMEOUT", "NAABU_TIMEOUT",
    "NUCLEI_TIMEOUT", "KATANA_TIMEOUT", "KATANA_DEPTH",
    "MAX_JOB_RETENTION_DAYS",
}


def validate_env(env: dict[str, str], env_file: Path) -> None:
    """Check that every required key is present, non-empty, and valid. Exit with clear error if not."""
    missing: list[str] = []
    empty: list[str] = []
    invalid: list[str] = []

    for key, description in REQUIRED_ENV_KEYS.items():
        if key not in env:
            missing.append(f"  {key:25s} - {description}")
        elif not env[key].strip() or env[key].strip().startswith("your_"):
            empty.append(f"  {key:25s} - {description} (current: '{env[key]}')")
        elif key in TIMEOUT_KEYS:
            try:
                val = int(env[key])
                if val < 0:
                    raise ValueError("negative")
            except ValueError:
                invalid.append(f"  {key:25s} - must be a non-negative integer (current: '{env[key]}')")

    if missing or empty or invalid:
        logging.error("=" * 65)
        logging.error(".env CONFIGURATION ERROR")
        logging.error("=" * 65)
        if missing:
            logging.error("Missing keys (%d):", len(missing))
            for line in missing:
                logging.error(line)
        if empty:
            logging.error("Keys with placeholder/empty values (%d):", len(empty))
            for line in empty:
                logging.error(line)
        if invalid:
            logging.error("Keys with invalid values (%d):", len(invalid))
            for line in invalid:
                logging.error(line)
        logging.error("File: %s", env_file)
        logging.error("Fix the .env file and restart the service.")
        logging.error("=" * 65)
        sys.exit(1)


def load_config() -> Config:
    """Load and validate all configuration from .env file beside the script."""
    script_dir = Path(__file__).resolve().parent
    env_file = script_dir / ".env"

    if not env_file.exists():
        logging.error("=" * 65)
        logging.error("FATAL: .env file not found!")
        logging.error("Expected: %s", env_file)
        logging.error("Copy .env.example to .env and configure all values.")
        logging.error("=" * 65)
        sys.exit(1)

    env = read_env_file(env_file)
    validate_env(env, env_file)

    return Config(
        root_dir=Path(env["ROOT_DIR"]).expanduser(),
        notify_bin=env["NOTIFY_BIN"],
        notify_id=env["NOTIFY_ID"].strip(),
        notify_step_by_step=env["NOTIFY_STEP_BY_STEP"].strip().lower() in ("true", "1", "yes"),
        subfinder_bin=env["SUBFINDER_BIN"],
        httpx_bin=env["HTTPX_BIN"],
        naabu_bin=env["NAABU_BIN"],
        nuclei_bin=env["NUCLEI_BIN"],
        katana_bin=env["KATANA_BIN"],
        nuclei_severities=env["NUCLEI_SEVERITIES"],
        subfinder_timeout=int(env["SUBFINDER_TIMEOUT"]),
        httpx_timeout=int(env["HTTPX_TIMEOUT"]),
        naabu_timeout=int(env["NAABU_TIMEOUT"]),
        nuclei_timeout=int(env["NUCLEI_TIMEOUT"]),
        katana_timeout=int(env["KATANA_TIMEOUT"]),
        katana_depth=int(env["KATANA_DEPTH"]),
        katana_headless=env["KATANA_HEADLESS"].strip().lower() in ("true", "1", "yes"),
        max_job_retention_days=int(env["MAX_JOB_RETENTION_DAYS"]),
        dry_run=env["DRY_RUN"].strip().lower() in ("true", "1", "yes"),
    )



# File locking (service safety)
# -----------------------------

def acquire_lock(workdir: Path) -> Optional[Any]:
    """Acquire exclusive file lock to prevent concurrent scan instances."""
    lock_path = workdir / ".recon.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:
        pass  # Non-POSIX system (Windows), skip locking
    except BlockingIOError:
        logging.error("Another scan instance is already running. Exiting.")
        lock_file.close()
        sys.exit(0)
    return lock_file


# -----------------------------
# Artifact cleanup
# -----------------------------

def cleanup_old_jobs(workdir: Path, max_days: int) -> None:
    """Remove job directories older than max_days to free disk space."""
    if max_days <= 0:
        return
    cutoff = dt.datetime.now() - dt.timedelta(days=max_days)
    removed = 0
    for program_dir in workdir.iterdir():
        if not program_dir.is_dir() or program_dir.name.startswith("."):
            continue
        for job_dir in program_dir.iterdir():
            if not job_dir.is_dir():
                continue
            try:
                mtime = dt.datetime.fromtimestamp(job_dir.stat().st_mtime)
                if mtime < cutoff:
                    shutil.rmtree(job_dir)
                    removed += 1
            except Exception as exc:
                logging.warning("Failed to clean up %s: %s", job_dir, exc)
    if removed:
        logging.info("Cleaned up %d old job dir(s) older than %d days", removed, max_days)


# -----------------------------
# Main execution
# -----------------------------

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
    parser = argparse.ArgumentParser(description="Bug Bounty Auto Recon")
    parser.add_argument("-d", "--domain", help="Domain to add and initialize (e.g. example.com)")
    parser.add_argument("--setup", action="store_true", help="Initialize the directory structure and database")
    args = parser.parse_args()

    cfg = load_config()

    if args.setup:
        cfg.root_dir.mkdir(parents=True, exist_ok=True)
        cfg.targets_dir.mkdir(parents=True, exist_ok=True)
        cfg.workdir.mkdir(parents=True, exist_ok=True)
        cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
        connect_db(cfg.db_path).close()
        
        setup_logging(cfg.log_file)
        logging.info("Setup complete. Initialized structure in %s", cfg.root_dir)
        return 0

    # Ensure root_dir exists before proceeding to normal execution
    if not cfg.root_dir.exists() or not cfg.targets_dir.exists() or not cfg.workdir.exists() or not cfg.db_path.exists() or not cfg.log_file.parent.exists():
        print(f"Error: Essential directories or database not found in {cfg.root_dir}. Run with --setup first.")
        return 1

    setup_logging(cfg.log_file)

    # Bootstrap logic via CLI
    if args.domain:
        domain = args.domain.strip().lower()
        if " " in domain or "." not in domain:
            logging.error("Invalid domain format. Example: example.com")
            return 1
            
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.rstrip("/").rstrip(".")
        
        program_name = domain.replace(".", "_")
        
        target_file = cfg.targets_dir / f"{program_name}.txt"
        target_file.write_text(domain + "\n", encoding="utf-8")
        
        logging.info("Created target: %s", target_file)
        logging.info("Scope domain: %s", domain)
        logging.info("Program name: %s", program_name)

    # Check if we have targets to run
    target_files = [p for p in cfg.targets_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
    if not target_files:
        logging.error("No target files found in '%s'. Add a target via -d <domain>.", cfg.targets_dir)
        return 1

    # Acquire file lock to prevent concurrent instances (service safety)
    lock_file = acquire_lock(cfg.workdir)

    logging.info("Config loaded from .env")
    logging.info("Root dir: %s", cfg.root_dir)
    logging.info("Targets dir: %s", cfg.targets_dir)
    logging.info("Database: %s", cfg.db_path)
    logging.info("Workdir: %s", cfg.workdir)
    logging.info("Log file: %s", cfg.log_file)
    if cfg.dry_run:
        logging.info("DRY_RUN mode enabled — external tools will not be executed")

    try:
        # Clean up old scan artifacts before starting
        cleanup_old_jobs(cfg.workdir, cfg.max_job_retention_days)
        run_cycle(cfg)
    except subprocess.TimeoutExpired as exc:
        logging.exception("Timeout: %s", exc)
        return 1
    except Exception as exc:
        logging.exception("Scan failed: %s", exc)
        return 1
    finally:
        if lock_file:
            lock_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
