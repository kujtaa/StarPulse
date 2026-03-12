#!/usr/bin/env python3
"""Sentinel V3 — Central Server (Multi-tenant SaaS)
Multi-tenant Linux security monitoring dashboard + REST API.
Python 3.6+ stdlib only. Single file. No external dependencies.
"""

import argparse
import configparser
import getpass
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import pathlib
import re
import secrets
import signal
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

__version__ = "3.0.0"

ALERT_DEDUP = 300

DEFAULT_CFG = {
    "server": {
        "port": "8765",
        "db_path": "/var/lib/sentinel-central/sentinel.db",
        "offline_after": "120",
        "session_ttl": "86400",
    },
    "notifications": {
        "email_enabled": "false",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_password": "",
        "alert_to": "",
        "notify_offline": "true",
        "min_severity": "high",
        "slack_enabled": "false",
        "slack_webhook": "",
    },
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

LOG = logging.getLogger("sentinel-central")

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def load_config(path):
    cfg = configparser.ConfigParser()
    for section, values in DEFAULT_CFG.items():
        if not cfg.has_section(section):
            cfg.add_section(section)
        for k, v in values.items():
            cfg.set(section, k, v)
    if path and os.path.isfile(path):
        cfg.read(path)
    return cfg


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return "{}:{}".format(salt, h)


def verify_password(stored, candidate):
    if ":" not in stored:
        return False
    salt, _ = stored.split(":", 1)
    return hmac.compare_digest(stored, hash_password(candidate, salt))


def make_uuid():
    h = secrets.token_hex(16)
    return "{}-{}-{}-{}-{}".format(h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def make_slug(name):
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    token TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT 'default',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    hostname TEXT,
    ip TEXT,
    os_info TEXT,
    agent_ver TEXT,
    first_seen REAL,
    last_seen REAL,
    meta TEXT,
    tags TEXT,
    offline_alerted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alert_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    org_id TEXT NOT NULL,
    fingerprint TEXT,
    category TEXT,
    severity TEXT,
    title TEXT,
    first_seen REAL,
    last_seen REAL,
    count INTEGER DEFAULT 1,
    last_detail TEXT,
    last_data TEXT,
    hostname TEXT,
    UNIQUE(agent_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at REAL,
    user_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    email TEXT
);
"""


class Database:
    def __init__(self, db_path):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _conn(self):
        c = sqlite3.connect(self._db_path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init_schema(self):
        with self._lock:
            c = self._conn()
            c.executescript(SCHEMA)
            c.commit()
            c.close()

    # -- organizations --------------------------------------------------------

    def create_organization(self, name, slug):
        org_id = make_uuid()
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT INTO organizations (id, name, slug, created_at) VALUES (?,?,?,?)",
                    [org_id, name, slug, now],
                )
                c.commit()
            except sqlite3.IntegrityError:
                c.close()
                return None
            c.close()
        return {"id": org_id, "name": name, "slug": slug, "created_at": now}

    def get_organization(self, org_id):
        with self._lock:
            c = self._conn()
            row = c.execute("SELECT * FROM organizations WHERE id=?", [org_id]).fetchone()
            c.close()
        return dict(row) if row else None

    def slug_exists(self, slug):
        with self._lock:
            c = self._conn()
            row = c.execute("SELECT 1 FROM organizations WHERE slug=?", [slug]).fetchone()
            c.close()
        return row is not None

    # -- users ----------------------------------------------------------------

    def create_user(self, org_id, name, email, password_hash, role="owner"):
        user_id = make_uuid()
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    "INSERT INTO users (id, org_id, email, name, password_hash, role, created_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    [user_id, org_id, email, name, password_hash, role, now],
                )
                c.commit()
            except sqlite3.IntegrityError:
                c.close()
                return None
            c.close()
        return {"id": user_id, "org_id": org_id, "email": email, "name": name,
                "role": role, "created_at": now}

    def get_user_by_email(self, email):
        with self._lock:
            c = self._conn()
            row = c.execute("SELECT * FROM users WHERE email=?", [email]).fetchone()
            c.close()
        return dict(row) if row else None

    # -- api tokens -----------------------------------------------------------

    def create_api_token(self, org_id, label="default"):
        token_id = make_uuid()
        token_value = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            c = self._conn()
            c.execute(
                "INSERT INTO api_tokens (id, org_id, token, label, created_at) VALUES (?,?,?,?,?)",
                [token_id, org_id, token_value, label, now],
            )
            c.commit()
            c.close()
        return {"id": token_id, "org_id": org_id, "token": token_value,
                "label": label, "created_at": now}

    def get_api_tokens(self, org_id):
        with self._lock:
            c = self._conn()
            rows = c.execute(
                "SELECT * FROM api_tokens WHERE org_id=? ORDER BY created_at DESC", [org_id]
            ).fetchall()
            c.close()
        return [dict(r) for r in rows]

    def delete_api_token(self, org_id, token_id):
        with self._lock:
            c = self._conn()
            cur = c.execute(
                "DELETE FROM api_tokens WHERE id=? AND org_id=?", [token_id, org_id]
            )
            c.commit()
            deleted = cur.rowcount > 0
            c.close()
        return deleted

    def lookup_token(self, token_value):
        if not token_value:
            return None
        with self._lock:
            c = self._conn()
            row = c.execute(
                "SELECT * FROM api_tokens WHERE token=?", [token_value]
            ).fetchone()
            c.close()
        return dict(row) if row else None

    # -- agents ---------------------------------------------------------------

    def upsert_agent(self, org_id, agent_id, hostname, ip, os_info, agent_ver, meta, tags):
        now = time.time()
        with self._lock:
            c = self._conn()
            c.execute(
                """INSERT INTO agents (id, org_id, hostname, ip, os_info, agent_ver,
                   first_seen, last_seen, meta, tags, offline_alerted)
                   VALUES (?,?,?,?,?,?,?,?,?,?,0)
                   ON CONFLICT(id) DO UPDATE SET
                     org_id=excluded.org_id,
                     hostname=excluded.hostname,
                     ip=excluded.ip,
                     os_info=excluded.os_info,
                     agent_ver=excluded.agent_ver,
                     last_seen=excluded.last_seen,
                     meta=excluded.meta,
                     tags=excluded.tags,
                     offline_alerted=0""",
                [agent_id, org_id, hostname, ip, os_info, agent_ver, now, now,
                 json.dumps(meta) if isinstance(meta, dict) else meta,
                 tags],
            )
            c.commit()
            c.close()

    def get_agents(self, org_id, search=None):
        with self._lock:
            c = self._conn()
            if search:
                q = "%{}%".format(search)
                rows = c.execute(
                    "SELECT * FROM agents WHERE org_id=? AND "
                    "(hostname LIKE ? OR id LIKE ? OR tags LIKE ?) ORDER BY last_seen DESC",
                    [org_id, q, q, q],
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM agents WHERE org_id=? ORDER BY last_seen DESC", [org_id]
                ).fetchall()
            c.close()
        return [dict(r) for r in rows]

    def get_agent(self, org_id, agent_id):
        with self._lock:
            c = self._conn()
            row = c.execute(
                "SELECT * FROM agents WHERE id=? AND org_id=?", [agent_id, org_id]
            ).fetchone()
            c.close()
        return dict(row) if row else None

    def get_offline_agents(self, threshold):
        cutoff = time.time() - threshold
        with self._lock:
            c = self._conn()
            rows = c.execute(
                "SELECT a.*, o.name AS org_name FROM agents a "
                "JOIN organizations o ON a.org_id = o.id "
                "WHERE a.last_seen < ? AND a.offline_alerted = 0",
                [cutoff],
            ).fetchall()
            c.close()
        return [dict(r) for r in rows]

    def mark_offline_alerted(self, agent_id):
        with self._lock:
            c = self._conn()
            c.execute("UPDATE agents SET offline_alerted=1 WHERE id=?", [agent_id])
            c.commit()
            c.close()

    # -- alert groups ---------------------------------------------------------

    def upsert_alert(self, org_id, agent_id, fingerprint, category, severity, title,
                     detail, data, hostname):
        now = time.time()
        with self._lock:
            c = self._conn()
            existing = c.execute(
                """SELECT id, last_seen FROM alert_groups
                   WHERE agent_id=? AND fingerprint=?
                   ORDER BY last_seen DESC LIMIT 1""",
                [agent_id, fingerprint],
            ).fetchone()

            if existing and (now - existing["last_seen"]) < ALERT_DEDUP:
                c.execute(
                    """UPDATE alert_groups
                       SET count=count+1, last_seen=?, last_detail=?,
                           last_data=?, severity=?
                       WHERE id=?""",
                    [now, detail, json.dumps(data) if isinstance(data, dict) else data,
                     severity, existing["id"]],
                )
                is_new = False
            else:
                c.execute(
                    """INSERT INTO alert_groups
                       (agent_id, org_id, fingerprint, category, severity, title,
                        first_seen, last_seen, count, last_detail, last_data, hostname)
                       VALUES (?,?,?,?,?,?,?,?,1,?,?,?)""",
                    [agent_id, org_id, fingerprint, category, severity, title,
                     now, now, detail,
                     json.dumps(data) if isinstance(data, dict) else data,
                     hostname],
                )
                is_new = True
            c.commit()
            c.close()
        return is_new

    def get_alerts(self, org_id, agent_id=None, severity=None, category=None,
                   limit=50, offset=0, hours=None, search=None):
        clauses = ["org_id=?"]
        params = [org_id]
        if agent_id:
            clauses.append("agent_id=?")
            params.append(agent_id)
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if category:
            clauses.append("category=?")
            params.append(category)
        if hours:
            clauses.append("last_seen > ?")
            params.append(time.time() - float(hours) * 3600)
        if search:
            clauses.append("(title LIKE ? OR last_detail LIKE ? OR hostname LIKE ?)")
            q = "%{}%".format(search)
            params.extend([q, q, q])

        where = " WHERE " + " AND ".join(clauses)
        with self._lock:
            c = self._conn()
            total = c.execute(
                "SELECT COUNT(*) AS cnt FROM alert_groups" + where, params
            ).fetchone()["cnt"]
            rows = c.execute(
                "SELECT * FROM alert_groups" + where +
                " ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
            c.close()
        return [dict(r) for r in rows], total

    def get_stats(self, org_id, agent_id=None, hours=24):
        cutoff = time.time() - float(hours) * 3600
        base_clause = " WHERE org_id=? AND last_seen > ?"
        params = [org_id, cutoff]
        if agent_id:
            base_clause += " AND agent_id=?"
            params.append(agent_id)

        with self._lock:
            c = self._conn()

            total = c.execute(
                "SELECT COUNT(*) AS cnt FROM alert_groups" + base_clause, params
            ).fetchone()["cnt"]

            by_sev = {}
            for row in c.execute(
                "SELECT severity, COUNT(*) AS cnt FROM alert_groups"
                + base_clause + " GROUP BY severity", params
            ).fetchall():
                by_sev[row["severity"]] = row["cnt"]

            by_cat = {}
            for row in c.execute(
                "SELECT category, COUNT(*) AS cnt FROM alert_groups"
                + base_clause + " GROUP BY category", params
            ).fetchall():
                by_cat[row["category"]] = row["cnt"]

            by_agent = {}
            for row in c.execute(
                "SELECT agent_id, hostname, COUNT(*) AS cnt FROM alert_groups"
                + base_clause + " GROUP BY agent_id", params
            ).fetchall():
                by_agent[row["agent_id"]] = {
                    "hostname": row["hostname"],
                    "count": row["cnt"],
                }

            hourly = []
            now = time.time()
            for i in range(24):
                bucket_start = now - (24 - i) * 3600
                bucket_end = now - (23 - i) * 3600
                hp = [org_id, bucket_start, bucket_end]
                ha_clause = " WHERE org_id=? AND last_seen >= ? AND last_seen < ?"
                if agent_id:
                    ha_clause += " AND agent_id=?"
                    hp.append(agent_id)
                cnt = c.execute(
                    "SELECT COUNT(*) AS cnt FROM alert_groups" + ha_clause, hp
                ).fetchone()["cnt"]
                hourly.append(cnt)

            agents_total = c.execute(
                "SELECT COUNT(*) AS cnt FROM agents WHERE org_id=?", [org_id]
            ).fetchone()["cnt"]
            offline_threshold = time.time() - 120
            agents_online = c.execute(
                "SELECT COUNT(*) AS cnt FROM agents WHERE org_id=? AND last_seen >= ?",
                [org_id, offline_threshold],
            ).fetchone()["cnt"]

            c.close()

        return {
            "total_24h": total,
            "by_severity": by_sev,
            "by_category": by_cat,
            "by_agent": by_agent,
            "hourly": hourly,
            "agents_total": agents_total,
            "agents_online": agents_online,
        }

    # -- sessions -------------------------------------------------------------

    def create_session(self, user_id, org_id, email, ttl):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            c = self._conn()
            c.execute("DELETE FROM sessions WHERE created_at < ?", [now - ttl])
            c.execute(
                "INSERT INTO sessions (token, created_at, user_id, org_id, email) "
                "VALUES (?,?,?,?,?)",
                [token, now, user_id, org_id, email],
            )
            c.commit()
            c.close()
        return token

    def validate_session(self, token, ttl):
        if not token:
            return None
        now = time.time()
        with self._lock:
            c = self._conn()
            row = c.execute(
                "SELECT * FROM sessions WHERE token=? AND created_at > ?",
                [token, now - ttl],
            ).fetchone()
            c.close()
        if not row:
            return None
        return {"user_id": row["user_id"], "org_id": row["org_id"], "email": row["email"]}

    def delete_session(self, token):
        with self._lock:
            c = self._conn()
            c.execute("DELETE FROM sessions WHERE token=?", [token])
            c.commit()
            c.close()


# ---------------------------------------------------------------------------
# Notifier
# ---------------------------------------------------------------------------

class Notifier:
    def __init__(self, cfg):
        self._cfg = cfg

    def _email_enabled(self):
        return self._cfg.get("notifications", "email_enabled").lower() == "true"

    def _slack_enabled(self):
        return self._cfg.get("notifications", "slack_enabled").lower() == "true"

    def _severity_passes(self, severity):
        threshold = self._cfg.get("notifications", "min_severity")
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 2)

    def notify_alert(self, alert):
        if not self._severity_passes(alert.get("severity", "low")):
            return
        subject = "[Sentinel] {} — {} on {}".format(
            alert.get("severity", "?").upper(),
            alert.get("title", "Alert"),
            alert.get("hostname", "unknown"),
        )
        org_line = ""
        if alert.get("org_name"):
            org_line = "Org: {}\n".format(alert["org_name"])
        body = (
            "{org_line}"
            "Category: {category}\n"
            "Severity: {severity}\n"
            "Host: {hostname}\n"
            "Title: {title}\n"
            "Detail: {detail}\n"
            "Time: {time}\n"
        ).format(
            org_line=org_line,
            category=alert.get("category", ""),
            severity=alert.get("severity", ""),
            hostname=alert.get("hostname", ""),
            title=alert.get("title", ""),
            detail=alert.get("detail", ""),
            time=datetime.now(timezone.utc).isoformat(),
        )
        self._send(subject, body)

    def notify_offline(self, agent):
        if self._cfg.get("notifications", "notify_offline").lower() != "true":
            return
        subject = "[Sentinel] Agent offline: {}".format(
            agent.get("hostname", agent.get("id", "?"))
        )
        last = agent.get("last_seen", 0)
        last_str = datetime.fromtimestamp(last, tz=timezone.utc).isoformat() if last else "never"
        org_line = ""
        if agent.get("org_name"):
            org_line = "Org: {}\n".format(agent["org_name"])
        body = (
            "{org_line}"
            "Agent {hostname} ({agent_id}) has not checked in.\n"
            "Last seen: {last_str}\n"
            "IP: {ip}\n"
            "Tags: {tags}\n"
        ).format(
            org_line=org_line,
            hostname=agent.get("hostname", "?"),
            agent_id=agent.get("id", "?"),
            last_str=last_str,
            ip=agent.get("ip", "?"),
            tags=agent.get("tags", ""),
        )
        self._send(subject, body)

    def _send(self, subject, body):
        if self._email_enabled():
            self._send_email(subject, body)
        if self._slack_enabled():
            self._send_slack("{}\n{}".format(subject, body))

    def _send_email(self, subject, body):
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self._cfg.get("notifications", "smtp_user")
            msg["To"] = self._cfg.get("notifications", "alert_to")
            ctx = ssl.create_default_context()
            with smtplib.SMTP(
                self._cfg.get("notifications", "smtp_host"),
                self._cfg.getint("notifications", "smtp_port"),
            ) as srv:
                srv.starttls(context=ctx)
                srv.login(
                    self._cfg.get("notifications", "smtp_user"),
                    self._cfg.get("notifications", "smtp_password"),
                )
                srv.send_message(msg)
            LOG.info("Email sent: %s", subject)
        except Exception:
            LOG.exception("Failed to send email")

    def _send_slack(self, text):
        webhook = self._cfg.get("notifications", "slack_webhook")
        if not webhook:
            return
        try:
            payload = json.dumps({"text": text}).encode()
            req = urllib.request.Request(
                webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
            LOG.info("Slack notification sent")
        except Exception:
            LOG.exception("Failed to send Slack notification")


# ---------------------------------------------------------------------------
# Offline watcher
# ---------------------------------------------------------------------------

class OfflineWatcher(threading.Thread):
    def __init__(self, db, cfg, notifier):
        super().__init__(daemon=True)
        self._db = db
        self._cfg = cfg
        self._notifier = notifier
        self._stop_event = threading.Event()

    def run(self):
        LOG.info("OfflineWatcher started")
        while not self._stop_event.is_set():
            try:
                threshold = self._cfg.getint("server", "offline_after")
                agents = self._db.get_offline_agents(threshold)
                for agent in agents:
                    LOG.warning("Agent offline: %s (%s) org=%s",
                                agent["hostname"], agent["id"],
                                agent.get("org_name", agent.get("org_id", "?")))
                    self._notifier.notify_offline(agent)
                    self._db.mark_offline_alerted(agent["id"])
            except Exception:
                LOG.exception("OfflineWatcher error")
            self._stop_event.wait(30)

    def stop(self):
        self._stop_event.set()


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_PAGE_STYLE = """\
*{margin:0;padding:0;box-sizing:border-box}
body{background:#05080d;color:#c8d6e5;font-family:'Syne',sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#090e15;border:1px solid rgba(0,229,255,.12);
  border-radius:12px;padding:2.5rem;width:100%;max-width:400px;
  box-shadow:0 0 40px rgba(0,229,255,.04)}
h1{font-size:1.5rem;font-weight:700;color:#00e5ff;margin-bottom:.25rem;
  letter-spacing:.5px}
.sub{font-family:'Syne Mono',monospace;font-size:.75rem;color:#4a5568;
  margin-bottom:2rem}
label{display:block;font-size:.8rem;color:#718096;margin-bottom:.35rem;
  font-weight:600;letter-spacing:.3px;text-transform:uppercase}
input{width:100%;padding:.65rem .85rem;background:#05080d;
  border:1px solid rgba(0,229,255,.15);border-radius:6px;color:#e2e8f0;
  font-family:'Syne Mono',monospace;font-size:.9rem;margin-bottom:1.25rem;
  outline:none;transition:border .2s}
input:focus{border-color:#00e5ff}
button{width:100%;padding:.7rem;background:#00e5ff;color:#05080d;
  font-family:'Syne',sans-serif;font-weight:700;font-size:.9rem;
  border:none;border-radius:6px;cursor:pointer;letter-spacing:.3px;
  transition:opacity .2s}
button:hover{opacity:.85}
.err{color:#ff5252;font-size:.8rem;margin-bottom:1rem;text-align:center;
  font-family:'Syne Mono',monospace}
.link{text-align:center;margin-top:1.25rem;font-size:.8rem}
.link a{color:#00e5ff;text-decoration:none;font-family:'Syne Mono',monospace}
.link a:hover{text-decoration:underline}
"""

LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=Syne+Mono&display=swap" rel="stylesheet">
<style>""" + _PAGE_STYLE + """</style>
</head>
<body>
<form class="card" method="POST" action="/login">
  <h1>Sentinel</h1>
  <p class="sub">Sign in to your dashboard</p>
  {{ERROR}}
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="email" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
  <p class="link">Don't have an account? <a href="/register">Create one</a></p>
</form>
</body>
</html>
"""

REGISTER_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — Register</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=Syne+Mono&display=swap" rel="stylesheet">
<style>""" + _PAGE_STYLE + """</style>
</head>
<body>
<form class="card" method="POST" action="/register">
  <h1>Create your account</h1>
  <p class="sub">Start monitoring your infrastructure</p>
  {{ERROR}}
  <label for="org_name">Organization name</label>
  <input id="org_name" name="org_name" type="text" required autofocus>
  <label for="user_name">Your name</label>
  <input id="user_name" name="user_name" type="text" required>
  <label for="email">Email</label>
  <input id="email" name="email" type="email" autocomplete="email" required>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="new-password" required>
  <label for="confirm_password">Confirm password</label>
  <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
  <button type="submit">Create Account</button>
  <p class="link">Already have an account? <a href="/login">Sign in</a></p>
</form>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class SentinelHandler(BaseHTTPRequestHandler):
    server_version = "Sentinel/3.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        LOG.info("%s %s", self.address_string(), fmt % args)

    # -- helpers ---------------------------------------------------------------

    def _db(self):
        return self.server.db

    def _cfg(self):
        return self.server.cfg

    def _notifier(self):
        return self.server.notifier

    def _send(self, code, body, content_type="text/html; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj), "application/json", headers)

    def _get_cookie(self, name):
        header = self.headers.get("Cookie", "")
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(header)
        except http.cookies.CookieError:
            return None
        morsel = cookies.get(name)
        return morsel.value if morsel else None

    def _require_session(self):
        token = self._get_cookie("sentinel_session")
        ttl = self._cfg().getint("server", "session_ttl")
        session = self._db().validate_session(token, ttl)
        if not session:
            self._send(302, "", headers={"Location": "/login"})
            return None
        return session

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def _parse_qs(self, url):
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _param(self, qs, name, default=None):
        vals = qs.get(name, [])
        return vals[0] if vals else default

    def _client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _serve_file(self, filepath, content_type=None):
        try:
            fp = pathlib.Path(filepath)
            if not fp.is_file():
                self._send(404, "Not found")
                return
            data = fp.read_bytes()
            if content_type is None:
                ext = fp.suffix.lower()
                ct_map = {
                    ".html": "text/html; charset=utf-8",
                    ".js": "application/javascript",
                    ".css": "text/css",
                    ".json": "application/json",
                    ".png": "image/png",
                    ".svg": "image/svg+xml",
                    ".ico": "image/x-icon",
                    ".py": "text/plain",
                    ".sh": "text/plain",
                }
                content_type = ct_map.get(ext, "application/octet-stream")
            self._send(200, data, content_type)
        except Exception:
            LOG.exception("Error serving %s", filepath)
            self._send(500, "Internal server error")

    # -- routing ---------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path == "/agent.py":
            base = pathlib.Path(__file__).resolve().parent.parent / "agent" / "agent.py"
            self._serve_file(str(base))
        elif path == "/install.sh":
            base = pathlib.Path(__file__).resolve().parent.parent / "agent" / "install.sh"
            self._serve_file(str(base))
        elif path == "/register":
            self._handle_register_page()
        elif path == "/login":
            self._handle_login_page()
        elif path == "/logout":
            self._handle_logout()
        elif path == "/api/status":
            self._json(200, {"status": "ok", "version": __version__, "time": time.time()})
        elif path == "/":
            session = self._require_session()
            if not session:
                return
            base = pathlib.Path(__file__).resolve().parent / "dashboard" / "index.html"
            self._serve_file(str(base))
        elif path == "/api/me":
            self._handle_get_me()
        elif path == "/api/agents":
            self._handle_get_agents(qs)
        elif path == "/api/alerts":
            self._handle_get_alerts(qs)
        elif path == "/api/stats":
            self._handle_get_stats(qs)
        elif path == "/api/tokens":
            self._handle_get_tokens()
        elif path.startswith("/api/agent/"):
            agent_id = path[len("/api/agent/"):]
            self._handle_get_agent(agent_id)
        else:
            base = pathlib.Path(__file__).resolve().parent / "dashboard"
            requested = (base / path.lstrip("/")).resolve()
            if str(requested).startswith(str(base)) and requested.is_file():
                if not self._require_session():
                    return
                self._serve_file(str(requested))
            else:
                self._send(404, "Not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/register":
            self._handle_register_submit()
        elif path == "/login":
            self._handle_login_submit()
        elif path == "/api/ingest":
            self._handle_ingest()
        elif path == "/api/tokens":
            self._handle_create_token()
        else:
            self._send(404, "Not found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path.startswith("/api/tokens/"):
            token_id = path[len("/api/tokens/"):]
            self._handle_delete_token(token_id)
        else:
            self._send(404, "Not found")

    # -- GET handlers ----------------------------------------------------------

    def _handle_register_page(self, error=""):
        err_block = '<p class="err">{}</p>'.format(error) if error else ""
        html = REGISTER_HTML.replace("{{ERROR}}", err_block)
        self._send(200, html)

    def _handle_login_page(self, error=""):
        err_block = '<p class="err">{}</p>'.format(error) if error else ""
        html = LOGIN_HTML.replace("{{ERROR}}", err_block)
        self._send(200, html)

    def _handle_logout(self):
        token = self._get_cookie("sentinel_session")
        if token:
            self._db().delete_session(token)
        self._send(302, "", headers={
            "Location": "/login",
            "Set-Cookie": "sentinel_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        })

    def _handle_get_me(self):
        session = self._require_session()
        if not session:
            return
        user = self._db().get_user_by_email(session["email"])
        if not user:
            self._json(401, {"error": "User not found"})
            return
        org = self._db().get_organization(session["org_id"])
        if not org:
            self._json(401, {"error": "Organization not found"})
            return
        self._json(200, {
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
            "org": {
                "id": org["id"],
                "name": org["name"],
                "slug": org["slug"],
            },
        })

    def _handle_get_agents(self, qs):
        session = self._require_session()
        if not session:
            return
        search = self._param(qs, "search")
        agents = self._db().get_agents(session["org_id"], search)
        offline_after = self._cfg().getint("server", "offline_after")
        now = time.time()
        for a in agents:
            a["online"] = (now - (a.get("last_seen") or 0)) < offline_after
        self._json(200, agents)

    def _handle_get_alerts(self, qs):
        session = self._require_session()
        if not session:
            return
        alerts, total = self._db().get_alerts(
            org_id=session["org_id"],
            agent_id=self._param(qs, "agent_id"),
            severity=self._param(qs, "severity"),
            category=self._param(qs, "category"),
            limit=int(self._param(qs, "limit", "50")),
            offset=int(self._param(qs, "offset", "0")),
            hours=self._param(qs, "hours"),
            search=self._param(qs, "search"),
        )
        self._json(200, {
            "alerts": alerts,
            "total": total,
            "limit": int(self._param(qs, "limit", "50")),
            "offset": int(self._param(qs, "offset", "0")),
        })

    def _handle_get_stats(self, qs):
        session = self._require_session()
        if not session:
            return
        stats = self._db().get_stats(
            org_id=session["org_id"],
            agent_id=self._param(qs, "agent_id"),
            hours=float(self._param(qs, "hours", "24")),
        )
        self._json(200, stats)

    def _handle_get_agent(self, agent_id):
        session = self._require_session()
        if not session:
            return
        agent = self._db().get_agent(session["org_id"], agent_id)
        if not agent:
            self._json(404, {"error": "Agent not found"})
            return
        offline_after = self._cfg().getint("server", "offline_after")
        agent["online"] = (time.time() - (agent.get("last_seen") or 0)) < offline_after
        self._json(200, agent)

    def _handle_get_tokens(self):
        session = self._require_session()
        if not session:
            return
        tokens = self._db().get_api_tokens(session["org_id"])
        self._json(200, tokens)

    # -- POST handlers ---------------------------------------------------------

    def _handle_register_submit(self):
        body = self._read_body().decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(body)
        org_name = (params.get("org_name") or [""])[0].strip()
        user_name = (params.get("user_name") or [""])[0].strip()
        email = (params.get("email") or [""])[0].strip().lower()
        password = (params.get("password") or [""])[0]
        confirm = (params.get("confirm_password") or [""])[0]

        if not org_name or not user_name or not email or not password:
            self._handle_register_page(error="All fields are required")
            return

        if password != confirm:
            self._handle_register_page(error="Passwords do not match")
            return

        if len(password) < 6:
            self._handle_register_page(error="Password must be at least 6 characters")
            return

        slug = make_slug(org_name)
        if not slug:
            self._handle_register_page(error="Invalid organization name")
            return

        if self._db().slug_exists(slug):
            self._handle_register_page(error="Organization name already taken")
            return

        if self._db().get_user_by_email(email):
            self._handle_register_page(error="Email already registered")
            return

        org = self._db().create_organization(org_name, slug)
        if not org:
            self._handle_register_page(error="Could not create organization")
            return

        pw_hash = hash_password(password)
        user = self._db().create_user(org["id"], user_name, email, pw_hash, "owner")
        if not user:
            self._handle_register_page(error="Could not create user — email may already exist")
            return

        self._db().create_api_token(org["id"], "default")

        ttl = self._cfg().getint("server", "session_ttl")
        token = self._db().create_session(user["id"], org["id"], email, ttl)
        cookie = "sentinel_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax".format(
            token, ttl
        )
        self._send(302, "", headers={"Location": "/", "Set-Cookie": cookie})

    def _handle_login_submit(self):
        body = self._read_body().decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(body)
        email = (params.get("email") or [""])[0].strip().lower()
        password = (params.get("password") or [""])[0]

        if not email or not password:
            self._handle_login_page(error="Email and password are required")
            return

        user = self._db().get_user_by_email(email)
        if not user or not verify_password(user["password_hash"], password):
            self._handle_login_page(error="Invalid credentials")
            return

        ttl = self._cfg().getint("server", "session_ttl")
        token = self._db().create_session(user["id"], user["org_id"], user["email"], ttl)
        cookie = "sentinel_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax".format(
            token, ttl
        )
        self._send(302, "", headers={"Location": "/", "Set-Cookie": cookie})

    def _handle_ingest(self):
        provided_token = self.headers.get("X-Sentinel-Token", "")
        token_record = self._db().lookup_token(provided_token)

        if not token_record:
            self._json(403, {"error": "Invalid token"})
            return

        org_id = token_record["org_id"]

        try:
            raw = self._read_body()
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._json(400, {"error": "Invalid JSON"})
            return

        agent_id = payload.get("agent_id", "")
        hostname = payload.get("hostname", "")
        os_info = payload.get("os_info", "")
        agent_ver = payload.get("agent_ver", "")
        tags = payload.get("tags", "")
        meta = payload.get("meta", {})
        alerts = payload.get("alerts", [])

        if not agent_id:
            self._json(400, {"error": "Missing agent_id"})
            return

        client_ip = self._client_ip()
        self._db().upsert_agent(org_id, agent_id, hostname, client_ip, os_info,
                                agent_ver, meta, tags)

        new_count = 0
        for alert in alerts:
            cat = alert.get("category", "")
            title = alert.get("title", "")
            severity = alert.get("severity", "low")
            detail = alert.get("detail", "")
            data = alert.get("data", {})
            a_hostname = alert.get("hostname", hostname)

            fp_raw = "{}:{}:{}".format(agent_id, cat, title)
            fingerprint = hashlib.sha256(fp_raw.encode()).hexdigest()[:16]

            is_new = self._db().upsert_alert(
                org_id, agent_id, fingerprint, cat, severity, title, detail, data,
                a_hostname
            )
            if is_new:
                new_count += 1
                self._notifier().notify_alert({
                    "category": cat,
                    "severity": severity,
                    "hostname": a_hostname,
                    "title": title,
                    "detail": detail,
                })

        self._json(200, {"ok": True, "new_alerts": new_count, "total": len(alerts)})

    def _handle_create_token(self):
        session = self._require_session()
        if not session:
            return
        try:
            raw = self._read_body()
            body = json.loads(raw) if raw else {}
        except (json.JSONDecodeError, ValueError):
            body = {}
        label = body.get("label", "default").strip()
        if not label:
            label = "default"
        token_obj = self._db().create_api_token(session["org_id"], label)
        self._json(201, token_obj)

    # -- DELETE handlers -------------------------------------------------------

    def _handle_delete_token(self, token_id):
        session = self._require_session()
        if not session:
            return
        deleted = self._db().delete_api_token(session["org_id"], token_id)
        if deleted:
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "Token not found"})


# ---------------------------------------------------------------------------
# Threaded HTTP server
# ---------------------------------------------------------------------------

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------

def setup_wizard():
    print("=" * 50)
    print("  Sentinel V3 — Central Server Setup")
    print("=" * 50)
    print()

    port = input("Server port [8765]: ").strip() or "8765"
    db_path = input("Database path [/var/lib/sentinel-central/sentinel.db]: ").strip()
    db_path = db_path or "/var/lib/sentinel-central/sentinel.db"

    email_enabled = input("Enable email notifications? [y/N]: ").strip().lower() == "y"
    smtp_host = ""
    smtp_port = "587"
    smtp_user = ""
    smtp_password = ""
    alert_to = ""
    if email_enabled:
        smtp_host = input("  SMTP host [smtp.gmail.com]: ").strip() or "smtp.gmail.com"
        smtp_port = input("  SMTP port [587]: ").strip() or "587"
        smtp_user = input("  SMTP user: ").strip()
        smtp_password = getpass.getpass("  SMTP password: ")
        alert_to = input("  Alert recipient email: ").strip()

    slack_enabled = input("Enable Slack notifications? [y/N]: ").strip().lower() == "y"
    slack_webhook = ""
    if slack_enabled:
        slack_webhook = input("  Slack webhook URL: ").strip()

    cfg = configparser.ConfigParser()
    cfg.add_section("server")
    cfg.set("server", "port", port)
    cfg.set("server", "db_path", db_path)
    cfg.set("server", "offline_after", "120")
    cfg.set("server", "session_ttl", "86400")

    cfg.add_section("notifications")
    cfg.set("notifications", "email_enabled", str(email_enabled).lower())
    cfg.set("notifications", "smtp_host", smtp_host)
    cfg.set("notifications", "smtp_port", smtp_port)
    cfg.set("notifications", "smtp_user", smtp_user)
    cfg.set("notifications", "smtp_password", smtp_password)
    cfg.set("notifications", "alert_to", alert_to)
    cfg.set("notifications", "notify_offline", "true")
    cfg.set("notifications", "min_severity", "high")
    cfg.set("notifications", "slack_enabled", str(slack_enabled).lower())
    cfg.set("notifications", "slack_webhook", slack_webhook)

    conf_dir = "/etc/sentinel"
    conf_path = os.path.join(conf_dir, "server.conf")

    try:
        os.makedirs(conf_dir, exist_ok=True)
    except PermissionError:
        print("\nCannot create {}. Run with sudo or create it manually.".format(conf_dir))
        conf_path = os.path.join(os.getcwd(), "server.conf")
        print("Writing to {} instead.".format(conf_path))

    db_dir = os.path.dirname(db_path)
    try:
        os.makedirs(db_dir, exist_ok=True)
    except PermissionError:
        print("Cannot create DB directory {}. Create it manually and ensure write permissions.".format(db_dir))

    with open(conf_path, "w") as f:
        cfg.write(f)

    print()
    print("Configuration written to: {}".format(conf_path))
    print("Database path: {}".format(db_path))
    print()
    print("Users and API tokens are created via the web UI (/register).")
    print()
    print("Start the server with:")
    print("  python3 central/server.py --config {}".format(conf_path))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Sentinel V3 Central Server")
    parser.add_argument("--config", default="/etc/sentinel/server.conf",
                        help="Path to config file")
    parser.add_argument("--setup", action="store_true",
                        help="Run interactive setup wizard")
    args = parser.parse_args()

    if args.setup:
        setup_wizard()
        return

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cfg = load_config(args.config)

    db_path = cfg.get("server", "db_path")
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.isdir(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    db = Database(db_path)
    notifier = Notifier(cfg)

    port = cfg.getint("server", "port")
    server = ThreadedHTTPServer(("0.0.0.0", port), SentinelHandler)
    server.db = db
    server.cfg = cfg
    server.notifier = notifier

    watcher = OfflineWatcher(db, cfg, notifier)
    watcher.start()

    shutdown_event = threading.Event()

    def _shutdown(signum, frame):
        LOG.info("Received signal %s, shutting down…", signum)
        shutdown_event.set()
        watcher.stop()
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    LOG.info("Sentinel V3 Central Server starting on port %d", port)
    LOG.info("Database: %s", db_path)

    try:
        server.serve_forever()
    except Exception:
        if not shutdown_event.is_set():
            LOG.exception("Server error")
    finally:
        watcher.stop()
        LOG.info("Server stopped.")


if __name__ == "__main__":
    main()
