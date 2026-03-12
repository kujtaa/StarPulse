#!/usr/bin/env python3
"""Sentinel V3 — Security Monitoring Agent.

Monitors a Linux host for file-integrity changes, crypto-mining activity,
HTTP log anomalies, and suspicious network behaviour.  Pushes alerts to a
central Sentinel server over HTTP.

Usage:
    python3 agent.py --config /etc/sentinel/agent.conf
    python3 agent.py --config /etc/sentinel/agent.conf --baseline
"""

from __future__ import print_function

import argparse
import collections
import configparser
import glob
import hashlib
import json
import logging
import os
import platform
import re
import signal
import socket
import struct
import sys
import threading
import time

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:
    from urllib2 import Request, urlopen, URLError, HTTPError

if sys.version_info < (3, 6):
    sys.exit("Sentinel agent requires Python 3.6+")

AGENT_VERSION = "3.0"

DEFAULT_CFG = {
    "agent": {
        "server_url": "http://127.0.0.1:8765",
        "token": "",
        "scan_interval": "30",
        "push_interval": "30",
        "agent_id": "",
        "tags": "",
    },
    "file_integrity": {
        "enabled": "true",
        "watch_dirs": "/etc,/usr/bin,/usr/sbin,/bin,/sbin",
        "suspicious_dirs": "/tmp,/var/tmp,/dev/shm",
        "suspicious_extensions": ".sh,.py,.pl,.php,.so,.elf,.bin",
        "baseline_file": "/var/lib/sentinel/baseline.json",
    },
    "crypto_mining": {
        "enabled": "true",
        "cpu_threshold_percent": "80",
        "sustained_seconds": "60",
        "known_miners": (
            "xmrig,xmr-stak,minerd,cpuminer,cgminer,bfgminer,"
            "ethminer,t-rex,gminer,nbminer,lolminer,phoenixminer"
        ),
        "mining_ports": "3333,4444,5555,7777,8888,9999,14444,45700,3032",
        "mining_domains": (
            "moneroocean,pool.supportxmr,xmrig.com,c3pool,2miners,"
            "nanopool,f2pool,ethermine,flypool,hiveon"
        ),
        "check_cron": "true",
    },
    "http_anomaly": {
        "enabled": "true",
        "log_paths": (
            "/var/log/nginx/access.log,/var/log/apache2/access.log,"
            "/var/log/httpd/access_log"
        ),
        "threshold_404": "50",
        "threshold_403": "30",
        "threshold_500": "20",
        "threshold_same_ip": "100",
    },
    "network": {
        "enabled": "true",
        "suspicious_ports": "4444,5555,6666,7777,1337,31337,12345,54321,9001,6667",
        "check_dns": "true",
        "alert_on_new_listening_ports": "true",
    },
}

log = logging.getLogger("sentinel")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

import subprocess  # noqa: E402  (grouped with stdlib above conceptually)


def _run(cmd, timeout=5):
    """Run a command list safely and return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", "command not found: {}".format(cmd[0]), 127
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as exc:
        return "", str(exc), -1


def _sha256(path):
    """Return hex SHA-256 of a file, or None on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return None


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _now_ms():
    return int(time.time() * 1000)


def _hostname():
    return socket.gethostname()


def _os_info():
    u = platform.uname()
    return "{} {} {}".format(u.system, u.release, u.machine)


def _read_file(path):
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except (OSError, IOError):
        return ""


def _csv(value):
    """Split a comma-separated config value into a list of stripped strings."""
    return [s.strip() for s in value.split(",") if s.strip()]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_cfg(path):
    """Read the INI config file and merge with DEFAULT_CFG."""
    cp = configparser.ConfigParser()
    for section, kvs in DEFAULT_CFG.items():
        if not cp.has_section(section):
            cp.add_section(section)
        for k, v in kvs.items():
            cp.set(section, k, v)
    if path and os.path.isfile(path):
        cp.read(path)
    else:
        log.warning("Config file not found at %s — using defaults", path)
    return cp


# ---------------------------------------------------------------------------
# Agent ID
# ---------------------------------------------------------------------------

def get_agent_id(cfg, cfg_path):
    """Return a stable UUID-formatted agent identifier.

    Priority: config value > derived from hostname + machine-id.
    Once derived it is written back to the config file so it persists.
    """
    existing = cfg.get("agent", "agent_id", fallback="").strip()
    if existing:
        return existing

    machine_id = _read_file("/etc/machine-id")
    raw = "{}{}".format(_hostname(), machine_id)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    uid = "{}-{}-{}-{}-{}".format(
        digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]
    )
    cfg.set("agent", "agent_id", uid)

    if cfg_path:
        try:
            d = os.path.dirname(cfg_path)
            if d and not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            with open(cfg_path, "w") as fh:
                cfg.write(fh)
            log.info("Persisted agent_id %s to %s", uid, cfg_path)
        except (OSError, IOError) as exc:
            log.warning("Could not persist agent_id: %s", exc)

    return uid


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------

class AlertManager(object):
    """Thread-safe in-memory alert buffer."""

    def __init__(self, maxlen=5000):
        self.pending = collections.deque(maxlen=maxlen)
        self.lock = threading.Lock()

    def fire(self, category, severity, title, detail, data=None):
        alert = {
            "id": _now_ms(),
            "timestamp": _now_iso(),
            "category": category,
            "severity": severity,
            "title": title,
            "detail": detail,
            "data": data or {},
            "hostname": _hostname(),
        }
        with self.lock:
            self.pending.append(alert)
        log.info("[%s/%s] %s", category, severity, title)

    def drain(self):
        with self.lock:
            items = list(self.pending)
            self.pending.clear()
        return items

    def requeue(self, items):
        with self.lock:
            for a in items:
                self.pending.appendleft(a)


# ---------------------------------------------------------------------------
# Pusher
# ---------------------------------------------------------------------------

class Pusher(object):
    """Background thread that ships alerts to the central server."""

    def __init__(self, cfg, am, agent_id, shutdown_event):
        self.am = am
        self.agent_id = agent_id
        self.shutdown = shutdown_event
        self.server_url = cfg.get("agent", "server_url", fallback="http://127.0.0.1:8765")
        self.token = cfg.get("agent", "token", fallback="")
        self.interval = int(cfg.get("agent", "push_interval", fallback="30"))
        self.tags = cfg.get("agent", "tags", fallback="")
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()

    def _loop(self):
        import random
        stagger = random.uniform(1, 10)
        log.debug("Pusher stagger: %.1fs", stagger)
        self.shutdown.wait(stagger)

        while not self.shutdown.is_set():
            self._push()
            self.shutdown.wait(self.interval)

        self._push()

    def _push(self):
        alerts = self.am.drain()
        payload = {
            "agent_id": self.agent_id,
            "hostname": _hostname(),
            "os_info": _os_info(),
            "agent_ver": AGENT_VERSION,
            "tags": self.tags,
            "alerts": alerts,
            "meta": {"python": platform.python_version()},
        }
        body = json.dumps(payload).encode("utf-8")
        url = self.server_url.rstrip("/") + "/api/ingest"
        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("X-Sentinel-Token", self.token)
        try:
            resp = urlopen(req, timeout=15)
            resp.read()
            log.debug("Pushed %d alerts -> %s (%s)", len(alerts), url, resp.status)
        except Exception as exc:
            log.warning("Push failed (%s) — re-queuing %d alerts", exc, len(alerts))
            self.am.requeue(alerts)


# ---------------------------------------------------------------------------
# Module 1 — FIM (File Integrity Monitor)
# ---------------------------------------------------------------------------

class FIM(object):
    """Monitors file integrity via SHA-256 hashing and suspicious-dir scanning."""

    def __init__(self, cfg, am):
        self.am = am
        self.watch_dirs = _csv(cfg.get("file_integrity", "watch_dirs", fallback=""))
        self.suspicious_dirs = _csv(cfg.get("file_integrity", "suspicious_dirs", fallback=""))
        self.suspicious_exts = set(
            _csv(cfg.get("file_integrity", "suspicious_extensions", fallback=""))
        )
        self.baseline_file = cfg.get(
            "file_integrity", "baseline_file",
            fallback="/var/lib/sentinel/baseline.json",
        )
        self.baseline = {}
        self._load_baseline()

    # -- baseline --------------------------------------------------------

    def _load_baseline(self):
        if os.path.isfile(self.baseline_file):
            try:
                with open(self.baseline_file, "r") as fh:
                    self.baseline = json.load(fh)
                log.info("FIM baseline loaded: %d files", len(self.baseline))
            except (OSError, IOError, ValueError) as exc:
                log.warning("Could not load baseline: %s", exc)

    def build_baseline(self):
        log.info("FIM: building baseline for %s", self.watch_dirs)
        bl = {}
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            for root, _dirs, files in os.walk(d):
                for fn in files:
                    fp = os.path.join(root, fn)
                    h = _sha256(fp)
                    if h is not None:
                        bl[fp] = h
        d = os.path.dirname(self.baseline_file)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(self.baseline_file, "w") as fh:
            json.dump(bl, fh)
        self.baseline = bl
        log.info("FIM baseline written: %d files -> %s", len(bl), self.baseline_file)

    # -- scan ------------------------------------------------------------

    def scan(self):
        self._scan_suspicious_dirs()
        self._scan_baseline()

    def _scan_suspicious_dirs(self):
        cutoff = time.time() - 7200  # 120 minutes
        for d in self.suspicious_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for root, _dirs, files in os.walk(d):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        _, ext = os.path.splitext(fn)
                        if ext not in self.suspicious_exts:
                            continue
                        try:
                            st = os.stat(fp)
                        except OSError:
                            continue
                        if st.st_mtime < cutoff:
                            continue
                        is_exec = os.access(fp, os.X_OK)
                        self.am.fire(
                            "file_integrity", "high",
                            "Suspicious file in {}".format(d),
                            "New file: {} ({}b, exec={})".format(fp, st.st_size, is_exec),
                            {"path": fp, "size": str(st.st_size), "executable": str(is_exec)},
                        )
            except OSError:
                pass

    def _scan_baseline(self):
        if not self.baseline:
            return
        for fp, expected in self.baseline.items():
            if not os.path.exists(fp):
                self.am.fire(
                    "file_integrity", "medium",
                    "Baseline file missing",
                    "File removed: {}".format(fp),
                    {"path": fp},
                )
                continue
            current = _sha256(fp)
            if current is None:
                continue
            if current != expected:
                self.am.fire(
                    "file_integrity", "critical",
                    "File integrity mismatch",
                    "Hash changed: {} (expected {}, got {})".format(
                        fp, expected[:12], current[:12]
                    ),
                    {"path": fp, "expected": expected, "actual": current},
                )


# ---------------------------------------------------------------------------
# Module 2 — CMD (Crypto Mining Detector)
# ---------------------------------------------------------------------------

class CMD(object):
    """Detects crypto-mining processes, connections, and cron injections."""

    def __init__(self, cfg, am):
        self.am = am
        self.known_miners = set(
            m.lower() for m in _csv(cfg.get("crypto_mining", "known_miners", fallback=""))
        )
        self.cpu_threshold = float(
            cfg.get("crypto_mining", "cpu_threshold_percent", fallback="80")
        )
        self.sustained_seconds = int(
            cfg.get("crypto_mining", "sustained_seconds", fallback="60")
        )
        self.mining_ports = set(
            _csv(cfg.get("crypto_mining", "mining_ports", fallback=""))
        )
        self.mining_domains = [
            d.lower() for d in _csv(cfg.get("crypto_mining", "mining_domains", fallback=""))
        ]
        self.check_cron = cfg.getboolean("crypto_mining", "check_cron", fallback=True)
        self._high_cpu_since = {}  # pid -> first_seen_ts
        self._cpu_prev = None  # (idle, total) from /proc/stat

    def scan(self):
        self._check_processes()
        self._check_system_cpu()
        self._check_connections()
        if self.check_cron:
            self._check_cron()

    # -- processes -------------------------------------------------------

    def _check_processes(self):
        stdout, _, rc = _run(["ps", "aux"])
        if rc != 0:
            return
        now = time.time()
        seen_pids = set()
        for line in stdout.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            user, pid_s, cpu_s = parts[0], parts[1], parts[2]
            command = parts[10]
            cmd_lower = command.lower()

            for miner in self.known_miners:
                if miner in cmd_lower:
                    self.am.fire(
                        "crypto_mining", "critical",
                        "Crypto miner detected: {}".format(miner),
                        "PID {}, user {}, {}% CPU".format(pid_s, user, cpu_s),
                        {"pid": pid_s, "cpu": cpu_s, "user": user, "cmd": command[:200]},
                    )
                    break

            try:
                cpu_pct = float(cpu_s)
            except ValueError:
                continue
            if cpu_pct >= self.cpu_threshold:
                seen_pids.add(pid_s)
                if pid_s not in self._high_cpu_since:
                    self._high_cpu_since[pid_s] = now
                elif now - self._high_cpu_since[pid_s] >= self.sustained_seconds:
                    self.am.fire(
                        "crypto_mining", "high",
                        "Sustained high CPU process",
                        "PID {} ({}), user {}, {}% CPU for {}s".format(
                            pid_s, command[:60], user, cpu_s,
                            int(now - self._high_cpu_since[pid_s]),
                        ),
                        {"pid": pid_s, "cpu": cpu_s, "user": user, "cmd": command[:200]},
                    )

        expired = [p for p in self._high_cpu_since if p not in seen_pids]
        for p in expired:
            del self._high_cpu_since[p]

    # -- system CPU via /proc/stat --------------------------------------

    def _check_system_cpu(self):
        try:
            with open("/proc/stat", "r") as fh:
                first = fh.readline()
        except (OSError, IOError):
            return
        parts = first.split()
        if len(parts) < 5:
            return
        try:
            vals = [int(v) for v in parts[1:]]
        except ValueError:
            return
        idle = vals[3]
        total = sum(vals)
        if self._cpu_prev is not None:
            prev_idle, prev_total = self._cpu_prev
            d_idle = idle - prev_idle
            d_total = total - prev_total
            if d_total > 0:
                usage = 100.0 * (1.0 - d_idle / float(d_total))
                if usage >= self.cpu_threshold:
                    self.am.fire(
                        "crypto_mining", "high",
                        "System CPU above threshold",
                        "Overall CPU usage: {:.1f}%".format(usage),
                        {"cpu_percent": "{:.1f}".format(usage)},
                    )
        self._cpu_prev = (idle, total)

    # -- mining connections ---------------------------------------------

    def _check_connections(self):
        stdout, _, rc = _run(["ss", "-tnp"])
        if rc != 0:
            return
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[0]
            if state != "ESTAB":
                continue
            peer = parts[4]
            host_port = peer.rsplit(":", 1)
            if len(host_port) != 2:
                continue
            port = host_port[1]
            host = host_port[0]

            if port in self.mining_ports:
                proc_info = parts[5] if len(parts) > 5 else ""
                self.am.fire(
                    "crypto_mining", "critical",
                    "Connection to mining port :{}".format(port),
                    "Peer {} — {}".format(peer, proc_info),
                    {"peer": peer, "port": port, "process": proc_info[:200]},
                )

            for domain in self.mining_domains:
                if domain in host.lower():
                    proc_info = parts[5] if len(parts) > 5 else ""
                    self.am.fire(
                        "crypto_mining", "critical",
                        "Connection to mining domain ({})".format(domain),
                        "Peer {} — {}".format(peer, proc_info),
                        {"peer": peer, "domain": domain, "process": proc_info[:200]},
                    )
                    break

    # -- cron injection -------------------------------------------------

    _CRON_SUSPICIOUS_RE = re.compile(
        r"(curl|wget|bash\s*-c|python|perl|nc\s|ncat|/dev/tcp|xmrig|miner"
        r"|\.onion|pastebin|transfer\.sh|iplogger)",
        re.IGNORECASE,
    )

    def _check_cron(self):
        cron_paths = ["/etc/crontab"]
        for d in ["/var/spool/cron", "/var/spool/cron/crontabs", "/etc/cron.d"]:
            if os.path.isdir(d):
                try:
                    for fn in os.listdir(d):
                        fp = os.path.join(d, fn)
                        if os.path.isfile(fp):
                            cron_paths.append(fp)
                except OSError:
                    pass

        for fp in cron_paths:
            content = _read_file(fp)
            if not content:
                continue
            for i, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = self._CRON_SUSPICIOUS_RE.search(line)
                if m:
                    self.am.fire(
                        "crypto_mining", "critical",
                        "Suspicious cron entry",
                        "{}:{} matched '{}': {}".format(fp, i, m.group(), line[:200]),
                        {"file": fp, "line_num": str(i), "match": m.group()},
                    )


# ---------------------------------------------------------------------------
# Module 3 — HAD (HTTP Anomaly Detector)
# ---------------------------------------------------------------------------

class HAD(object):
    """Watches HTTP access logs for anomalous patterns."""

    _LOG_RE = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+".*?"\s+(\d{3})\s+'
    )

    def __init__(self, cfg, am):
        self.am = am
        self.log_paths = _csv(cfg.get("http_anomaly", "log_paths", fallback=""))
        self.threshold_404 = int(cfg.get("http_anomaly", "threshold_404", fallback="50"))
        self.threshold_403 = int(cfg.get("http_anomaly", "threshold_403", fallback="30"))
        self.threshold_500 = int(cfg.get("http_anomaly", "threshold_500", fallback="20"))
        self.threshold_ip = int(cfg.get("http_anomaly", "threshold_same_ip", fallback="100"))
        self._log_file = None
        self._log_pos = 0
        self._log_inode = None
        self._cooldowns = {}  # key -> last_fired_ts
        self._resolve_log()

    def _resolve_log(self):
        for p in self.log_paths:
            if os.path.isfile(p):
                self._log_file = p
                try:
                    self._log_inode = os.stat(p).st_ino
                    self._log_pos = os.path.getsize(p)
                except OSError:
                    self._log_pos = 0
                log.info("HAD: tailing %s", p)
                return
        log.debug("HAD: no accessible log file found")

    def scan(self):
        if not self._log_file:
            self._resolve_log()
        if not self._log_file:
            return
        lines = self._read_new_lines()
        if not lines:
            return
        self._analyse(lines)

    def _read_new_lines(self):
        try:
            st = os.stat(self._log_file)
        except OSError:
            self._log_file = None
            return []

        if st.st_ino != self._log_inode:
            log.info("HAD: log rotated, resetting position")
            self._log_inode = st.st_ino
            self._log_pos = 0

        if st.st_size < self._log_pos:
            self._log_pos = 0

        if st.st_size == self._log_pos:
            return []

        try:
            with open(self._log_file, "r", errors="replace") as fh:
                fh.seek(self._log_pos)
                data = fh.read(4 * 1024 * 1024)  # cap at 4 MB per scan
            self._log_pos = min(self._log_pos + len(data.encode("utf-8", errors="replace")),
                                st.st_size)
        except (OSError, IOError):
            return []
        return data.splitlines()

    def _analyse(self, lines):
        cnt_404 = 0
        cnt_403 = 0
        cnt_5xx = 0
        ip_counts = collections.Counter()
        for line in lines:
            m = self._LOG_RE.match(line)
            if not m:
                continue
            ip = m.group(1)
            status = m.group(2)
            ip_counts[ip] += 1
            if status == "404":
                cnt_404 += 1
            elif status == "403":
                cnt_403 += 1
            elif status.startswith("5"):
                cnt_5xx += 1

        now = time.time()
        cooldown = 120

        if cnt_404 >= self.threshold_404 and self._can_fire("404", now, cooldown):
            self.am.fire(
                "http_anomaly", "high",
                "High 404 rate",
                "{} 404 responses in scan window".format(cnt_404),
                {"count_404": str(cnt_404)},
            )

        if cnt_403 >= self.threshold_403 and self._can_fire("403", now, cooldown):
            self.am.fire(
                "http_anomaly", "high",
                "High 403 rate",
                "{} 403 responses in scan window".format(cnt_403),
                {"count_403": str(cnt_403)},
            )

        if cnt_5xx >= self.threshold_500 and self._can_fire("5xx", now, cooldown):
            self.am.fire(
                "http_anomaly", "medium",
                "Elevated 5xx errors",
                "{} server errors in scan window".format(cnt_5xx),
                {"count_5xx": str(cnt_5xx)},
            )

        for ip, cnt in ip_counts.most_common(10):
            if cnt >= self.threshold_ip and self._can_fire("ip_" + ip, now, cooldown):
                self.am.fire(
                    "http_anomaly", "high",
                    "IP request flood",
                    "{} requests from {} in scan window".format(cnt, ip),
                    {"ip": ip, "count": str(cnt)},
                )

    def _can_fire(self, key, now, cooldown):
        last = self._cooldowns.get(key, 0)
        if now - last < cooldown:
            return False
        self._cooldowns[key] = now
        return True


# ---------------------------------------------------------------------------
# Module 4 — NAD (Network Anomaly Detector)
# ---------------------------------------------------------------------------

class NAD(object):
    """Detects suspicious network connections, new listeners, and DNS changes."""

    _RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.")

    _WELL_KNOWN_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                        "9.9.9.9", "149.112.112.112", "208.67.222.222",
                        "208.67.220.220"}

    def __init__(self, cfg, am):
        self.am = am
        self.suspicious_ports = set(
            _csv(cfg.get("network", "suspicious_ports", fallback=""))
        )
        self.check_dns = cfg.getboolean("network", "check_dns", fallback=True)
        self.alert_new_listen = cfg.getboolean(
            "network", "alert_on_new_listening_ports", fallback=True,
        )
        self._baseline_listeners = None

    def scan(self):
        self._check_established()
        if self.alert_new_listen:
            self._check_listeners()
        if self.check_dns:
            self._check_dns()

    def _check_established(self):
        stdout, _, rc = _run(["ss", "-tnp"])
        if rc != 0:
            return
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0] != "ESTAB":
                continue
            peer = parts[4]
            host_port = peer.rsplit(":", 1)
            if len(host_port) != 2:
                continue
            port = host_port[1]
            if port in self.suspicious_ports:
                proc_info = parts[5] if len(parts) > 5 else ""
                self.am.fire(
                    "network", "high",
                    "Connection to suspicious port :{}".format(port),
                    "Peer {} — {}".format(peer, proc_info),
                    {"peer": peer, "port": port, "process": proc_info[:200]},
                )

    def _check_listeners(self):
        stdout, _, rc = _run(["ss", "-tlnp"])
        if rc != 0:
            return
        current = set()
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            lp = local.rsplit(":", 1)
            if len(lp) == 2:
                current.add(lp[1])

        if self._baseline_listeners is None:
            self._baseline_listeners = current
            log.info("NAD: baseline listeners: %s", sorted(current))
            return

        new_ports = current - self._baseline_listeners
        for port in new_ports:
            self.am.fire(
                "network", "medium",
                "New listening port :{}".format(port),
                "Port {} appeared since baseline".format(port),
                {"port": port},
            )
        self._baseline_listeners = current

    def _check_dns(self):
        content = _read_file("/etc/resolv.conf")
        if not content:
            return
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("nameserver"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ns = parts[1]
            if ns in self._WELL_KNOWN_DNS:
                continue
            is_private = any(ns.startswith(p) for p in self._RFC1918_PREFIXES)
            if not is_private:
                self.am.fire(
                    "network", "medium",
                    "Non-standard DNS server",
                    "Nameserver {} is not RFC1918 or well-known public DNS".format(ns),
                    {"nameserver": ns},
                )


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class Agent(object):
    """Orchestrates modules and the scan loop."""

    def __init__(self, cfg, cfg_path):
        self.cfg = cfg
        self.shutdown = threading.Event()
        self.agent_id = get_agent_id(cfg, cfg_path)
        self.scan_interval = int(cfg.get("agent", "scan_interval", fallback="30"))
        self.am = AlertManager()
        self.pusher = Pusher(cfg, self.am, self.agent_id, self.shutdown)
        self.modules = []

        if cfg.getboolean("file_integrity", "enabled", fallback=True):
            self.modules.append(FIM(cfg, self.am))
        if cfg.getboolean("crypto_mining", "enabled", fallback=True):
            self.modules.append(CMD(cfg, self.am))
        if cfg.getboolean("http_anomaly", "enabled", fallback=True):
            self.modules.append(HAD(cfg, self.am))
        if cfg.getboolean("network", "enabled", fallback=True):
            self.modules.append(NAD(cfg, self.am))

        log.info(
            "Agent %s started (id=%s, modules=%d, scan=%ds, push=%ds)",
            AGENT_VERSION, self.agent_id, len(self.modules),
            self.scan_interval,
            int(cfg.get("agent", "push_interval", fallback="30")),
        )

    def build_baseline(self):
        for mod in self.modules:
            if isinstance(mod, FIM):
                mod.build_baseline()
                return
        log.error("FIM module not enabled — cannot build baseline")

    def run(self):
        self.pusher.start()
        while not self.shutdown.is_set():
            for mod in self.modules:
                try:
                    mod.scan()
                except Exception:
                    log.exception("Module %s scan failed", type(mod).__name__)
            self.shutdown.wait(self.scan_interval)
        log.info("Agent shutting down")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _setup_logging():
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [logging.StreamHandler(sys.stdout)]
    log_dir = "/var/log/sentinel"
    if os.path.isdir(log_dir):
        try:
            handlers.append(logging.FileHandler(
                os.path.join(log_dir, "agent.log")
            ))
        except (OSError, IOError):
            pass
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)


def main():
    _setup_logging()

    parser = argparse.ArgumentParser(description="Sentinel V3 Agent")
    parser.add_argument("--config", required=True, help="Path to agent.conf")
    parser.add_argument("--baseline", action="store_true",
                        help="Rebuild FIM baseline and exit")
    args = parser.parse_args()

    cfg = load_cfg(args.config)
    agent = Agent(cfg, args.config)

    if args.baseline:
        agent.build_baseline()
        return

    def _signal_handler(signum, _frame):
        log.info("Received signal %d, shutting down…", signum)
        agent.shutdown.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        agent.run()
    except KeyboardInterrupt:
        agent.shutdown.set()


if __name__ == "__main__":
    main()
