#!/usr/bin/env python3
"""
onedrive_enum.py - OneDrive-based user enumeration for apimspray.

Checks whether users have OneDrive provisioned by making GET requests to:
  https://[tenant]-my.sharepoint.com/personal/[user]_[domain]_com/_layouts/15/onedrive.aspx

Response interpretation:
  403 Forbidden  -> valid user (OneDrive provisioned)
  404 Not Found  -> user not found or OneDrive never accessed
  302 redirect   -> followed transparently by allow_redirects=True; final status evaluated
  other          -> unknown / error
"""

import queue
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# User agents for GET requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

_SAFE_RE = re.compile(r'[.\-]')


def build_onedrive_path(upn):
    """
    Build the OneDrive personal URL path for a given UPN.

    john.doe@contoso.com -> personal/john_doe_contoso_com/_layouts/15/onedrive.aspx
    """
    upn = upn.lower()
    username, domain = upn.split("@", 1)
    username_safe = _SAFE_RE.sub("_", username)
    domain_safe = domain.replace(".", "_")
    return f"personal/{username_safe}_{domain_safe}/_layouts/15/onedrive.aspx"


class OneDriveEnumerator:
    """
    Enumerates valid users via OneDrive URL probing.

    Uses a thread pool with one thread per proxy URL.
    Falls back to a single direct thread when no proxies are provided.
    """

    def __init__(self, proxy_urls=None):
        self.proxy_urls = list(proxy_urls) if proxy_urls else []

    def _check_user(self, upn, tenant_name=None, proxy_url=None):
        """
        Make a single OneDrive check for a UPN.

        Returns: 'valid', 'not_found', or 'error'
        """
        path = build_onedrive_path(upn)
        if proxy_url:
            url = f"{proxy_url.rstrip('/')}/{path}"
        else:
            url = f"https://{tenant_name}-my.sharepoint.com/{path}"

        headers = {"User-Agent": random.choice(USER_AGENTS)}
        try:
            resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            if resp.status_code == 403:
                return "valid"
            elif resp.status_code == 404:
                return "not_found"
            else:
                return "error"
        except requests.RequestException:
            return "error"

    def enumerate(self, users, tenant_name=None, logger=None):
        """
        Enumerate all users using the proxy pool.

        Thread model: one thread per proxy URL, each thread owns its proxy.
        Returns: (valid_users: set, counters: dict)
        """
        user_queue = queue.Queue()
        for u in users:
            user_queue.put(u)

        proxy_pool = self.proxy_urls if self.proxy_urls else [None]
        n_threads = len(proxy_pool)

        valid_users = set()
        results_lock = threading.Lock()
        counters = {"completed": 0, "valid": 0, "not_found": 0, "errors": 0}

        total = len(users)
        start_time = time.time()
        stop_progress = threading.Event()

        def progress_printer():
            while not stop_progress.wait(10):
                with results_lock:
                    done = counters["completed"]
                    found = counters["valid"]
                elapsed = int(time.time() - start_time)
                rate = done / elapsed if elapsed > 0 else 0
                remaining = total - done
                eta = int(remaining / rate) if rate > 0 else 0
                eta_str = f"{eta//60}m{eta%60:02d}s" if eta > 0 else "?"
                print(f"[*] Progress: {done}/{total} | Found: {found} | "
                      f"{rate:.1f} req/s | ETA: {eta_str}")

        progress_thread = threading.Thread(target=progress_printer, daemon=True)
        progress_thread.start()

        def worker(proxy_url):
            while True:
                try:
                    upn = user_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    result = self._check_user(upn, tenant_name, proxy_url)
                    with results_lock:
                        counters["completed"] += 1
                        if result == "valid":
                            counters["valid"] += 1
                            valid_users.add(upn)
                            print(f"[+] VALID: {upn}")
                            if logger:
                                logger.log_result("enumerated", upn)
                        elif result == "not_found":
                            counters["not_found"] += 1
                        else:
                            counters["errors"] += 1
                finally:
                    user_queue.task_done()

        with ThreadPoolExecutor(max_workers=n_threads) as executor:
            futures = [executor.submit(worker, proxy_pool[i % len(proxy_pool)])
                       for i in range(n_threads)]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        stop_progress.set()
        return valid_users, counters
