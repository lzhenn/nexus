#!/usr/bin/env python3
"""
Nexus OA Sync: polls for new messages in projects with work_dir set,
downloads attachments via the Nexus API, and saves msg.md + files
to the local work directory.

Usage:
    python3 sync_oa.py              # single run
    python3 sync_oa.py --loop 3600  # poll every 3600 seconds (1 hour)
"""

import os
import sys
import json
import time
import urllib.request
import ssl
import base64
from datetime import datetime

# --- Config ---
NEXUS_BASE = "https://upwave-research.com/nexus/api"
NEXUS_TOKEN = os.environ.get("NEXUS_TOKEN", "")
HTACCESS_USER = os.environ.get("HTACCESS_USER", "upwave")
HTACCESS_PASS = os.environ.get("HTACCESS_PASS", "")
LOCAL_BASE = "/Users/zhenningli/work/ust-jumper"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _make_request(url, data=None, method=None):
    """Send request with Basic Auth (Apache) + X-Auth-Token (Nexus)."""
    req = urllib.request.Request(url, data=data)
    if method:
        req.method = method
    # Basic Auth for Apache (preemptive, no challenge needed)
    basic = base64.b64encode(f"{HTACCESS_USER}:{HTACCESS_PASS}".encode()).decode()
    req.add_header("Authorization", "Basic " + basic)
    # Bearer token via custom header (backend checks both Authorization and X-Auth-Token)
    req.add_header("X-Auth-Token", NEXUS_TOKEN)
    if data:
        req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL_CTX))
    return opener.open(req)


def api_get(path):
    resp = _make_request(NEXUS_BASE + path)
    return json.loads(resp.read().decode())


def api_post(path, data):
    resp = _make_request(NEXUS_BASE + path, data=json.dumps(data).encode(), method="POST")
    return json.loads(resp.read().decode())


def download_file(file_id, local_path):
    """Download a file via Nexus API."""
    resp = _make_request(NEXUS_BASE + f"/files/{file_id}/download")
    with open(local_path, 'wb') as f:
        f.write(resp.read())


def sync_once():
    try:
        pending = api_get("/sync/pending")
    except Exception as e:
        print(f"[sync] Failed to fetch pending: {e}")
        return

    if not pending:
        print("[sync] No pending messages")
        return

    print(f"[sync] {len(pending)} pending message(s)")
    synced_ids = []

    for msg in pending:
        work_dir = msg.get("work_dir", "")
        if not work_dir:
            continue

        ts = msg.get("created_at", "")
        try:
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = datetime.now()
        oa_dir_name = dt.strftime("%Y%m%d%H%M")
        local_dir = os.path.join(LOCAL_BASE, work_dir, "OA", oa_dir_name)
        os.makedirs(local_dir, exist_ok=True)

        md_content = f"""---
author: {msg.get('author', 'unknown')}
time: {ts}
project: {msg.get('project_name', '')}
message_id: {msg.get('id', '')}
---

{msg.get('content', '')}
"""
        with open(os.path.join(local_dir, "msg.md"), "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"  [{work_dir}/OA/{oa_dir_name}] msg.md written")

        all_ok = True
        for att in msg.get("attachments", []):
            file_id = att.get("id")
            filename = att.get("filename", "")
            local_path = os.path.join(local_dir, filename)
            try:
                download_file(file_id, local_path)
                print(f"  [{work_dir}/OA/{oa_dir_name}] {filename} downloaded")
            except Exception as e:
                print(f"  [{work_dir}/OA/{oa_dir_name}] {filename} FAILED: {e}")
                all_ok = False

        if all_ok:
            synced_ids.append(msg["id"])

    if synced_ids:
        try:
            api_post("/sync/ack", {"ids": synced_ids})
            print(f"[sync] Acknowledged {len(synced_ids)} message(s)")
        except Exception as e:
            print(f"[sync] Failed to ack: {e}")


def main():
    if not NEXUS_TOKEN:
        print("Error: NEXUS_TOKEN not set.")
        sys.exit(1)
    if not HTACCESS_PASS:
        print("Error: HTACCESS_PASS not set.")
        sys.exit(1)

    if "--loop" in sys.argv:
        idx = sys.argv.index("--loop")
        interval = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 3600
        print(f"[sync] Polling every {interval}s. Ctrl+C to stop.")
        while True:
            sync_once()
            time.sleep(interval)
    else:
        sync_once()


if __name__ == "__main__":
    main()
