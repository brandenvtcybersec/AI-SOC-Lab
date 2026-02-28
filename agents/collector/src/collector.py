import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Local Splunk uses a self-signed cert by default; suppress warnings in lab.
urllib3.disable_warnings(category=InsecureRequestWarning)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ts_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def load_env():
    host = os.getenv("SPLUNK_HOST", "localhost").strip()
    port = os.getenv("SPLUNK_PORT", "8089").strip()
    username = os.getenv("SPLUNK_USERNAME", "").strip()
    password = os.getenv("SPLUNK_PASSWORD", "").strip()

    scheme = os.getenv("SPLUNK_SCHEME", "https").strip().lower()
    verify = os.getenv("SPLUNK_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")

    if not username or not password:
        raise SystemExit(
            "Missing SPLUNK_USERNAME or SPLUNK_PASSWORD environment variables.\n"
            "Set them then retry."
        )

    return f"{scheme}://{host}:{port}", username, password, verify


def build_detections():
    window_earliest = os.getenv("DETECTION_EARLIEST", "-30m")
    window_latest = os.getenv("DETECTION_LATEST", "now")

    return [
        {
            "detection": "smoke_test",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": '| makeresults | eval status="ok", note="collector connected" | table status note',
        },

        # ✅ FIXED: strict PowerShell encoded command detection (prevents git.exe false positives)
        {
            "detection": "sysmon_encoded_powershell",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* sourcetype=WinEventLog EventCode=1 Image="*\\powershell.exe"
| search (CommandLine="*-EncodedCommand *" OR CommandLine="*-enc *")
| table _time host User Image ParentImage CommandLine
| sort - _time
| head 50''',
        },

        {
            "detection": "sysmon_scripting_network",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* sourcetype=WinEventLog EventCode=3 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe")
| table _time host User Image DestinationIp DestinationPort DestinationHostname Protocol
| sort - _time
| head 50''',
        },

        {
            "detection": "sysmon_office_to_powershell",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* sourcetype=WinEventLog EventCode=1 Image="*\\powershell.exe"
| search (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.EXE" OR ParentImage="*\\OUTLOOK.EXE")
| table _time host User Image ParentImage CommandLine
| sort - _time
| head 50''',
        },

        {
            "detection": "sysmon_lolbins_suspicious",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* sourcetype=WinEventLog EventCode=1
| search (Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| table _time host User Image ParentImage CommandLine
| sort - _time
| head 50''',
        },

        {
            "detection": "bruteforce_then_success",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* (EventCode=4625 OR EventCode=4624)
| eval outcome=if(EventCode=4624,"success","fail")
| stats count(eval(outcome="fail")) as fails count(eval(outcome="success")) as successes values(host) as hosts values(user) as users by src
| where fails >= 10 AND successes >= 1
| sort - fails''',
        },

        {
            "detection": "new_service_created",
            "earliest": window_earliest,
            "latest": window_latest,
            "spl": r'''index=* (EventCode=7045 OR EventCode=4697)
| table _time host user ServiceName ImagePath
| sort - _time
| head 50''',
        },
    ]


def create_search_job(session: requests.Session, base_url: str, spl: str, earliest: str, latest: str) -> str:
    """
    Create an async search job. Returns SID.
    """
    url = f"{base_url}/services/search/jobs"
    payload = {
        "search": f"search {spl}",
        "earliest_time": earliest,
        "latest_time": latest,
        "exec_mode": "normal",
    }
    r = session.post(url, data=payload, timeout=(10, 60))
    r.raise_for_status()

    # Splunk returns XML by default unless output_mode is set
    # We'll parse SID from XML response safely.
    text = r.text
    m = None
    import re
    m = re.search(r"<sid>([^<]+)</sid>", text)
    if not m:
        raise RuntimeError("Could not parse search SID from Splunk response.")
    return m.group(1)


def wait_for_job_done(session: requests.Session, base_url: str, sid: str, timeout_seconds: int = 45) -> dict:
    """
    Poll job status until done or timeout. Returns parsed JSON status payload.
    """
    url = f"{base_url}/services/search/jobs/{sid}"
    start = time.time()

    while True:
        r = session.get(url, params={"output_mode": "json"}, timeout=(10, 30))
        r.raise_for_status()
        info = r.json()

        # Navigate job entry safely
        entry = (info.get("entry") or [{}])[0]
        content = entry.get("content") or {}
        done = bool(content.get("isDone", False))
        dispatch_state = content.get("dispatchState", "")

        if done or dispatch_state.lower() == "done":
            return info

        if time.time() - start > timeout_seconds:
            return info

        time.sleep(0.5)


def fetch_job_results(session: requests.Session, base_url: str, sid: str, count: int = 50) -> list[dict]:
    url = f"{base_url}/services/search/jobs/{sid}/results"
    r = session.get(url, params={"output_mode": "json", "count": str(count)}, timeout=(10, 60))
    r.raise_for_status()
    data = r.json()
    return data.get("results", []) or []


def cancel_job(session: requests.Session, base_url: str, sid: str):
    """
    Best-effort cleanup.
    """
    try:
        url = f"{base_url}/services/search/jobs/{sid}"
        session.delete(url, timeout=(10, 30))
    except Exception:
        pass


def run_detection(session: requests.Session, base_url: str, spl: str, earliest: str, latest: str, count: int = 50) -> list[dict]:
    sid = create_search_job(session, base_url, spl, earliest, latest)
    wait_for_job_done(session, base_url, sid, timeout_seconds=45)
    results = fetch_job_results(session, base_url, sid, count=count)
    cancel_job(session, base_url, sid)
    return results


def main():
    try:
        base_url, username, password, verify_ssl = load_env()
    except SystemExit as e:
        print(e)
        sys.exit(1)

    repo_root = Path(__file__).resolve().parents[3]
    cases_dir = repo_root / "agents" / "collector" / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    detections = build_detections()

    cases_out = {"generated_at_utc": utc_now_iso(), "cases": []}

    with requests.Session() as s:
        s.verify = verify_ssl
        s.auth = HTTPBasicAuth(username, password)
        s.headers.update({"Accept": "application/json"})

        for d in detections:
            name = d["detection"]
            earliest = d["earliest"]
            latest = d["latest"]
            spl = d["spl"]

            try:
                results = run_detection(s, base_url, spl, earliest, latest, count=50)
                case = {
                    "detection": name,
                    "timestamp_utc": utc_now_iso(),
                    "time_window": {"earliest": earliest, "latest": latest},
                    "spl": spl,
                    "event_count": len(results),
                    "events": results,
                }
            except Exception as e:
                case = {
                    "detection": name,
                    "timestamp_utc": utc_now_iso(),
                    "time_window": {"earliest": earliest, "latest": latest},
                    "spl": spl,
                    "event_count": 0,
                    "events": [],
                    "error": str(e),
                }

            cases_out["cases"].append(case)

    out_path = cases_dir / f"cases_{ts_for_filename()}.json"
    out_path.write_text(json.dumps(cases_out, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out_path} with {len(cases_out['cases'])} detection bundles.")
    print("Expected: smoke_test should be 1. Sysmon detections will populate as you generate activity.")


if __name__ == "__main__":
    main()