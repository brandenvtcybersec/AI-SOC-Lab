import os
import json
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_filename(prefix: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.json"


def splunk_login_session_key(base_url: str, username: str, password: str) -> str:
    url = base_url.rstrip("/") + "/services/auth/login"
    data = {"username": username, "password": password, "output_mode": "json"}
    resp = requests.post(url, data=data, timeout=30, verify=False)
    resp.raise_for_status()
    payload = resp.json()
    if "sessionKey" not in payload:
        raise RuntimeError(f"Login succeeded but no sessionKey returned. Keys: {list(payload.keys())}")
    return payload["sessionKey"]


def splunk_search_oneshot(
    base_url: str,
    session_key: str,
    spl: str,
    earliest: str = "-15m",
    latest: str = "now",
    count: int = 50,
):
    url = base_url.rstrip("/") + "/services/search/jobs/oneshot"
    headers = {"Authorization": f"Splunk {session_key}"}
    data = {
        "search": spl.strip(),
        "output_mode": "json",
        "earliest_time": earliest,
        "latest_time": latest,
        "count": str(count),
    }
    resp = requests.post(url, headers=headers, data=data, timeout=90, verify=False)
    resp.raise_for_status()
    payload = resp.json()
    results = payload.get("results")
    if results is None:
        raise RuntimeError(f"Oneshot JSON had no 'results' key. Keys: {list(payload.keys())}")
    if not isinstance(results, list):
        raise RuntimeError(f"'results' was not a list (type={type(results)}).")
    return results


def main():
    load_dotenv()

    base_url = os.getenv("SPLUNK_BASE_URL", "").strip()
    username = os.getenv("SPLUNK_USERNAME", "").strip()
    password = os.getenv("SPLUNK_PASSWORD", "").strip()
    cases_dir = os.getenv("CASES_DIR", "agents/collector/cases").strip()

    if not base_url or not username or not password:
        raise SystemExit(
            "Missing env vars. Create agents/collector/.env with:\n"
            "SPLUNK_BASE_URL=https://localhost:8089\n"
            "SPLUNK_USERNAME=admin\n"
            "SPLUNK_PASSWORD=your_password\n"
            "CASES_DIR=agents/collector/cases\n"
        )

    # --- Sysmon + Windows detections (MVP, portfolio-friendly) ---
    # Notes:
    # - Sysmon Process Create = EventCode=1 (Sysmon Operational)
    # - Sysmon Network Connect = EventCode=3
    # - Windows Service Create often appears as EventCode=7045 (System log)
    # Adjust index=main if you used a different index.
    detections = {
        "smoke_test": r'| makeresults count=1 | eval status="ok", note="collector connected" | table status note',

        # Windows: new service created
        "new_service_created": r"""
            search index=main (EventCode=7045 OR EventCode=4697)
            | head 50
        """,

        # Windows: brute force then success (works once you have 4624/4625 in Security)
        "bruteforce_then_success": r"""
            search index=main (EventCode=4625 OR EventCode=4624)
            | eval outcome=if(EventCode=4624,"success","fail")
            | stats count(eval(outcome="fail")) as fails
                    count(eval(outcome="success")) as successes
                    values(host) as hosts
                    values(user) as users
              by src
            | where fails >= 10 AND successes >= 1
            | sort - fails
        """,

        # Sysmon: Encoded / obfuscated PowerShell
        "sysmon_encoded_powershell": r"""
            search index=main EventCode=1
            | eval cl=coalesce(CommandLine, process, cmdline)
            | search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR cl="*powershell*")
            | search (cl="* -enc *" OR cl="* -encodedcommand *" OR cl="*EncodedCommand*")
            | table _time host User Image ParentImage CommandLine
            | head 50
        """,

        # Sysmon: LOLBins often used for download/exec (certutil/bitsadmin/mshta/rundll32/regsvr32)
        "sysmon_lolbins_suspicious": r"""
            search index=main EventCode=1
            | eval img=lower(coalesce(Image,""))
            | eval cl=lower(coalesce(CommandLine,""))
            | where like(img,"%\\certutil.exe") OR like(img,"%\\bitsadmin.exe") OR like(img,"%\\mshta.exe")
                   OR like(img,"%\\rundll32.exe") OR like(img,"%\\regsvr32.exe")
            | where like(cl,"%http%") OR like(cl,"%https%") OR like(cl,"%url%") OR like(cl,"%download%")
                   OR like(cl,"%powershell%") OR like(cl,"%base64%")
            | table _time host User Image ParentImage CommandLine
            | head 50
        """,

        # Sysmon: Office -> PowerShell (classic phish to execution chain)
        "sysmon_office_to_powershell": r"""
            search index=main EventCode=1
            | eval p=lower(coalesce(ParentImage,""))
            | eval i=lower(coalesce(Image,""))
            | where (like(p,"%\\winword.exe") OR like(p,"%\\excel.exe") OR like(p,"%\\powerpnt.exe") OR like(p,"%\\outlook.exe"))
              AND (like(i,"%\\powershell.exe") OR like(i,"%\\pwsh.exe") OR like(i,"%\\cmd.exe") OR like(i,"%\\wscript.exe") OR like(i,"%\\cscript.exe"))
            | table _time host User ParentImage Image CommandLine
            | head 50
        """,

        # Sysmon: Network connections from PowerShell/cmd (useful once EventCode=3 is flowing)
        "sysmon_scripting_network": r"""
            search index=main EventCode=3
            | eval img=lower(coalesce(Image,""))
            | where like(img,"%\\powershell.exe") OR like(img,"%\\pwsh.exe") OR like(img,"%\\cmd.exe") OR like(img,"%\\wscript.exe") OR like(img,"%\\cscript.exe")
            | table _time host User Image DestinationIp DestinationPort DestinationHostname Protocol
            | head 50
        """,
    }

    session_key = splunk_login_session_key(base_url, username, password)

    all_cases = []
    for name, spl in detections.items():
        try:
            hits = splunk_search_oneshot(base_url, session_key, spl, earliest="-30m", latest="now", count=50)
            all_cases.append(
                {
                    "detection": name,
                    "timestamp_utc": utc_now_iso(),
                    "time_window": {"earliest": "-30m", "latest": "now"},
                    "spl": spl.strip(),
                    "event_count": len(hits),
                    "events": hits,
                }
            )
        except Exception as e:
            all_cases.append(
                {
                    "detection": name,
                    "timestamp_utc": utc_now_iso(),
                    "spl": spl.strip(),
                    "error": str(e),
                    "events": [],
                }
            )

    Path(cases_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(cases_dir) / safe_filename("cases")
    out_path.write_text(json.dumps({"generated_at_utc": utc_now_iso(), "cases": all_cases}, indent=2), encoding="utf-8")

    print(f"[OK] Wrote {out_path} with {len(all_cases)} detection bundles.")
    print("Expected: smoke_test should be 1. Sysmon detections will populate as you generate activity.")


if __name__ == "__main__":
    main()