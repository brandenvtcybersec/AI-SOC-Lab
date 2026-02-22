import argparse
import json
import os
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
import re


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def newest_file(path: Path, pattern: str) -> Path | None:
    files = sorted(path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def run_cmd(cmd: list[str], dry_run: bool) -> dict:
    if dry_run:
        return {"cmd": cmd, "ran": False, "returncode": None, "stdout": "", "stderr": ""}

    p = subprocess.run(cmd, capture_output=True, text=True, shell=False)
    return {
        "cmd": cmd,
        "ran": True,
        "returncode": p.returncode,
        "stdout": p.stdout.strip(),
        "stderr": p.stderr.strip(),
    }


def powershell(ps: str, dry_run: bool) -> dict:
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
    return run_cmd(cmd, dry_run)


def get_local_hostname() -> str:
    return os.environ.get("COMPUTERNAME", "").strip() or "UNKNOWN_HOST"


def get_userdnsdomain() -> str:
    # If joined to AD, this is often set.
    return os.environ.get("USERDNSDOMAIN", "").strip()


def normalize_user(u: str) -> str:
    u = (u or "").strip()
    return u


def split_identity(identity: str) -> dict:
    """
    Returns:
      {
        "raw": original,
        "domain": "DOMAIN" or "",
        "user": "sam",
        "is_qualified": bool (DOMAIN\\user or user@domain),
      }
    """
    identity = (identity or "").strip()
    out = {"raw": identity, "domain": "", "user": identity, "is_qualified": False}

    if not identity:
        out["user"] = ""
        return out

    if "\\" in identity:
        dom, usr = identity.split("\\", 1)
        out.update({"domain": dom, "user": usr, "is_qualified": True})
        return out

    if "@" in identity:
        usr, dom = identity.split("@", 1)
        out.update({"domain": dom, "user": usr, "is_qualified": True})
        return out

    return out


def infer_account_type(identity: str, local_host: str) -> str:
    """
    Heuristic:
      - If DOMAIN\\user and DOMAIN != local_host => domain
      - If user@domain => domain
      - Else => local
    """
    p = split_identity(identity)
    if p["is_qualified"]:
        # DOMAIN\user case
        if "\\" in p["raw"]:
            if p["domain"].upper() != local_host.upper():
                return "domain"
            return "local"
        # user@domain
        return "domain"
    return "local"


def extract_users_from_case(case: dict) -> list[str]:
    """
    Best-effort: pull usernames from evidence fields.
    """
    users = []
    for e in case.get("sample_events", []) or []:
        for key in ("users", "user", "User"):
            val = e.get(key)
            if isinstance(val, list):
                for x in val:
                    sx = str(x).strip()
                    if sx and sx.upper() != "NOT_TRANSLATED":
                        users.append(sx)
            elif isinstance(val, str):
                sx = val.strip()
                if sx and sx.upper() != "NOT_TRANSLATED":
                    users.append(sx)

    # de-dupe
    seen = set()
    out = []
    for u in users:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def require_admin_note() -> str:
    return (
        "NOTE: Execute mode requires an elevated (Run as Administrator) terminal "
        "for firewall rules and account changes."
    )


def action_kill_suspicious_powershell(dry_run: bool) -> dict:
    ps = r"""
$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match '^(powershell|pwsh)\.exe$' -and
    ($_.CommandLine -match 'EncodedCommand' -or $_.CommandLine -match '\s-enc(\s|$)')
}
$killed = @()
foreach ($p in $procs) {
    try {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
        $killed += [pscustomobject]@{ pid=$p.ProcessId; name=$p.Name; cmd=$p.CommandLine }
    } catch {
        $killed += [pscustomobject]@{ pid=$p.ProcessId; name=$p.Name; cmd=$p.CommandLine; error=$_.Exception.Message }
    }
}
$killed | ConvertTo-Json -Depth 4
"""
    return {"action": "kill_suspicious_powershell", "result": powershell(ps, dry_run)}


def action_block_powershell_outbound(minutes: int, dry_run: bool) -> dict:
    rule_name = f"AI-SOC-Lab Block PowerShell Outbound (temp) {datetime.now().strftime('%Y%m%d_%H%M%S')}"
    program = r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

    add_rule_ps = rf"""
New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -Program "{program}" -Action Block -Profile Any | Out-Null
"OK"
"""
    add_res = powershell(add_rule_ps, dry_run)

    run_at = (datetime.now() + timedelta(minutes=minutes)).strftime("%H:%M")
    task_name = f"AI-SOC-Lab-RemoveFW-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    remove_cmd = rf'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetFirewallRule -DisplayName ''{rule_name}'' | Remove-NetFirewallRule -ErrorAction SilentlyContinue"'

    schtasks_cmd = [
        "schtasks",
        "/Create",
        "/TN", task_name,
        "/TR", remove_cmd,
        "/SC", "ONCE",
        "/ST", run_at,
        "/F"
    ]
    sched_res = run_cmd(schtasks_cmd, dry_run)

    return {
        "action": "temp_block_powershell_outbound",
        "rule_name": rule_name,
        "duration_minutes": minutes,
        "scheduled_task": task_name,
        "add_rule": add_res,
        "schedule_removal": sched_res,
    }


def action_disable_local_user(username: str, dry_run: bool) -> dict:
    username = (username or "").strip()
    if not username:
        return {"action": "disable_local_user", "error": "No username provided."}

    ps = rf"""
try {{
    $u = Get-LocalUser -Name "{username}" -ErrorAction Stop
    Disable-LocalUser -Name "{username}" -ErrorAction Stop
    "OK: Disabled local user {username}"
}} catch {{
    "ERROR: " + $_.Exception.Message
}}
"""
    return {"action": "disable_local_user", "user": username, "result": powershell(ps, dry_run)}


def action_disable_domain_user(identity: str, domain_hint: str, dry_run: bool) -> dict:
    """
    Disables a domain account using the ActiveDirectory module.
    identity can be:
      - DOMAIN\\user
      - user@domain
      - user (if domain_hint provided)
    """
    p = split_identity(identity)
    user = p["user"]
    dom = p["domain"] or (domain_hint or "")
    dom = dom.strip()

    # We use samAccountName (user) most of the time.
    # If user@domain was provided, user is already extracted.
    # If DOMAIN\\user was provided, user is extracted.
    # If only "user", dom comes from hint (optional).

    ps = rf"""
$targetUser = "{user}"
$domainHint = "{dom}"

try {{
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null

    # Resolve user object. Prefer -Identity samAccountName, fallback to UPN if needed.
    $u = $null
    try {{
        $u = Get-ADUser -Identity $targetUser -ErrorAction Stop
    }} catch {{
        if ($domainHint -and $targetUser -and ($targetUser -notmatch '@')) {{
            $upn = "$($targetUser)@$($domainHint)"
            $u = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -ErrorAction Stop
        }} else {{
            throw
        }}
    }}

    Disable-ADAccount -Identity $u.DistinguishedName -ErrorAction Stop
    "OK: Disabled domain user " + $u.SamAccountName
}} catch {{
    "ERROR: " + $_.Exception.Message
}}
"""
    return {
        "action": "disable_domain_user",
        "identity": identity,
        "domain_hint": dom,
        "result": powershell(ps, dry_run),
        "note": "Requires RSAT/ActiveDirectory module (Import-Module ActiveDirectory)."
    }


def main():
    ap = argparse.ArgumentParser(description="AI-SOC-Lab remediation agent (recommend/execute).")
    ap.add_argument("--mode", choices=["recommend", "execute"], default="recommend")
    ap.add_argument("--triage", default="", help="Path to triage_*.json. If empty, uses newest in agents/triage/output.")
    ap.add_argument("--allow-host", action="append", default=[], help="Allow remediation only on these hosts. If not set, uses local host only.")
    ap.add_argument("--fw-minutes", type=int, default=30, help="Firewall block duration for powershell.exe outbound (minutes).")
    ap.add_argument("--user", default="", help="Username/identity to disable (local user, DOMAIN\\user, or user@domain).")
    ap.add_argument("--account-type", choices=["auto", "local", "domain"], default="auto",
                    help="Account scope for disable action. auto tries to infer from identity.")
    ap.add_argument("--domain", default="", help="Domain hint (e.g., contoso.local) used when identity is unqualified (e.g., 'jdoe').")
    args = ap.parse_args()

    dry_run = (args.mode == "recommend")
    local_host = get_local_hostname()
    userdnsdomain = get_userdnsdomain()

    repo_root = Path(__file__).resolve().parents[3]
    triage_out = repo_root / "agents" / "triage" / "output"
    logs_dir = repo_root / "agents" / "remediate" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    triage_path = Path(args.triage) if args.triage else newest_file(triage_out, "triage_*.json")
    if not triage_path or not triage_path.exists():
        raise SystemExit("No triage_*.json found. Run triage_report.py first (it generates triage JSON).")

    triage = json.loads(triage_path.read_text(encoding="utf-8"))
    chains = triage.get("correlated_chains", []) or []
    cases = triage.get("triage_cases", []) or []

    allow = set(args.allow_host) if args.allow_host else {local_host}

    actions = []
    notes = [require_admin_note()]

    # 1) Containment: Encoded PowerShell + scripting network correlation
    for ch in chains:
        host = ch.get("host", "(unknown-host)")
        involved = ch.get("involved", [])
        if host not in allow:
            continue
        if host != local_host:
            continue  # do not remediate remote hosts in this lab agent

        if "sysmon_encoded_powershell" in involved and "sysmon_scripting_network" in involved:
            actions.append({
                "when": "CRITICAL correlation detected (encoded PowerShell + outbound scripting traffic)",
                "host": host,
                "what": "Kill suspicious encoded PowerShell processes; temporarily block powershell.exe outbound traffic",
            })
            actions.append(action_kill_suspicious_powershell(dry_run))
            actions.append(action_block_powershell_outbound(args.fw_minutes, dry_run))

    # 2) Account response: brute force then success
    bf_case = next((c for c in cases if c.get("detection") == "bruteforce_then_success"), None)
    if bf_case and (bf_case.get("severity") == "critical" or bf_case.get("score", 0) >= 90):
        if local_host in allow:
            identity = args.user.strip()
            inferred = []

            if not identity:
                inferred = extract_users_from_case(bf_case)
                if inferred:
                    identity = inferred[0]

            # Determine account type
            if args.account_type == "auto":
                acct_type = infer_account_type(identity, local_host) if identity else "local"
            else:
                acct_type = args.account_type

            domain_hint = (args.domain or userdnsdomain or "").strip()

            actions.append({
                "when": "CRITICAL brute force then success detected",
                "host": local_host,
                "what": "Disable suspected compromised account (local or domain depending on identity/type)",
                "identity_selected": identity or "(none)",
                "account_type": acct_type,
                "domain_hint": domain_hint or "(none)",
                "users_inferred": inferred,
            })

            if not identity:
                notes.append("No identity provided/inferred for bruteforce_then_success. Re-run with --user <name>.")
            else:
                if acct_type == "local":
                    # If identity is DOMAIN\user, strip domain when doing local disable
                    user_only = split_identity(identity)["user"]
                    actions.append(action_disable_local_user(user_only, dry_run))
                else:
                    actions.append(action_disable_domain_user(identity, domain_hint, dry_run))
                    notes.append("Domain disable requires RSAT/ActiveDirectory module. If missing, install RSAT or run on a system with AD tools.")

    out = {
        "generated_at_utc": utc_now_iso(),
        "mode": args.mode,
        "triage_source": str(triage_path),
        "local_host": local_host,
        "userdnsdomain": userdnsdomain,
        "allow_hosts": sorted(list(allow)),
        "notes": notes,
        "actions": actions,
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"remediation_{ts}.json"
    log_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"[OK] Remediation agent completed in mode={args.mode}.")
    print(f"[OK] Wrote log: {log_path}")

    if dry_run:
        print("\n--- RECOMMEND MODE (no changes applied) ---")
        print("Re-run with: --mode execute (Admin) to apply actions.")


if __name__ == "__main__":
    main()