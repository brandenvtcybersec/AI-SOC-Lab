import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict
import re


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_filename(prefix: str, ext: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


MITRE_BY_DETECTION = {
    "sysmon_encoded_powershell": ["T1059.001", "T1027"],
    "sysmon_scripting_network": ["T1071", "T1105"],
    "sysmon_lolbins_suspicious": ["T1218", "T1105"],
    "sysmon_office_to_powershell": ["T1566", "T1204"],
    "new_service_created": ["T1543.003"],
    "bruteforce_then_success": ["T1110"],
    "smoke_test": [],
}

WEIGHTS = {
    "sysmon_encoded_powershell": 50,
    "sysmon_scripting_network": 40,
    "sysmon_lolbins_suspicious": 40,
    "sysmon_office_to_powershell": 40,
    "new_service_created": 35,
    "bruteforce_then_success": 60,
    "smoke_test": 0,
}

# SOC-ish correlation window (minutes)
CORRELATION_WINDOW_MINUTES = 10


def score_to_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def parse_splunk_time(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, list):
        for v in value:
            dt = parse_splunk_time(v)
            if dt:
                return dt
        return None

    s = str(value).strip()
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2}|Z)?$", s)
        if not m:
            return None
        base, frac, tz = m.group(1), m.group(2) or "", m.group(3) or "+00:00"
        if tz == "Z":
            tz = "+00:00"
        try:
            dt = datetime.fromisoformat(base + frac + tz)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None


def extract_hosts(events: list[dict]) -> set[str]:
    hosts = set()
    for e in events:
        h = e.get("host") or e.get("ComputerName")
        if isinstance(h, list):
            for x in h:
                if x:
                    hosts.add(str(x))
        elif h:
            hosts.add(str(h))
    return hosts


def extract_event_times(events: list[dict]) -> list[datetime]:
    times = []
    for e in events:
        dt = parse_splunk_time(e.get("_time"))
        if dt:
            times.append(dt)
    return times


def min_time(times: list[datetime]) -> datetime | None:
    return min(times) if times else None


def within_window(a: datetime | None, b: datetime | None, minutes: int) -> bool:
    if not a or not b:
        return False
    return abs(a - b) <= timedelta(minutes=minutes)


def pick_best_str(value, default="-"):
    if value is None:
        return default
    if isinstance(value, list):
        for v in value:
            if v:
                return str(v)
        return default
    s = str(value).strip()
    return s if s else default


def build_executive_summary(chains: list[dict], evidence_by_host: dict, window_min: int) -> list[str]:
    """
    Builds a SOC-style narrative section when correlation is present.
    Pulls key evidence (encoded command, destination IP/port) if available.
    """
    lines = []
    lines.append("## SOC Escalation Note")
    lines.append("")
    lines.append("**Severity:** CRITICAL (correlated multi-signal behavior)")
    lines.append("")

    # Keep it readable; summarize up to 3 hosts
    for ch in chains[:3]:
        host = ch["host"]
        chain_desc = ch["chain"]
        ev = evidence_by_host.get(host, {})

        enc_cmd = ev.get("encoded_commandline", "-")
        parent = ev.get("encoded_parent", "-")
        img = ev.get("encoded_image", "-")

        dip = ev.get("dest_ip", "-")
        dport = ev.get("dest_port", "-")
        proto = ev.get("dest_proto", "-")

        lines.append(f"### Host: `{host}`")
        lines.append(f"- **Observed chain:** {chain_desc} (within {window_min} minutes)")
        lines.append("- **What this suggests:** Obfuscated scripting followed by outbound traffic is consistent with staging, download, or command-and-control behavior pending validation.")
        lines.append("- **Key evidence:**")
        lines.append(f"  - Encoded PowerShell: `{img}` (parent `{parent}`)")
        if enc_cmd != "-":
            # Avoid dumping super long commands
            preview = enc_cmd if len(enc_cmd) <= 220 else enc_cmd[:220] + "…"
            lines.append(f"  - CommandLine: `{preview}`")
        lines.append(f"  - Outbound connection: `{proto}` to `{dip}:{dport}`")
        lines.append("")

    lines.append("**Immediate actions (recommended):**")
    lines.append("1. Decode and review any `-EncodedCommand` payload; determine intent (benign admin vs malicious).")
    lines.append("2. Pivot on process tree (parent → child) and search for follow-on activity (file writes, persistence, additional network connections).")
    lines.append("3. Investigate destination IP/hostname reputation and correlate with other telemetry in the same window.")
    lines.append("4. If unexpected, isolate the host and preserve triage artifacts (process list, autoruns, relevant event logs).")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def main():
    repo_root = Path(__file__).resolve().parents[3]
    cases_dir = repo_root / "agents" / "collector" / "cases"
    out_dir = repo_root / "agents" / "triage" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(cases_dir.glob("cases_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise SystemExit("No cases_*.json found. Run the collector first.")
    cases_path = files[0]

    data = json.loads(cases_path.read_text(encoding="utf-8"))

    triage_cases = []
    by_host = defaultdict(dict)          # host -> det -> {count, first_seen}
    evidence_by_host = defaultdict(dict) # host -> key evidence for narrative

    for case in data.get("cases", []):
        det = case.get("detection", "unknown")
        count = int(case.get("event_count", 0) or 0)
        events = case.get("events", []) or []

        hosts = extract_hosts(events[:10])
        times = extract_event_times(events[:10])
        first_seen = min_time(times)

        base_score = 0 if count == 0 else WEIGHTS.get(det, 10)
        severity = "info" if det == "smoke_test" else score_to_severity(base_score)

        triage_cases.append({
            "detection": det,
            "event_count": count,
            "hosts": sorted(list(hosts)) if hosts else [],
            "first_seen_utc": first_seen.isoformat().replace("+00:00", "Z") if first_seen else None,
            "mitre": MITRE_BY_DETECTION.get(det, []),
            "score": base_score,
            "severity": severity,
            "summary": f"{det} returned {count} event(s).",
            "sample_events": events[:2],
        })

        if count > 0:
            if not hosts:
                hosts = {"(unknown-host)"}
            for h in hosts:
                by_host[h][det] = {"count": count, "first_seen": first_seen}

        # Collect narrative evidence (best-effort) from sample events
        # Encoded PowerShell detection sample event
        if det == "sysmon_encoded_powershell" and events:
            e = events[0]
            h = pick_best_str(e.get("host"), "(unknown-host)")
            evidence_by_host[h]["encoded_commandline"] = pick_best_str(e.get("CommandLine"))
            evidence_by_host[h]["encoded_parent"] = pick_best_str(e.get("ParentImage"))
            evidence_by_host[h]["encoded_image"] = pick_best_str(e.get("Image"))

        # Scripting network detection sample event
        if det == "sysmon_scripting_network" and events:
            e = events[0]
            h = pick_best_str(e.get("host"), "(unknown-host)")
            evidence_by_host[h]["dest_ip"] = pick_best_str(e.get("DestinationIp"))
            evidence_by_host[h]["dest_port"] = pick_best_str(e.get("DestinationPort"))
            evidence_by_host[h]["dest_proto"] = pick_best_str(e.get("Protocol"))

    # Correlation
    chains = []
    escalate_pairs = defaultdict(set)
    window_min = CORRELATION_WINDOW_MINUTES

    for host, dets in by_host.items():
        def t(det_name: str) -> datetime | None:
            return dets.get(det_name, {}).get("first_seen")

        # Chain A: Encoded PS + scripting network within window
        if "sysmon_encoded_powershell" in dets and "sysmon_scripting_network" in dets:
            if within_window(t("sysmon_encoded_powershell"), t("sysmon_scripting_network"), window_min):
                chains.append({
                    "host": host,
                    "chain": "Execution → Network (Encoded PowerShell + outbound scripting traffic)",
                    "involved": ["sysmon_encoded_powershell", "sysmon_scripting_network"],
                })
                escalate_pairs["sysmon_encoded_powershell"].add(host)
                escalate_pairs["sysmon_scripting_network"].add(host)

        # Chain B: bruteforce+success + service creation within window
        if "bruteforce_then_success" in dets and "new_service_created" in dets:
            if within_window(t("bruteforce_then_success"), t("new_service_created"), window_min):
                chains.append({
                    "host": host,
                    "chain": "Credential Access → Persistence (successful auth then service creation)",
                    "involved": ["bruteforce_then_success", "new_service_created"],
                })
                escalate_pairs["bruteforce_then_success"].add(host)
                escalate_pairs["new_service_created"].add(host)

        # Chain C: Office->PowerShell + LOLBins within window
        if "sysmon_office_to_powershell" in dets and "sysmon_lolbins_suspicious" in dets:
            if within_window(t("sysmon_office_to_powershell"), t("sysmon_lolbins_suspicious"), window_min):
                chains.append({
                    "host": host,
                    "chain": "User Execution → Proxy Execution (Office spawn + LOLBin behavior)",
                    "involved": ["sysmon_office_to_powershell", "sysmon_lolbins_suspicious"],
                })
                escalate_pairs["sysmon_office_to_powershell"].add(host)
                escalate_pairs["sysmon_lolbins_suspicious"].add(host)

    # Escalate ONLY involved detections on involved hosts; smoke_test never escalates
    for c in triage_cases:
        det = c["detection"]
        if det == "smoke_test" or c["event_count"] == 0:
            continue
        hosts = set(c["hosts"]) if c["hosts"] else {"(unknown-host)"}
        if det in escalate_pairs and (hosts & escalate_pairs[det]):
            c["severity"] = "critical"
            c["score"] = max(c["score"], 90)

    # Sort report by severity
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    triage_sorted = sorted(triage_cases, key=lambda x: sev_rank.get(x["severity"], 0), reverse=True)

    # Write report
    report_lines = []
    report_lines.append("# AI SOC Incident Report")
    report_lines.append("")
    report_lines.append(f"Generated: **{utc_now_iso()}**")
    report_lines.append(f"Source cases file: `{cases_path}`")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")

    if chains:
        report_lines.extend(build_executive_summary(chains, evidence_by_host, window_min))

        report_lines.append("##  Correlated Attack Chains")
        report_lines.append("")
        for ch in chains:
            report_lines.append(f"### Host: `{ch['host']}`")
            report_lines.append(f"- {ch['chain']} (within {window_min}m)")
            report_lines.append(f"- Involved detections: {', '.join(ch['involved'])}")
            report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

    for c in triage_sorted:
        report_lines.append(f"## {c['detection']} — {c['severity'].upper()} (score {c['score']})")
        report_lines.append("")
        report_lines.append(f"- **Event count:** {c['event_count']}")
        if c["hosts"]:
            report_lines.append(f"- **Hosts:** {', '.join(c['hosts'])}")
        if c["first_seen_utc"]:
            report_lines.append(f"- **First seen (UTC):** {c['first_seen_utc']}")
        if c["mitre"]:
            report_lines.append(f"- **MITRE:** {', '.join(c['mitre'])}")
        report_lines.append(f"- **Summary:** {c['summary']}")
        report_lines.append("")

        if c["sample_events"]:
            report_lines.append("**Sample evidence (first 2 events)**")
            report_lines.append("```json")
            report_lines.append(json.dumps(c["sample_events"], indent=2)[:4000])
            report_lines.append("```")
            report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    report_path = out_dir / safe_filename("report", "md")
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"[OK] Wrote {report_path}")

    triage_json_path = out_dir / safe_filename("triage", "json")
    triage_json_path.write_text(
        json.dumps({
            "generated_at_utc": utc_now_iso(),
            "source_cases_file": str(cases_path),
            "correlated_chains": chains,
            "triage_cases": triage_cases,
            "correlation_window_minutes": window_min,
        }, indent=2),
        encoding="utf-8"
    )
    print(f"[OK] Wrote {triage_json_path}")


if __name__ == "__main__":
    main()