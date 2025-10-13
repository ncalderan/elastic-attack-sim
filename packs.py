# packs.py
from dataclasses import dataclass
from typing import Dict, Any, List

@dataclass
class Pack:
    key: str
    title: str
    description: str
    active: bool
    generator_script: str
    generator_args: Dict[str, Any]
    discover_queries: List[str]
    expected_alerts: List[str]

PACKS: List[Pack] = [
    Pack(
        key="windows_persistence",
        title="Windows Persistence (Task + PS + LSASS)",
        description=(
            "Generates Windows Security 4698/1102 + PowerShell 4104 + Endpoint API (LSASS) "
            "and AWS IAM context — aligned to prebuilt Elastic Security (non-ML) rules."
        ),
        active=True,
        generator_script="generators/elastic_attack_sim_v2.py",
        generator_args={
            "count": 1000,
            "rate": 200,
            "batch_size": 500,
            "seed": 42,
            "namespace": None,  # will be filled from UI
        },
        discover_queries=[
            'data_stream.dataset:"windows.security" AND winlog.event_id:4698 AND event.action:"scheduled-task-created"',
            'data_stream.dataset:"windows.security" AND winlog.event_id:1102 AND (event.action:"audit-log-cleared" OR event.action:"Log clear")',
            'data_stream.dataset:"windows.powershell" AND powershell.file.script_block_text:(FromBase64String AND (GzipStream OR DeflateStream))',
            'data_stream.dataset:"endpoint.events.api" AND process.Ext.api.name:"OpenProcess" AND Target.process.name:"lsass.exe"',
            'data_stream.dataset:"aws.cloudtrail" AND event.action:"CreateAccessKey"',
        ],
        expected_alerts=[
            "A scheduled task was created",
            "Windows Event Logs Cleared",
            "Suspicious Windows Powershell Arguments",
            "PowerShell Suspicious Payload Encoded and Compressed",
            "Suspicious Portable Executable Encoded in Powershell Script",
            "Suspicious Lsass Process Access",
            "AWS IAM User Created Access Keys For Another User",
            "AWS IAM AdministratorAccess Policy Attached to User",
        ],
    ),
    # Stubs for future packs (disabled/placeholder)
    Pack(
        key="cloud_priv_esc",
        title="Cloud Privilege Escalation (AWS)",
        description="AWS IAM key creation and admin policy attach chain.",
        active=False,
        generator_script="generators/elastic_attack_sim_v2.py",
        generator_args={"count": 300, "rate": 150, "batch_size": 300, "seed": 7, "namespace": None},
        discover_queries=[],
        expected_alerts=[],
    ),
    Pack(
        key="ransomware_windows",
        title="Ransomware (Windows)",
        description="Mass file encryption indicators and lateral discovery.",
        active=False,
        generator_script="generators/elastic_attack_sim_v2.py",
        generator_args={"count": 800, "rate": 250, "batch_size": 400, "seed": 9, "namespace": None},
        discover_queries=[],
        expected_alerts=[],
    ),
    Pack(
        key="lateral_windows_only",
        title="Lateral Movement (Windows Only)",
        description="RDP/SMB attempts, process starts, and discovery utilities.",
        active=False,
        generator_script="generators/elastic_attack_sim_v2.py",
        generator_args={"count": 600, "rate": 200, "batch_size": 300, "seed": 21, "namespace": None},
        discover_queries=[],
        expected_alerts=[],
    ),
]
