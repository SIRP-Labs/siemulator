"""Synthetic CrowdStrike-flavoured detection templates.

Both the LogScale and QRadar mock surfaces draw from this pool. Each
template carries MITRE ATT&CK tactic + technique IDs so consumers
exercising detection-engineering paths see realistic content.

Adding templates: append a dict matching the schema below. Optional
network fields (RemoteAddress, RemotePort, Domain) trigger C2-style
event enrichment in the LogScale shape.
"""

from __future__ import annotations

ALERT_TEMPLATES: list[dict] = [
    {
        "DetectName": "Credential Dumping via Mimikatz",
        "DetectDescription": (
            "Process attempted to extract credentials from LSASS memory using "
            "Mimikatz-style API calls."
        ),
        "Severity": 5,
        "SeverityName": "Critical",
        "Tactic": "Credential Access",
        "TacticId": "TA0006",
        "Technique": "OS Credential Dumping: LSASS Memory",
        "TechniqueId": "T1003.001",
        "FileName": "mimikatz.exe",
        "FilePath": "C:\\Users\\analyst\\Downloads\\",
        "CommandLine": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
        "MD5String": "a1b2c3d4e5f6789012345678901234aa",
        "SHA256String": "0f2dd7587bccdaa4d7c7e8c5a82bf2eeae0db2c6db2b5f6dcd5db4f9b9faaaaa",
        "ParentImageFileName": "powershell.exe",
        "ParentCommandLine": "powershell.exe -ExecutionPolicy Bypass -File run.ps1",
    },
    {
        "DetectName": "Suspicious PowerShell with Base64 Encoded Command",
        "DetectDescription": (
            "PowerShell launched with -EncodedCommand parameter from a non-"
            "standard parent process; decoded payload contains download "
            "cradle to external URL."
        ),
        "Severity": 4,
        "SeverityName": "High",
        "Tactic": "Execution",
        "TacticId": "TA0002",
        "Technique": "Command and Scripting Interpreter: PowerShell",
        "TechniqueId": "T1059.001",
        "FileName": "powershell.exe",
        "FilePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
        "CommandLine": (
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            "JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA…"
        ),
        "MD5String": "e3b0c44298fc1c149afbf4c8996fb924",
        "SHA256String": "1b2c3d4e5f6789a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
        "ParentImageFileName": "winword.exe",
        "ParentCommandLine": "WINWORD.EXE /n \"InvoiceQ4.docm\"",
    },
    {
        "DetectName": "Lateral Movement via PsExec",
        "DetectDescription": (
            "PsExec service binary created on remote host; followed by "
            "service start from non-administrative user context."
        ),
        "Severity": 4,
        "SeverityName": "High",
        "Tactic": "Lateral Movement",
        "TacticId": "TA0008",
        "Technique": "Remote Services: SMB/Windows Admin Shares",
        "TechniqueId": "T1021.002",
        "FileName": "PSEXESVC.exe",
        "FilePath": "C:\\Windows\\",
        "CommandLine": "C:\\Windows\\PSEXESVC.exe",
        "MD5String": "75b55bb34dac9d029396fbb98ab8b8ff",
        "SHA256String": "141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944",
        "ParentImageFileName": "services.exe",
        "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
    },
    {
        "DetectName": "Phishing — Suspicious Outlook Attachment",
        "DetectDescription": (
            "Outlook spawned excel.exe to open attachment from external "
            "sender; macro auto-execution triggered network connection to "
            "newly-observed domain."
        ),
        "Severity": 3,
        "SeverityName": "Medium",
        "Tactic": "Initial Access",
        "TacticId": "TA0001",
        "Technique": "Phishing: Spearphishing Attachment",
        "TechniqueId": "T1566.001",
        "FileName": "EXCEL.EXE",
        "FilePath": "C:\\Program Files\\Microsoft Office\\Office16\\",
        "CommandLine": (
            '"EXCEL.EXE" "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\'
            'Windows\\INetCache\\Content.Outlook\\K2N9PQ\\Invoice_Q4_2026.xlsm"'
        ),
        "MD5String": "4f8c0d3bbb9c1a2e3d4f5b6c7a8d9e0f",
        "SHA256String": "9e2c1a3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
        "ParentImageFileName": "OUTLOOK.EXE",
        "ParentCommandLine": '"OUTLOOK.EXE"',
    },
    {
        "DetectName": "Beaconing C2 Traffic to Known Bad Domain",
        "DetectDescription": (
            "Process exhibited regular 47-minute interval connections to "
            "external host previously associated with BlueNoroff campaigns."
        ),
        "Severity": 5,
        "SeverityName": "Critical",
        "Tactic": "Command and Control",
        "TacticId": "TA0011",
        "Technique": "Application Layer Protocol: Web Protocols",
        "TechniqueId": "T1071.001",
        "FileName": "outlook.exe",
        "FilePath": "C:\\Program Files\\Microsoft Office\\Office16\\",
        "CommandLine": '"outlook.exe"',
        "RemoteAddress": "185.220.101.34",
        "RemotePort": 443,
        "Domain": "track-payload.bluenoroff-c2.io",
        "ConnectionFrequencyMinutes": 47,
        "MD5String": "5a1b2c3d4e5f6789a0b1c2d3e4f5a6b7",
        "SHA256String": "abc123def456789012345678901234567890abc123def456789012345678901234",
    },
    {
        "DetectName": "Suspicious File Write to Startup Folder",
        "DetectDescription": (
            "Non-elevated process wrote .lnk file to user Startup folder "
            "pointing to script downloaded from external HTTP source."
        ),
        "Severity": 3,
        "SeverityName": "Medium",
        "Tactic": "Persistence",
        "TacticId": "TA0003",
        "Technique": (
            "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
        ),
        "TechniqueId": "T1547.001",
        "FileName": "RunDLL32.exe",
        "FilePath": "C:\\Windows\\System32\\",
        "CommandLine": "rundll32.exe shell32.dll,ShellExec_RunDLL persistence.lnk",
        "MD5String": "8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d",
        "SHA256String": "bcd234efg567890123456789012345678901bcd234efg567890123456789012345",
    },
]


HOSTNAMES = [
    "WIN-DESKTOP-01.example.local",
    "FIN-LAPTOP-22.example.local",
    "DC-PRIMARY.example.local",
    "HR-WORKSTATION-09.example.local",
    "DEV-BUILD-03.example.local",
]

USERS = [
    "EXAMPLE\\analyst",
    "EXAMPLE\\admin.svc",
    "EXAMPLE\\jane.doe",
    "EXAMPLE\\john.smith",
    "EXAMPLE\\security.tester",
]

REPO_NAME = "detections"
