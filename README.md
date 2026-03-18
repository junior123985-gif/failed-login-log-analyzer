# failed-login-log-analyzer

A beginner-friendly Python project that reads log data and identifies failed login or authentication events across multiple services.

## What this project does

`analyzer.py` reads `sample.log`, detects failed authentication activity, extracts useful context (source IP, username, and service), and prints a clear summary.

This project is intentionally simple so junior cybersecurity learners can understand each step and extend it.

## Multi-service failed login analysis

The analyzer is designed to detect failures from more than just SSH. It includes examples for:

- SSH
- FTP
- RDP
- Web application login attempts
- Generic authentication/PAM-style failures

## Features

- Reads a log file (`sample.log`)
- Detects failed login/authentication events
- Skips clearly successful authentication events
- Extracts source IP addresses when present
- Extracts usernames when present
- Identifies service/protocol when possible
- Counts failed attempts per IP address
- Prints a table-like summary output

## How to run

1. Make sure you are in the project folder.
2. Run:

```bash
python3 analyzer.py sample.log
```

## Example output

```text
=== Failed Login Event Details ===
#   Service  IP Address      Username           Raw Event
-----------------------------------------------------------------------------------------------
1   SSH      203.0.113.10    admin              2026-03-17T08:12:33Z host1 sshd[2145]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2
2   SSH      203.0.113.10    root               2026-03-17T08:12:50Z host1 sshd[2145]: Failed password for root from 203.0.113.10 port 51235 ssh2
...

=== Failed Attempts by Source IP ===
IP Address      Failed Attempts
--------------------------------
203.0.113.10    2
198.51.100.23   4
192.0.2.44      2
203.0.113.77    2
```

## Why this is useful for cybersecurity

This mini-project demonstrates practical SOC and threat detection fundamentals:

- **Triage:** Quickly spot repeated failed logins from the same source.
- **Investigation:** Correlate IP, username, and service to understand attack patterns.
- **Detection engineering basics:** Turn raw logs into actionable summaries.
- **Portfolio value:** Shows entry-level Python + cybersecurity log analysis skills.

A natural next step is adding alert thresholds (for example, flagging IPs with 5+ failed attempts) or exporting results to CSV/JSON.

