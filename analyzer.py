"""
failed-login-log-analyzer

A beginner-friendly script that reads a log file and summarizes failed
login/authentication events across multiple services.
"""

import re
import sys
from collections import defaultdict


# Keep service detection ordered from most specific to least specific.
SERVICE_PATTERNS = [
    ("SSH", [r"\bsshd\b", r"\bssh\b", r"pam_unix\(auth\)"]),
    ("FTP", [r"\bftp\b", r"\bvsftpd\b", r"\bproftpd\b"]),
    ("RDP", [r"\brdp\b", r"\brdpauth\b", r"\bterminalservices\b", r"\bmstsc\b"]),
    ("WEB", [r"\bwebapp\b", r"\bnginx\b", r"\bhttp\b", r"\bhttps\b", r"/login"]),
]

# Keywords that typically indicate a failed authentication event.
FAILURE_KEYWORDS = [
    "failed password",
    "authentication failure",
    "login failed",
    "failed login",
    "fail login",
    "invalid password",
    "invalid credentials",
    "auth failed",
    "denied",
]

# Keywords that usually indicate success, so we can skip them.
SUCCESS_KEYWORDS = [
    "accepted password",
    "login successful",
    "authentication succeeded",
]

# Regex patterns to extract IP addresses and usernames.
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USERNAME_REGEXES = [
    re.compile(r"\buser(?:name)?=([a-zA-Z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"\bfor invalid user\s+([a-zA-Z0-9._@-]+)", re.IGNORECASE),
    re.compile(r"\bfor\s+([a-zA-Z0-9._@-]+)\s+from\b", re.IGNORECASE),
    re.compile(r"\buser\s+\"([a-zA-Z0-9._@-]+)\"", re.IGNORECASE),
    re.compile(r"\blogin\s+for\s+([a-zA-Z0-9._@-]+)", re.IGNORECASE),
    re.compile(r'"username"\s*:\s*"([^"]+)"', re.IGNORECASE),
]


def detect_service(line: str) -> str:
    """Try to identify which service/protocol generated this log line."""
    lowered = line.lower()
    for service, patterns in SERVICE_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, lowered):
                return service
    return "UNKNOWN"


def is_failed_auth_line(line: str) -> bool:
    """Return True if the line looks like a failed auth/login event."""
    lowered = line.lower()

    # If the line clearly says success, do not treat it as a failure.
    if any(keyword in lowered for keyword in SUCCESS_KEYWORDS):
        return False

    return any(keyword in lowered for keyword in FAILURE_KEYWORDS)


def extract_username(line: str) -> str:
    """Best-effort username extraction from common log formats."""
    for regex in USERNAME_REGEXES:
        match = regex.search(line)
        if match:
            return match.group(1)
    return "N/A"


def extract_ip(line: str) -> str:
    """Extract first IPv4 address found in the log line."""
    match = IP_REGEX.search(line)
    if match:
        return match.group(0)
    return "N/A"


def print_summary_table(events: list[dict], failed_by_ip: dict[str, int]) -> None:
    """Print a beginner-friendly summary table of failed login events."""
    print("\n=== Failed Login Event Details ===")
    print(f"{'#':<3} {'Service':<8} {'IP Address':<15} {'Username':<18} {'Raw Event'}")
    print("-" * 95)

    for i, event in enumerate(events, start=1):
        print(
            f"{i:<3} {event['service']:<8} {event['ip']:<15} {event['username']:<18} {event['line']}"
        )

    print("\n=== Failed Attempts by Source IP ===")
    print(f"{'IP Address':<15} {'Failed Attempts':<15}")
    print("-" * 32)

    # Sort by highest number of attempts first.
    for ip, count in sorted(failed_by_ip.items(), key=lambda item: item[1], reverse=True):
        print(f"{ip:<15} {count:<15}")


def main() -> None:
    """Read a log file from CLI args, detect failed auth events, and print results."""
    # Expect a log file path as the first command-line argument.
    # Example: python3 analyzer.py sample.log
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <log_file_path>")
        print("Example: python3 analyzer.py sample.log")
        return

    log_file = sys.argv[1]
    """Read sample.log, detect failed auth events, and print summary results."""
    log_file = "sample.log"
    failed_events = []
    failed_attempts_by_ip = defaultdict(int)

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line:
                    continue

                if not is_failed_auth_line(line):
                    continue

                service = detect_service(line)
                ip = extract_ip(line)
                username = extract_username(line)

                failed_events.append(
                    {
                        "service": service,
                        "ip": ip,
                        "username": username,
                        "line": line,
                    }
                )

                if ip != "N/A":
                    failed_attempts_by_ip[ip] += 1

        if not failed_events:
            print(f"No failed login or authentication events were found in {log_file}")
            print("No failed login or authentication events were found in sample.log")
            return

        print_summary_table(failed_events, failed_attempts_by_ip)

    except FileNotFoundError:
        print(f"Error: Could not find {log_file}. Please make sure it exists.")


if __name__ == "__main__":
    main()
