import re

from .detector import detect_suspicious

from collections import Counter

LOG_PATTERN = re.compile(
    r"(?P<ip>\S+)"
    r"\s+\S+"
    r"\s+\S+"
    r"\s+\[(?P<timestamp>[^\]]+)\]"
    r'\s+"(?P<method>\S+)'
    r"\s+(?P<path>\S+)"
    r'\s+(?P<protocol>[^"]+)"'
    r"\s+(?P<status>\d{3})"
    r"\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]-)")?'
)


def parse_line(line):
    """
    Parse a single Apache/Nginx access log line
    """

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    entry = {
        "ip": data["ip"],
        "timestamp": data["timestamp"],
        "method": data["method"],
        "path": data["path"],
        "protocol": data["protocol"],
        "status": int(data["status"]),
        "size": data["size"],
        "referer": data["referer"],
        "user_agent": data["user_agent"],
    }

    findings = detect_suspicious(entry)
    entry["suspicious"] = bool(findings)
    entry["reasons"] = findings


def parse_file(filename):
    """
    Parse an entire log file.
    Returns a list of logged entries
    """

    entries = []

    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            entry = parse_line(line)

            if entry:
                entries.append(entry)

        return entries


def count_requests_by_ip(entries):
    """
    Count the number of requests made by each IP address.
    """

    return Counter(entry["ip"] for entry in entries)
