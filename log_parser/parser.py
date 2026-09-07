import re

from .detector import detect_suspicious

from collections import Counter, defaultdict

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
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
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

    return entry


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


def count_status_codes_by_ip(entries):
    """
    Count HTTP status codes for each IP address>
    """

    result = defaultdict(Counter)

    for entry in entries:
        ip = entry["ip"]
        status = entry["status"]

        result[ip][status] += 1

    return dict(result)


def generate_summary(entries):
    """
    Generate a security summary for each IP.
    """

    summary = defaultdict(
        lambda: {
            "total_requests": 0,
            "status_codes": Counter(),
            "suspicious_requests": 0,
            "suspicious_reasons": Counter(),
        }
    )

    for entry in entries:
        ip = entry["ip"]

        # Total requests
        summary[ip]["total_requests"] += 1

        # Status code
        summary[ip]["status_codes"][entry["status"]] += 1

        # Suspicious requests
        if entry["suspicious"]:
            summary[ip]["suspicious_requests"] += 1

            for reason in entry["reasons"]:
                summary[ip]["suspicious_reasons"][reason] += 1

    return dict(summary)
