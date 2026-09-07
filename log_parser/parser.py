import re

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
