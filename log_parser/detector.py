import re

SUSPICIOUS_PATTERNS = {
    "SQL injection": re.compile(
        r"(\bunion\b.*\bselect\b|\bor\bs+\d+=\d+|'\s*or\s*')", re.IGNORECASE
    ),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE),
    "Command injection": re.compile(r"(\||;|&&|\$\(|`)", re.IGNORECASE),
    "Sensitive file": re.compile(
        r"(/etc/passwd|\.env|\.git/|wp-config\.php|id_rsa)", re.IGNORECASE
    ),
    "Scanner/probe": re.compile(
        r"(wp-admin|phpmyadmin|cgi-bin|\.git|/admin)", re.IGNORECASE
    ),
}
