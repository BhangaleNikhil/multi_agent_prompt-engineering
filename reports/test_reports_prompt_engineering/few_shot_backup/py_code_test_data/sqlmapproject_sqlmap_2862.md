Vulnerability: Log Injection
Severity: Medium
CWE: CWE-117
Location: Line 17
Description: The function uses standard string formatting (`%s`) to log the extracted DBMS error message (`msg`). If the content of `msg` contains characters like newline characters (`\n`), carriage returns (`\r`), or format specifiers (e.g., `%s`, `%d`), an attacker could inject malicious log entries, potentially confusing log analysis, bypassing security monitoring, or causing denial of service in the logging system.
Remediation: When logging user-controlled or external data, always use parameterized logging methods provided by the logging framework (e.g., `logger.warning("parsed DBMS error message: %s", msg.rstrip('.'))`). This ensures that the input data is treated purely as data and cannot be interpreted as part of the log format string.