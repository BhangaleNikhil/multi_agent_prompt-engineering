Vulnerability: Log Injection
Severity: Medium
CWE: CWE-103
Location: Line 7 (and subsequent lines using string formatting)
Description: The function constructs a log message (`msg`) by concatenating inputs (`which`, `local`, `remote`) that are assumed to be controlled or influenced by external data. If these input variables contain control characters, such as newline characters (`\n`), carriage returns (`\r`), or other format specifiers, an attacker could inject arbitrary text into the log file. This technique (Log Injection) can confuse security monitoring systems, obscure malicious activity, or make forensic analysis difficult by creating false entries that appear legitimate.
Remediation: Before logging any user-controlled input, sanitize the data to strip out all control characters and newline sequences. Alternatively, use a structured logging format (e.g., JSON) which inherently handles escaping of special characters, preventing them from being interpreted as log delimiters.