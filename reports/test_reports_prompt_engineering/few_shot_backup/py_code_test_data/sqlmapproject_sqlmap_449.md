Vulnerability: Information Leakage (via Logging)
Severity: Medium
CWE: CWE-200
Location: Line 2
Description: The function logs the raw attributes (`attrs`) using `debug("%s", attrs")`. If the input attributes contain sensitive data (such as session tokens, API keys, passwords, or personal identifying information), this data will be written directly to the application logs. This practice increases the attack surface and violates the principle of least privilege regarding data retention.
Remediation: Before logging the attributes, implement a sanitization layer to detect and redact sensitive data fields. If logging is required for debugging, ensure that the logging mechanism explicitly filters out or masks known sensitive data types (e.g., credit card numbers, passwords).