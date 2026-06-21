Vulnerability: Information Leakage / Overly Broad Exception Handling
Severity: High
CWE: CWE-532
Location: Line 14
Description: The function uses a broad `except Exception as e:` block, which catches all types of exceptions, including system errors (like KeyboardInterrupt or MemoryError) that should not be handled by the retry logic. Furthermore, logging the raw exception details (`to_text(e).splitlines()[-1]`) can lead to information leakage. If the underlying exception object contains sensitive data, stack traces, internal file paths, or configuration details, an attacker could use this information for further exploitation (e.g., mapping the system architecture).
Remediation: 
1. **Narrow Exception Handling:** Replace `except Exception as e:` with specific exception types that are expected to fail during the action (e.g., `requests.exceptions.ConnectionError`, `DatabaseException`). This ensures that unexpected, critical errors bubble up and are handled by higher-level monitoring systems instead of being masked by the retry loop.
2. **Sanitize Logging:** When logging exceptions for debugging purposes, ensure that only generic, non-sensitive information is recorded (e.g., "Action failed due to connection error"). Avoid logging full stack traces or raw exception messages unless absolutely necessary and restricted to secure log storage.