Vulnerability: Information Leakage / Sensitive Data Exposure
Severity: Medium
CWE: CWE-209
Location: Line 3
Description: The function constructs an exception message that includes internal framework details (`@gen.engine`) and, critically, embeds the value of a variable named `result` using string formatting (`%r`). If this callback is triggered by an attacker or if the system state allows manipulation of `result`, the error message could leak sensitive information about the application's internal workings, data structures, or execution context, aiding in subsequent attacks.
Remediation: Error messages should be generic and sanitized to prevent the leakage of internal variable states, stack traces, or framework-specific identifiers. Instead of including `%r` % result, the error message should simply state that the function cannot return values without revealing the underlying data structure or value.