Vulnerability: Information Leakage (Sensitive Data Exposure via Error Message)
Severity: Medium
CWE: CWE-200
Location: Line 3
Description: When the function detects that a value is being returned (i.e., `value is not None`), it raises a custom exception. The error message constructed includes the variable `result` using string formatting (`%r`). If the variable `result` contains internal state, sensitive data, or details about the application's execution flow, an attacker who triggers this error can gain valuable information, aiding in further exploitation or reconnaissance.
Remediation: Ensure that error messages displayed to users or logged in production environments do not include internal variables or state information (`result`). If the variable must be included for debugging, implement robust logging that separates sensitive data from user-facing error messages, or sanitize the variable before inclusion.