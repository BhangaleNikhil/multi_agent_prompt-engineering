Vulnerability: Denial of Service (DoS) / Input Validation Failure
Severity: Medium
CWE: CWE-20
Location: Line 11
Description: The function assumes that any non-whitespace line (`line`) will contain at least one colon (`:`) separator, allowing it to be successfully unpacked into two variables (`name`, `value`). If an attacker provides a malformed header line that does not contain a colon (e.g., `line = "malformed header"`), the `line.split(":", 1)` operation will return a list of length 1. Attempting to unpack this list into two variables will raise a `ValueError`, causing the application to crash and resulting in a Denial of Service condition.
Remediation: Implement robust input validation and error handling. Before attempting to unpack the result of `line.split(":", 1)`, check the length of the resulting list. If the line is malformed, the function should log the error and gracefully skip processing the line instead of raising an unhandled exception.