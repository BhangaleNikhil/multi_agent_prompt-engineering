Vulnerability: Path Traversal / Injection
Severity: High
CWE: CWE-22
Location: Line 2
Description: The function accepts a `path` parameter, which is an untrusted input used to construct the target URL via `self.get_url(path)`. If this path input is not rigorously sanitized or validated (e.g., checking for directory traversal sequences like `../`), an attacker could inject malicious paths to access resources outside of the intended application scope.
Remediation: Implement strict validation and canonicalization on the `path` parameter. The system should enforce whitelisting rules for allowed path segments and ensure that all input is properly escaped before being used in URL construction, preventing directory traversal attacks.