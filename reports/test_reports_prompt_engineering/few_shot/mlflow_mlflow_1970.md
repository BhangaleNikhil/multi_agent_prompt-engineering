Vulnerability: Path Traversal / Improper Input Validation
Severity: High
CWE: CWE-22
Location: Line 5
Description: The `registry_uri` parameter is an untrusted input used to initialize the model store. If this URI is not strictly validated or sanitized, an attacker could inject path traversal sequences (e.g., `../../etc/passwd`) allowing them to access files and resources outside of the intended model registry directory structure. This vulnerability can lead to unauthorized information disclosure or system compromise.
Remediation: Implement strict input validation on `registry_uri`. The application must validate that the URI conforms only to expected formats (e.g., specific network protocols, allowed characters) and use canonicalization functions before passing it to any utility function that interacts with the file system or network resources. If possible, enforce whitelisting of acceptable paths/URIs.