Vulnerability: Path Traversal / Improper Input Sanitization
Severity: Medium
CWE: CWE-22
Location: Line 1
Description: The function constructs the static URL by directly concatenating the `path` parameter, which is assumed to be a clean, relative path. If the `path` input originates from an untrusted source (e.g., user request parameters) and is not properly sanitized or validated, an attacker could inject directory traversal sequences (like `../`) to manipulate the resulting URL structure, potentially pointing to sensitive files outside the intended static resource directory.
Remediation: Implement strict validation on the `path` parameter. Before concatenation, the path should be normalized using functions like `os.path.normpath()` and validated against a whitelist or regex pattern that strictly enforces valid characters and prevents traversal sequences (`..`, `/`). If possible, use dedicated URL building libraries instead of manual string concatenation.