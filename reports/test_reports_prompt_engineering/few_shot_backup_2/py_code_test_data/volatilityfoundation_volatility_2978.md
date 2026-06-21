Vulnerability: Path Traversal
Severity: High
CWE: CWE-22
Location: Line 24
Description: The file path is constructed using variables derived from process information, specifically `name` (task.ImageFileName). If the `ImageFileName` or any other input variable used in the format string contains directory traversal sequences (e.g., `../`), an attacker could potentially manipulate the resulting path to write dump files outside of the intended `self._config.DUMP_DIR`.
Remediation: Before incorporating external inputs like `name` into a file path, sanitize them by stripping or validating against path separators (`/`, `\`). Use functions such as `os.path.basename()` on any input that is expected to represent only a simple filename component to prevent traversal attacks.