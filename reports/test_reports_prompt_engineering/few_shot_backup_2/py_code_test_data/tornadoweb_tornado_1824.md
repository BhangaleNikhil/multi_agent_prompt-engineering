Vulnerability: Improper Input Validation / Denial of Service
Severity: Medium
CWE: CWE-20
Location: Line 4
Description: The function relies on parsing the `Content-Type` header (`headers.get("Content-Type", "")`) to determine if content is compressible. If an attacker can inject excessively long or malformed strings into the `Content-Type` header, the subsequent string manipulation (e.g., `.split(";")[0]`, and internal calls like `_unicode()`) could lead to resource exhaustion (Denial of Service) or unexpected behavior in the compression logic.
Remediation: Implement strict validation and sanitization on all incoming HTTP headers, especially those used for content negotiation (`Content-Type`). Limit the maximum length of header values and ensure that parsing functions handle malformed input gracefully without crashing or consuming excessive resources.