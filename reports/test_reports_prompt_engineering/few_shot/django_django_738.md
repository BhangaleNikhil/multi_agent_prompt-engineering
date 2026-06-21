Vulnerability: Potential Cross-Site Scripting (XSS) via Unsanitized Output
Severity: Medium
CWE: CWE-79
Location: Line 45, Line 60
Description: The function uses `mark_safe()` when returning the formatted number string. While this utility is intended to signal that the content has already been sanitized or is trusted (e.g., hardcoded HTML), if the input `text` originates from an untrusted user source and contains malicious script payloads, passing it through a formatting utility and then marking it safe can bypass standard template engine auto-escaping mechanisms, leading to XSS vulnerabilities in the consuming application context.
Remediation: Ensure that any data passed into this function (the `text` argument) is strictly validated as numeric input at the earliest possible point in the request lifecycle. If the output must be displayed in a web context, always rely on the template engine's built-in auto-escaping features rather than manually calling functions like `mark_safe()`, unless absolute certainty of sanitization is guaranteed upstream.

**Note:** The core logic for numerical formatting using Python's `Decimal` type appears robust and resistant to classic injection attacks (SQLi, Command Injection). However, the use of `mark_safe()` necessitates caution regarding the source trust level of the input data (`text`).