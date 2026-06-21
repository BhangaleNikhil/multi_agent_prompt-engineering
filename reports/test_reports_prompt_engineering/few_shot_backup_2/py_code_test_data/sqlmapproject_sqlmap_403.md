Vulnerability: Regular Expression Denial of Service (ReDoS)
Severity: High
CWE: CWE-400
Location: Line 72, and multiple regex usages throughout the function body.
Description: The crawler relies heavily on complex regular expressions to parse and extract data from untrusted HTML content fetched from external web sources. Specifically, the pattern `r"(?si)<html[^>]*>(.+)</html>"` (