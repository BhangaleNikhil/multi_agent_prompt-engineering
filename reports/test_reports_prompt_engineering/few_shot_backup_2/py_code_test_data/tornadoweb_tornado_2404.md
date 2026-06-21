Vulnerability: Open Redirect
Severity: High
CWE: CWE-601
Location: Line 7
Description: The code snippet validates how the application handles absolute URLs passed via a redirect parameter (`next`). If the underlying production logic fails to strictly validate or sanitize this input, an attacker could supply an arbitrary malicious URL (e.g., `http://attacker.com/phish`) instead of the expected local address. This vulnerability allows attackers to perform phishing attacks by redirecting legitimate users to unauthorized external websites while maintaining the appearance of a trusted domain.
Remediation: Implement strict validation on all parameters used for redirection targets. The application should enforce whitelisting rules, ensuring that the `next` parameter only accepts paths relative to the current site or is restricted to a predefined set of safe domains. Never trust user-supplied input when constructing redirect URLs.