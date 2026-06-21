Vulnerability: Open Redirect / Improper Input Validation
Severity: High
CWE: CWE-601
Location: Line 23
Description: The function accepts and uses the `redirect_uri` parameter directly from external input without validating it against a predefined whitelist of allowed callback URLs. In an OAuth flow, if the `redirect_uri` is not strictly validated (and ideally pre-registered with the identity provider), an attacker could potentially manipulate this URI to redirect authenticated users to malicious sites after successful login, leading to phishing or session hijacking attempts.
Remediation: Implement strict validation for the `redirect_uri`. The application must only accept and use whitelisted callback URIs that are explicitly registered and belong to the application's domain. Never trust user-supplied values for redirection targets in authentication flows.