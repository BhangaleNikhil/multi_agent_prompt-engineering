Vulnerability: Open Redirect
Severity: High
CWE: CWE-601
Location: Implied application logic handling the `Location` header (specifically the parameter used for the `next` redirect target).
Description: The test case structure suggests that the application uses a parameter (likely `next`) to determine the redirect destination after authentication. If the application accepts an arbitrary, unvalidated URL provided in this parameter and uses it directly in the HTTP `Location` header, it is vulnerable to Open Redirect. An attacker can exploit this by crafting a malicious URL that redirects the user to a phishing site, a credential harvesting page, or a local resource, making the application appear legitimate.
Remediation: Implement strict validation on the redirect target parameter. The application should only allow redirects to:
1.  A predefined list of safe, internal paths (whitelisting).
2.  Relative paths that are guaranteed to stay within the application's domain.
3.  If absolute URLs are necessary, they must be validated to ensure they belong to the same domain and do not contain schemes like `file://` or `data:`.