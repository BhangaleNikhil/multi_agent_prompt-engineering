Vulnerability: Information Leakage (Server Version)
Severity: Medium
CWE: CWE-200
Location: Line 3
Description: The function explicitly includes the application's specific version number (`tornado.version`) within the `Server` HTTP response header. This practice leaks implementation details, allowing attackers to perform accurate system fingerprinting and target known vulnerabilities associated with that exact software stack version.
Remediation: Remove or generalize the server version information from public-facing headers. If version reporting is necessary for internal logging, it should be stripped before sending the response to the client. Alternatively, use a generic header value (e.g., "Server: CustomApplication") to obscure the underlying technology stack.