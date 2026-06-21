Vulnerability: Weak/Insecure Configuration Acceptance (SSL/TLS)
Severity: High
CWE: CWE-295
Location: Line 1
Description: The `__init__` method accepts `ssl_options` via `kwargs.pop('ssl_options', {})` without performing any validation or enforcement of security standards. This design flaw allows the calling code to potentially pass insecure configurations (e.g., forcing the use of outdated protocols like TLS 1.0 or 1.1, or enabling weak cipher suites) which could severely compromise the confidentiality and integrity of the connection.
Remediation: The application must enforce strict security defaults. The initialization logic should validate the provided `ssl_options` to ensure that only modern, secure protocols (TLS 1.2 or TLS 1.3) and strong, approved cipher suites are permitted. If the user provides options that weaken security, the initialization should fail with a clear error message rather than proceeding with the insecure configuration.