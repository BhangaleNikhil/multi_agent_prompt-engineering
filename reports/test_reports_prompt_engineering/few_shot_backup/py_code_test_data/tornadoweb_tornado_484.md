Vulnerability: Hardcoded Credentials
Severity: High
CWE: CWE-798
Location: Lines 5, 7, and 8
Description: The code contains sensitive credentials, such as the consumer key (`'test_twitter_consumer_key'`) and the access token (`'hjkl'`), hardcoded directly into the source file. If an attacker gains access to the source code repository or the running application memory, these credentials can be immediately harvested and used to impersonate the application or access associated user data.
Remediation: Never hardcode secrets. Credentials must be loaded dynamically from secure sources such as environment variables, dedicated secret management services (e.g., AWS Secrets Manager, HashiCorp Vault), or secure configuration files that are excluded from version control.