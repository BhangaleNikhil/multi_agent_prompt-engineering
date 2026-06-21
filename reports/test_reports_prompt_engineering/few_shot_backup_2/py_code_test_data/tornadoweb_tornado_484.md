Vulnerability: Hardcoded Credentials / Secret Exposure
Severity: High
CWE: CWE-798
Location: Line 5, Line 8
Description: The code hardcodes sensitive values such as `oauth_consumer_key` ('test_twitter_consumer_key') and `oauth_token` ('hjkl'). Embedding credentials directly into the source code is a severe security risk. If the codebase is compromised or viewed by unauthorized personnel, these secrets are immediately exposed, allowing an attacker to impersonate users or access protected resources without needing to exploit a vulnerability.
Remediation: Credentials must never be hardcoded. Instead, they should be loaded dynamically from secure sources such as environment variables (e.g., using `os.environ`), dedicated configuration management systems, or professional secret vault services (e.g., HashiCorp Vault, AWS Secrets Manager).