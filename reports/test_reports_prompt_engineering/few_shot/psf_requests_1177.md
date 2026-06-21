Vulnerability: Hardcoded Credentials
Severity: High
CWE: CWE-798
Location: Line 2
Description: The code hardcodes a placeholder value for an authorization token (`"Bearer XXX"`). While this is likely intended as a test placeholder, the practice of embedding any sensitive credentials (API keys, tokens, passwords) directly into source code is a critical security vulnerability. If this pattern were used with real secrets, it would expose authentication material to anyone who gains access to the codebase repository.
Remediation: Credentials and sensitive configuration values must never be hardcoded. Instead, they should be loaded dynamically at runtime using secure methods such as environment variables (e.g., `os.environ['AUTH_TOKEN']`) or dedicated secret management services (e.g., HashiCorp Vault, AWS Secrets Manager).