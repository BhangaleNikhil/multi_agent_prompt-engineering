Vulnerability: Hardcoded Configuration/Secrets
Severity: Medium
CWE: CWE-798
Location: Line 2
Description: The connection URI (`conn_uri`) is hardcoded within the test function. While this pattern is common in unit tests, if similar configuration logic were used in production code, embedding environment-specific or sensitive details (like cluster contexts or credentials) directly into the source code increases the risk of accidental exposure and severely limits deployment flexibility.
Remediation: Configuration values should be loaded dynamically from secure sources such as dedicated secret managers (e.g., HashiCorp Vault, AWS Secrets Manager), environment variables, or configuration files that are managed outside of the version control system.