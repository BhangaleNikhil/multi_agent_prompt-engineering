Vulnerability: Hardcoded Credentials
Severity: Medium
CWE: CWE-798
Location: Line 3
Description: The code utilizes hardcoded secrets (`SignedValueTest.SECRET` and `"key"`) directly within the unit test function. While this is a test file, hardcoding sensitive values increases the risk of accidental exposure (e.g., committing the test file to a public repository) and makes credential rotation difficult.
Remediation: Secrets used for testing or development should be loaded from environment variables or a dedicated secret management system (e.g., HashiCorp Vault, AWS Secrets Manager) rather than being defined as constants within the source code.