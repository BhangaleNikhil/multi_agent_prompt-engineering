Vulnerability: Hardcoded Credentials
Severity: Medium
CWE: CWE-798
Location: Line 6
Description: The test function hardcodes sensitive credentials, specifically `passwd = "password"`. Storing plaintext passwords directly within source code, even in a unit test file, is a significant security anti-pattern. If the repository is compromised or viewed by unauthorized personnel, these secrets are immediately exposed.
Remediation: Credentials used for testing should never be hardcoded. Instead, they must be loaded dynamically from secure sources such as environment variables (e.g., using `os.environ`), dedicated secret management systems (like HashiCorp Vault or AWS Secrets Manager), or specialized test fixtures that abstract the credential retrieval process. This ensures secrets are not committed to version control history.