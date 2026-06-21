Vulnerability: Hardcoded Credentials
Severity: High
CWE: CWE-798
Location: Line 2
Description: The function hardcodes sensitive credentials, including `password='passsword'`, `server='localhost'`, and `user='admin'`. Storing secrets directly in the source code is a significant security risk. If the repository is compromised or if the code is accidentally exposed, these credentials can be immediately exploited by an attacker.
Remediation: Credentials should never be hardcoded. Instead, they must be loaded dynamically from secure sources such as environment variables (e.g., using `os.environ`), dedicated secret management services (e.g., HashiCorp Vault, AWS Secrets Manager), or encrypted configuration files that are excluded from version control.