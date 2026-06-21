Vulnerability: Insecure Handling of Credentials
Severity: High
CWE: CWE-312
Location: Line 7, Line 8
Description: The function accepts and assigns sensitive credentials (username and password) as plain text attributes (`self.esxi_username`, `self.esxi_password`) and passes them directly into the connection specification object. Storing or passing passwords in plaintext within application memory increases the risk of exposure through memory dumps, logging mechanisms, or unauthorized access to the process state.
Remediation: Credentials should never be stored or passed around as plain text attributes. Implement a robust secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) to retrieve credentials at runtime. If direct storage is unavoidable for testing/development, ensure that the data structure used for connection specifications automatically masks or encrypts sensitive fields before logging or serialization.