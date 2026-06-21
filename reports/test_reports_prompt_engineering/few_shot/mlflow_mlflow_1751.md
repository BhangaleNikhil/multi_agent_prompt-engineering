Vulnerability: Hardcoded Credentials
Severity: High
CWE: CWE-798
Location: Line 3
Description: The code initializes an Anthropic client using a hardcoded API key (`api_key="test_key"`). Embedding credentials directly into source code is a significant security risk. If the repository or compiled artifact is compromised, these keys can be exposed and misused by attackers, potentially leading to unauthorized access or billing charges against the associated account.
Remediation: Never hardcode secrets in application code. Instead, retrieve sensitive values such as API keys from secure sources at runtime. Recommended methods include using environment variables (e.g., `os.environ['ANTHROPIC_API_KEY']`) or utilizing dedicated secret management services like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.