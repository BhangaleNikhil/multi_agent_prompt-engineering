Vulnerability: Sensitive Data Exposure
Severity: High
CWE: CWE-532
Location: Line 10
Description: The function is designed to log arbitrary parameters (`param`) associated with a machine learning run. If the calling code allows users or processes to pass sensitive information (such as API keys, passwords, credentials, or Personally Identifiable Information - PII) into the `param` object, this data will be permanently logged and stored in the MLflow tracking database. This constitutes a significant risk of data leakage if the database is compromised or accessed by unauthorized personnel.
Remediation: Implement strict input validation and sanitization mechanisms before logging parameters. The system should filter out known sensitive patterns (e.g., API key formats, credit card numbers) or require explicit whitelisting of parameter names that are allowed to contain non-sensitive data. Consider encrypting highly sensitive metadata at rest if logging is absolutely necessary.