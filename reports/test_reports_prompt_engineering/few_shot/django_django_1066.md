Vulnerability: Hardcoded Credentials / Weak Password Usage
Severity: Medium
CWE: CWE-798
Location: Line 2
Description: The superuser account credentials (`password="secret"`) are hardcoded directly into the test setup method. While this is a testing file, embedding predictable or weak passwords in source code violates security best practices and increases the risk of accidental exposure if the codebase were ever mishandled or deployed to an insecure environment.
Remediation: Never hardcode credentials (passwords, API keys, tokens) directly into the source code. For test environments, use dedicated secret management tools, environment variables, or utilize factory patterns that pull necessary secrets from a secure configuration store rather than defining them as literal strings.