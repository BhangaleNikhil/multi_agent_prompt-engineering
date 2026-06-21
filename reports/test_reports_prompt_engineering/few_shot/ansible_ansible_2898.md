Vulnerability: SQL Injection
Severity: Critical
CWE: CWE-89
Location: Lines 60, 73
Description: The function constructs dynamic SQL commands using user-provided input (`role_attr_flags`) which is then inserted into the query string via Python's string formatting or concatenation. Specifically, when building the `alter` list in both the 'PUBLIC' user path and the `no_password_changes` path, the variable `role_attr_flags` is appended directly to the SQL structure (`alter.append(role_attr_flags)` or `alter.append('WITH %s' % role_attr_flags)`). If an attacker can manipulate the content of `role_attr_flags`, they could inject malicious SQL commands (e.g., using comments `--` or semicolons `;`) that execute arbitrary database operations, potentially leading to privilege escalation or data exfiltration.
Remediation: Instead of building dynamic SQL strings by concatenating user input for role attributes, the application must use a whitelisting approach. All acceptable role attribute names and values should be predefined constants. If dynamic construction is absolutely necessary, all inputs used in the query structure (like `role_attr_flags`) must be rigorously sanitized or passed through a dedicated SQL quoting function that handles complex structures like boolean flags, ensuring they are treated purely as data and never as executable code.

---
*Note: The use of parameterized queries for simple values (like user ID or expiration dates) is correct, but the dynamic construction of structural elements (like role attributes) bypasses this protection.*