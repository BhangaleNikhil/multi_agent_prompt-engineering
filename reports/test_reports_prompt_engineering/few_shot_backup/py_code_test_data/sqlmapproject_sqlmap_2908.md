Vulnerability: SQL Injection
Severity: Critical
CWE: CWE-89
Location: Line 70
Description: The function constructs complex SQL queries by concatenating variables (such as `condition` and database names from `dbs`) directly into the query string using Python's string formatting (`%s`). This practice is highly vulnerable to SQL Injection. An attacker who can influence the values of `condition` or the database names in `dbs` can inject arbitrary SQL commands, potentially leading to unauthorized data retrieval, modification, or denial of service.
Remediation: All dynamic values used in constructing SQL queries (including conditions, table names, and database names) must be passed as parameters to the database driver's execution method. Never use string formatting or concatenation to build SQL queries. If the database driver supports identifier quoting (e.g., `?` or `:name`), use that mechanism instead of relying on manual string escaping.