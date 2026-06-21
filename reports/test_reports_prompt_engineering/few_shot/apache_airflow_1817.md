Vulnerability: SQL Injection
Severity: Critical
CWE: CWE-89
Location: Line 5
Description: The code executes a dynamically generated query (`update_query`) using `op.execute()`. If the internal function `_update_value_from_dag_run` constructs this query by concatenating untrusted inputs (such as `dag_id`, `run_id`, or other values passed to it) directly into the SQL string, the application is vulnerable to SQL Injection. An attacker could manipulate these input variables to alter the intended database operation, potentially leading to data theft, modification, or denial of service.
Remediation: Ensure that all dynamic values used in constructing the `update_query` are passed as parameters to the execution function (e.g., using parameterized query syntax provided by SQLAlchemy/Alembic) rather than being formatted directly into the SQL string. Never use f-strings or standard string concatenation for building database queries with user-controlled data.