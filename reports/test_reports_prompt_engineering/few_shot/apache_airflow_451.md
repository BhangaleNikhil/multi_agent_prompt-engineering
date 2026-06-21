Vulnerability: Injection
Severity: High
CWE: CWE-79
Location: Line 1
Description: The function constructs an API endpoint URL by directly embedding the `DAG_ID` variable into the query string using an f-string (`f"/object/grid_data?dag_id={DAG_ID}"`). If `DAG_ID` originates from untrusted user input, an attacker could inject characters (such as `&`, `=`, or path traversal sequences) to modify the intended parameters, potentially leading to unauthorized data retrieval, parameter tampering, or API misuse.
Remediation: Use dedicated URL building libraries (e.g., Python's `urllib.parse` or the client library's built-in methods for passing query parameters). These tools automatically handle proper URL encoding for all input variables, ensuring that user-supplied data is treated as literal values and cannot break out of the intended parameter structure.