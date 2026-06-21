Vulnerability: Denial of Service (Resource Exhaustion)
Severity: High
CWE: CWE-400
Location: Line 18
Description: The function retrieves all records from the `Connection` table using `.all()` without implementing any pagination or size limits. If the database grows to contain a very large number of connections, this query will attempt to load all data into memory at once, leading to excessive memory consumption and potentially crashing the application process (Out-of-Memory error), resulting in a Denial of Service condition.
Remediation: Implement robust pagination logic using `limit()` and `offset()` when querying large datasets. Alternatively, enforce a maximum record count check before executing the query to prevent resource exhaustion. If exporting all data is mandatory, consider streaming results directly to the file handler rather than loading them entirely into memory first.