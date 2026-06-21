Vulnerability: Denial of Service (DoS) via Resource Exhaustion
Severity: High
CWE: CWE-400
Location: Line 30
Description: The function systematically iterates through a potentially large range of column counts (`for count in xrange(lowerCount, upperCount + 1):`) to test for UNION injection. If the configured range (`lowerCount` to `upperCount`) is excessively wide, or if the target endpoint is slow, this process will execute a high volume of database queries. This aggressive querying pattern can quickly consume excessive resources (CPU, database connections, network bandwidth) on the target system, potentially leading to a Denial of Service condition.
Remediation: Implement robust rate limiting and throttling mechanisms within the scanner framework. The tool should enforce configurable limits on the maximum number of queries executed and the maximum size of the column count range to ensure that testing remains non-disruptive to the target service.