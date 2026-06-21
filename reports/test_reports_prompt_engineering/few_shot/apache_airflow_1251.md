Vulnerability: Insecure Direct Object Reference (IDOR) / Broken Access Control
Severity: High
CWE: CWE-284
Location: Line 10
Description: The function accepts a resource identifier (`replication_task_arn`) and uses it directly to retrieve data without performing any authorization checks. An attacker who knows the ARN of another user's replication task can call this method and potentially view its status, violating the principle of least privilege and leading to unauthorized information disclosure.
Remediation: Before calling `self.find_replication_tasks_by_arn`, implement a robust access control check. This check must verify that the authenticated user or service principal has explicit permission (e.g., ownership rights or appropriate role-based permissions) to view the status of the resource identified by `replication_task_arn`. The authorization logic should be executed *before* any data retrieval occurs.