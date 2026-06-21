Vulnerability: Denial of Service (Resource Exhaustion)
Severity: High
CWE: CWE-400
Location: Line 5
Description: The `serialize` method processes an arbitrary input node (`node`) without implementing any safeguards against excessive resource consumption. If the underlying data structure or the content within the node is maliciously crafted (e.g., deeply nested elements, excessively large arrays, or recursive entities in XML/text formats), it can lead to stack overflow, out-of-memory errors, or CPU exhaustion, resulting in a Denial of Service condition.
Remediation: Implement strict resource controls on the serialization process. This includes setting maximum limits for recursion depth, enforcing constraints on the total number of nodes/elements processed, and utilizing streaming parsers or iterative processing methods rather than relying solely on deep recursive calls.