Vulnerability: Denial of Service (DoS) / Resource Exhaustion
Severity: High
CWE: CWE-400
Location: Function scope (The entire `compose_node` function)
Description: The function is part of a parser or compiler component that processes structured data (indicated by the use of events, anchors, and composition methods). If the input data stream is maliciously crafted to be excessively deep (e.g., deeply nested sequences or mappings) or if the internal resolver logic contains circular references, the function may trigger deep recursion, leading to a Stack Overflow or excessive memory consumption, resulting in a Denial of Service condition.
Remediation: Implement strict resource limits and depth checks. The parser should enforce a maximum recursion depth limit (e.g., a configurable limit on the number of nested nodes or events processed) to prevent stack overflow attacks. Additionally, consider implementing resource monitoring (e.g., time limits) during the parsing process.