Vulnerability: Insecure Deserialization / Pickle RCE
Severity: Critical
CWE: CWE-502
Location: Line 6, Line 10
Description: The code utilizes Python's `pickle` module for serialization and deserialization (`pickle.dumps()` and `pickle.loads()`). The `pickle` protocol is inherently insecure because it can deserialize arbitrary Python objects, allowing an attacker who controls the input data to execute malicious code (Remote Code Execution) upon calling `pickle.loads()`. This vulnerability exists even if the current context is a unit test, as the pattern itself represents a critical security flaw when handling untrusted or external data streams.
Remediation: Never use `pickle` to deserialize data received from an untrusted source (e.g., network requests, user-uploaded files). Instead, use safer, language-agnostic serialization formats such as JSON or XML, which only serialize basic data types and do not support arbitrary code execution during deserialization.