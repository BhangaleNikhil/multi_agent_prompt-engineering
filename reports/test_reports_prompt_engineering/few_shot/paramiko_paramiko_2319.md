Vulnerability: Information Leakage / Sensitive Data Exposure
Severity: Medium
CWE: CWE-209
Location: Line 1
Description: The `__repr__` method is designed to provide a string representation of an object, which is frequently used in logging and debugging. If the internal method `self._debug_str()` processes or includes sensitive attributes (such as passwords, API keys, session tokens, or private identifiers), this function will inadvertently leak that data into logs or debug output. This constitutes a significant information leakage risk.
Remediation: When implementing custom representation methods (`__repr__`, `__str__`), developers must ensure that all attributes included in the returned string are non-sensitive. Implement explicit filtering or sanitization logic within `_debug_str()` to mask, redact, or exclude any data classified as confidential before it is logged or displayed.