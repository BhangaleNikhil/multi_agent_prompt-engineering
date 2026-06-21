Vulnerability: Information Leakage / Credential Exposure
Severity: High
CWE: CWE-200
Location: Lines 70, 72
Description: The class accepts and stores sensitive credentials, specifically `auth_password` and `proxy_password`, as plain instance attributes. Storing passwords directly in memory attributes makes them highly susceptible to exposure through memory dumps, debugging tools, or accidental logging/serialization of the object state.
Remediation: Credentials should never be stored in plain text within an object's state if they are not strictly necessary for the object's lifecycle. If storage is required, consider using secure memory handling techniques, or, ideally, passing credentials only to the underlying network client library at the point of use, rather than storing them as persistent attributes. For logging, ensure these attributes are masked or redacted.