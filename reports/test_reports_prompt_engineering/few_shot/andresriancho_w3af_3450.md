Vulnerability: Parameter Injection
Severity: Medium
CWE: CWE-79
Location: Line 3
Description: The code constructs URLs using standard Python string formatting (`%s`) to embed parameters. While the current test case uses controlled integer inputs, if this pattern were applied in production code where `id` or `bar` are derived from unsanitized user input (e.g., HTTP request parameters), an attacker could inject characters such as `&`, `=`, or path separators. This allows them to modify the intended query structure, potentially bypassing authorization checks or accessing unintended resources.
Remediation: Always use dedicated URL building libraries, such as Python's `urllib.parse` module (specifically `urlencode`), when constructing URLs from user-supplied data. These libraries automatically handle proper URL encoding and ensure that input values are treated strictly as data parameters, preventing structural injection attacks.