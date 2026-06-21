Vulnerability: Regex Injection
Severity: High
CWE: CWE-1036
Location: Line 5
Description: The function constructs a regular expression pattern using the `payload` variable without proper escaping. Since the `payload` is inserted directly into the regex string (`"(%s.*?%s)" % (_, _)`), if an attacker provides input containing regex metacharacters (such as `.`, `*`, `+`, or `?`), they can modify the intended matching logic. This could allow them to bypass security filters, match unintended content, or potentially lead to a Denial of Service (ReDoS) attack if the payload creates a catastrophic backtracking pattern.
Remediation: Before using any user-supplied input (`payload`) within a regular expression pattern, it must be explicitly escaped using `re.escape()` to ensure that all metacharacters are treated as literal characters and not interpreted by the regex engine.