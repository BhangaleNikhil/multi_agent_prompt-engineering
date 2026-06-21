Vulnerability: Regex Denial of Service (ReDoS)
Severity: High
CWE: CWE-400
Location: Line 3
Description: The router processes a list of rules (`rules`), which contain path patterns. If the underlying path matching mechanism (likely within `self.add_rules` or the `Rule` object) uses regular expressions derived from or influenced by user-supplied input, it is susceptible to Regex Denial of Service (ReDoS). An attacker can provide a path pattern that forces the regex engine into catastrophic backtracking, consuming excessive CPU resources and potentially causing the application to hang or crash.
Remediation: When implementing path matching, ensure that all regular expressions are rigorously validated and constrained. Use specialized libraries or techniques that limit the complexity and backtracking depth of the regex engine. If possible, use simple string matching or dedicated path parsing functions instead of general-purpose regex for core routing logic.