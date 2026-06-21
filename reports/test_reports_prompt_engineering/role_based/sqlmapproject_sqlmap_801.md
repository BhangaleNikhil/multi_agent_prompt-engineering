## Security Audit Report: `_oneShotUnionUse` Function

**Target Artifact:** Python function `_oneShotUnionUse(expression, unpack=True, limited=False)`
**Audit Focus:** Deep-seated logical vulnerabilities, injection risks, data integrity flaws, and resource management weaknesses.
**Assessment Level:** Critical/High Impact

---

### Executive Summary

The analyzed function, `_oneShotUnionUse`, is a highly specialized utility designed to execute complex SQL injection payloads (specifically UNION-based techniques). Due to its nature, the code handles multiple stages of untrusted input (`expression`) and constructs database queries using various internal components (`agent.concatQuery`, `agent.forgeUnionQuery`).

The primary security concern revolves around insufficient sanitization and improper handling of concatenated user-supplied data when constructing the final SQL query structure. While several escaping mechanisms are employed, their application is inconsistent across different code paths (e.g., JSON aggregation mode vs. standard mode), creating exploitable blind spots for advanced injection techniques.

### Detailed Vulnerability Analysis

#### 1. Injection Flaws (SQL/Data Manipulation)

**Vulnerability ID:** SAST-001
**Severity:** High
**Description:** The function exhibits multiple points where user-supplied input (`expression`) is incorporated into the final SQL query structure with insufficient or context-dependent sanitization, leading to potential SQL injection vulnerabilities.

**Analysis:**
The core vulnerability lies in how `injExpression` is generated and subsequently used within `agent.forgeUnionQuery`. While the code attempts to sanitize inputs using `unescaper.escape(expression)` or `unescaper.escape(agent.concatQuery(expression, unpack))`, this escaping mechanism may be incomplete or contextually incorrect for all database dialects (MSSQL, PGSQL) and payload types.

*   **Path 1: Standard Mode (`if not kb.jsonAggMode`)**:
    The expression is processed via `injExpression = unescaper.escape(agent.concatQuery(expression, unpack))`. If the underlying `unescaper` function only handles basic string literals (e.g., single quotes) but fails to account for dialect-specific escape sequences, comments (`--`, `#`), or character encoding bypasses, an attacker can inject arbitrary SQL logic into the query structure.
*   **Path 2: JSON Aggregation Mode (`if kb.jsonAggMode`)**:
    The expression is processed via `injExpression = unescaper.escape(expression)`. This path relies solely on escaping the raw input before passing it to `agent.forgeUnionQuery`. If the payload structure allows for injection *outside* of the primary data field (e.g., affecting column selection or WHERE clause logic), this sanitization is insufficient.

**Impact:** An attacker can manipulate the query construction, potentially bypassing intended filtering mechanisms, extracting unauthorized data, modifying database state (if permissions allow), or achieving blind SQL injection outcomes.

#### 2. Data Flow and Sanitization Flaws

**Vulnerability ID:** SAST-002
**Severity:** Medium
**Description:** The logic for handling the `WHERE` clause (`where`) is inconsistent and potentially allows unsanitized, user-controlled input to dictate query constraints, which can be leveraged in conjunction with injection flaws.

**Analysis:**
The determination of the `where` clause depends on complex conditional logic:
1.  If `conf.limitStart` or `conf.limitStop` are set, `where = PAYLOAD.WHERE.NEGATIVE`. (Controlled by configuration).
2.  Otherwise, `where = vector[6]`. (Hardcoded payload component).

However, the function also contains logic that modifies the original `expression` and recursively calls itself (`_oneShotUnionUse(expression, unpack, limited)`), specifically when attempting to recover from failed queries (e.g., removing `ORDER BY` or disabling NCHAR casting). In these recursive paths, the modified `expression` is used again in subsequent query constructions without re-evaluating its sanitization status against the current execution context, potentially leading to a state where previously sanitized input becomes unsanitized and exploitable.

**Impact:** Allows an attacker who can trigger specific failure modes (e.g., length limits or syntax errors) to force the function into a recursive path that uses partially cleaned or manipulated inputs in subsequent queries, facilitating injection bypasses.

#### 3. Resource Management and Denial of Service (DoS) Potential

**Vulnerability ID:** SAST-003
**Severity:** Medium
**Description:** The repeated use of `extractRegexResult` combined with complex string manipulation and JSON parsing within the result processing logic creates a potential for resource exhaustion, particularly when handling large or malformed database outputs.

**Analysis:**
The code block responsible for extracting results (especially in `kb.jsonAggMode`) involves multiple layers of regex extraction (`r"%s(?P<result>.*)%s"`, `r"{(?P<result>[^}]+)}"`), followed by JSON deserialization (`json.loads(output)`).

If the underlying database returns an extremely large result set, or if the data contains maliciously crafted strings that cause regex backtracking issues (ReDoS), the function can consume excessive CPU and memory resources, leading to a Denial of Service condition for the application service. The lack of explicit resource limits on input size or processing time exacerbates this risk.

**Impact:** An attacker could submit payloads designed to trigger computationally expensive regex operations or process massive data volumes, effectively locking up the underlying service thread.

### Recommendations and Remediation Plan

The following recommendations are mandatory engineering fixes required to mitigate the identified risks.

#### R-SAST-001: Implement Context-Aware Parameterization (Critical)
**Action:** Eliminate all instances of direct string concatenation using user input (`expression`) into SQL query construction logic.
**Implementation Detail:** The `agent.forgeUnionQuery` function must be refactored to accept parameters as a structured list or dictionary, allowing the underlying database driver to handle parameter binding and escaping natively. If native parameterization is impossible due to the nature of UNION queries, implement a robust, dialect-specific SQL parser that validates every character in the `expression` against an allowlist (e.g., alphanumeric characters, specific operators) before construction.

#### R-SAST-002: Enforce Strict Input Validation and State Management
**Action:** Isolate and validate all inputs used in recursive or conditional execution paths.
**Implementation Detail:** When the function detects a failure condition that triggers a retry (e.g., removing `ORDER BY` clause), the modified `expression` must be treated as entirely new, untrusted input. The sanitization process applied to the original `expression` must be re-run on the modified version before it is used in the subsequent call to `_oneShotUnionUse`.

#### R-SAST-003: Resource Guardrails and Input Limiting
**Action:** Implement explicit resource limits on data processing.
**Implementation Detail:**
1.  Introduce a maximum allowed size limit (e.g., 1MB) for the raw output received from `Request.queryPage`. If the output exceeds this threshold, truncate it and log a warning instead of attempting full parsing.
2.  Implement time-based execution limits or use asynchronous processing queues to prevent single requests from monopolizing CPU resources due to complex regex operations (ReDoS mitigation).

### Conclusion

The function `_oneShotUnionUse` represents a high-risk component within the application's security architecture. While it performs sophisticated payload handling, its reliance on string manipulation and inconsistent sanitization across different execution paths introduces critical SQL injection vulnerabilities. Immediate refactoring to utilize parameterized queries and robust input validation is required before deployment.