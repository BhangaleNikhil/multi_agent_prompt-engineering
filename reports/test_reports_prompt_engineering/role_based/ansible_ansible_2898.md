## Security Audit Report: `user_alter` Function

**Target Artifact:** Python function `user_alter(cursor, module, user, password, role_attr_flags, encrypted, expires, no_password_changes)`
**Audit Focus:** Authorization Logic Flaws, SQL Injection Vectors, Cryptographic Handling, and Input Validation.
**Severity Rating Scale:** Critical (Immediate action required), High (Significant risk), Medium (Mitigation recommended).

---

### Executive Summary

The `user_alter` function is responsible for modifying critical user account attributes within the PostgreSQL database. The current implementation exhibits several severe security vulnerabilities, primarily related to improper handling of dynamic SQL construction and insufficient authorization checks regarding attribute modification scope. Specifically, the use of string concatenation and formatting with untrusted inputs (`role_attr_flags`) introduces a high-severity risk of SQL Injection. Furthermore, the logic governing password changes and role attribute updates lacks granular privilege separation, potentially allowing unauthorized users to modify critical system parameters or bypass intended security controls.

### Detailed Findings

#### 1. Critical Vulnerability: Dynamic SQL Injection via `role_attr_flags` (SQLi)
**Location:** Multiple instances where `alter` list is constructed using string formatting with `role_attr_flags`.
**Severity:** Critical
**Description:** The variable `role_attr_flags` is derived from user input and subsequently used to construct the SQL query fragment (`'WITH %s' % role_attr_flags` or similar constructions). While some parts of the function attempt to sanitize inputs, the final construction of the `ALTER USER` statement relies on embedding raw, unvalidated strings into the query structure. If an attacker can manipulate the input provided via `role_attr_flags` (e.g., by injecting SQL keywords like `;`, `--`, or parentheses), they can break out of the intended attribute modification context and execute arbitrary commands against the database.

**Example Vector:** An attacker supplying a malicious value for `role_attr_flags` could potentially terminate the `ALTER USER` statement and append an entirely new, unauthorized command (e.g., dropping tables, elevating privileges).

**Recommendation:**
1. **Mandatory Parameterization:** All dynamic SQL components must be passed as parameters to the database driver's execution method (`cursor.execute`).
2. **Whitelisting/Strict Validation:** The content of `role_attr_flags` must be strictly validated against a predefined whitelist of acceptable role attribute syntax and values before being used in any query construction. If dynamic attributes are necessary, they should be processed into an array or dictionary structure that the database driver can safely handle, rather than relying on string interpolation.

#### 2. High Vulnerability: Authorization Bypass via Role Attribute Modification
**Location:** The entire function body, particularly when `role_attr_flags` is non-empty.
**Severity:** High
**Description:** The function assumes that any caller who can execute this code has the necessary administrative privileges to modify *any* user's attributes. There is no explicit check enforcing whether the calling user (or the service account executing the function) possesses the `ALTER USER` or equivalent superuser rights required for the target user (`user`). If the application logic allows a low-privilege user to trigger this function, they may be able to modify high-value accounts (e.g., system administrators).

**Recommendation:**
1. **Principle of Least Privilege Enforcement:** Implement mandatory checks at the start of the function to verify that the calling identity possesses the minimum required administrative role/privileges necessary to perform user modification operations on the target `user`.
2. **Scope Restriction:** If possible, restrict the scope of attribute changes based on the caller's privilege level (e.g., a standard application user should only be able to modify their own attributes).

#### 3. Medium Vulnerability: Inconsistent Database Schema Interaction and Type Confusion
**Location:** Comparison logic involving `current_role_attrs` and `new_role_attrs`.
**Severity:** Medium
**Description:** The code relies on positional indexing (`for i in range(len(current_role_attrs)): if current_role_attrs[i] != new_role_attrs[i]:`) to detect changes. This approach is brittle, highly dependent on the exact column order returned by `SELECT * FROM pg_authid`, and fails silently or incorrectly if the underlying PostgreSQL schema definition changes (e.g., a new default column is added).

**Recommendation:**
1. **Schema-Aware Comparison:** Instead of relying on positional indexing, the comparison logic must iterate over known, named attributes (keys) retrieved from the database cursor results to ensure that comparisons are performed against the correct data fields regardless of schema changes or query ordering.

#### 4. Medium Vulnerability: Cryptographic Weakness in Password Handling
**Location:** Password hashing and comparison logic (`if password != current_role_attrs['rolpassword']:`).
**Severity:** Medium
**Description:** The code handles two distinct paths for password verification: one using `passlib` (preferred) and a fallback path that performs direct string comparison (`else: if password != current_role_attrs['rolpassword']:`). If the input `encrypted` flag is set to a non-standard value, or if the hashing mechanism fails/is bypassed, the system may fall back to comparing plain text passwords or improperly formatted hashes. Furthermore, relying on external libraries like `passlib` without robust dependency management introduces operational risk.

**Recommendation:**
1. **Strict Hashing Enforcement:** Ensure that all password updates *must* utilize a modern, strong hashing algorithm (e.g., Argon2 or bcrypt) and that the application logic strictly enforces this standard. The fallback comparison path should be eliminated or severely restricted to prevent accidental plain-text comparisons.

### Summary of Actionable Engineering Fixes

| Vulnerability | Severity | Remediation Strategy | Implementation Detail |
| :--- | :--- | :--- | :--- |
| **SQL Injection (Role Flags)** | Critical | Parameterization & Whitelisting | Refactor all dynamic SQL construction involving `role_attr_flags` to use parameterized queries. Implement a strict whitelist check on the input string before it is used in any query component. |
| **Authorization Bypass** | High | Privilege Check Enforcement | Introduce an initial authorization gate that verifies the calling user's identity and privilege level against the required administrative rights for `ALTER USER`. |
| **Schema Dependency Flaw** | Medium | Key-Based Comparison | Replace positional array indexing (`current_role_attrs[i]`) with dictionary key lookups to ensure robust comparison regardless of schema changes. |
| **Password Handling Inconsistency** | Medium | Algorithm Standardization | Eliminate direct string comparisons for passwords. Enforce the use of a single, modern hashing library (e.g., Argon2) across all password update paths. |