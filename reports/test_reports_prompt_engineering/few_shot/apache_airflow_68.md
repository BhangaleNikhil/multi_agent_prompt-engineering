Vulnerability: Command Injection
Severity: Critical
CWE: CWE-78
Location: Line 3 (and subsequent usage of `pig`)
Description: The code handles command strings (`pig`) that are intended to be executed by a shell environment. If the variable `pig` or any component used to construct it (such as `TEST_TASK_ID`, if it were user-controlled) is derived from untrusted external input, an attacker can inject arbitrary operating system commands using shell metacharacters (e.g., `;`, `&&`, `|`). This allows for Remote Code Execution (RCE).
Remediation: Never pass unsanitized or unvalidated user input directly to a function that executes shell commands. If command execution is absolutely necessary, use strict whitelisting of allowed characters and inputs. Alternatively, if the system only needs to execute specific program arguments, use APIs that bypass the full shell interpreter (e.g., passing arguments as a list/array rather than a single concatenated string).