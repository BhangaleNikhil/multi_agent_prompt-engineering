Vulnerability: Command Injection
Severity: High
CWE: CWE-78
Location: Line 13
Description: The function executes an external system command (`stty size`) using `subprocess.Popen` with `shell=True`. Using `shell=True` is highly dangerous because it passes the command string to the system shell interpreter, allowing an attacker to inject arbitrary shell commands if any part of the command string were ever derived from untrusted input. While the current command is hardcoded, this pattern introduces a significant security risk and should be avoided.
Remediation: When using `subprocess.Popen`, always pass the command and its arguments as a list of strings and set `shell=False` (which is the default). This ensures that the operating system executes the command directly without involving the shell interpreter, preventing injection attacks.

Example of remediation:
Instead of:
`process = subprocess.Popen("stty size", shell=True, ...)`

Use:
`process = subprocess.Popen(["stty", "size"], stdout=subprocess.PIPE, stderr=FNULL or subprocess.PIPE)`