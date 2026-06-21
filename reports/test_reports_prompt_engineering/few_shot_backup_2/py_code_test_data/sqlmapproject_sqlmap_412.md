Vulnerability: Information Leakage via Exception Handling
Severity: High
CWE: CWE-209
Location: Lines 145 - 238 (The final generic `except:` block)
Description: The code utilizes a broad, catch-all `except:` block which captures all unhandled exceptions. Within this block, it calls `traceback.format_exc()` and prints the full stack trace (`excMsg`) to standard output/logger. While detailed logging is useful for developers, exposing raw stack traces