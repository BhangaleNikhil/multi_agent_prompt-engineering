Vulnerability: Cross-Site Scripting (XSS)
Severity: High
CWE: CWE-79
Location: Line 10
Description: The function constructs an HTML anchor tag by embedding user-controlled data (`text` and `url`) directly into f-strings. If the input `text` contains malicious characters (e.g., `<script>alert(1)</script>` or unencoded quotes), these inputs will be rendered as executable code in the browser, leading to a Cross-Site Scripting vulnerability. The lack of explicit HTML entity encoding for both `text` and `url` is the primary flaw.
Remediation: Never construct HTML using f-strings with user input. Instead, utilize a robust templating engine (like Jinja2 or Django templates) that automatically performs contextual output escaping by default. If manual construction is unavoidable, ensure that all variables inserted into the HTML structure are explicitly escaped for their specific context (HTML content vs. attribute value).