Vulnerability: Architectural Flaw / Use of Deprecated Functionality
Severity: Medium
CWE: CWE-416
Location: Line 14
Description: The method relies on calling `self._oauth_get_user`, which the docstring explicitly notes is the "old-style" method and advises that new code should override the method instead. Relying on deprecated or older functionality increases the risk surface because the old method may contain unpatched security flaws, lack modern security features (like robust error handling or rate limiting), or fail to adhere to current OAuth best practices.
Remediation: Refactor the code to eliminate the fallback mechanism. If the functionality provided by `_oauth_get_user` is necessary, it must be updated and secured to meet current standards. If the new method is intended to replace the old one, the call to the deprecated method should be removed entirely, forcing subclasses to implement the modern, secure logic.