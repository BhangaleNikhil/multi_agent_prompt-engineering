Vulnerability: Resource Leakage / Improper Cleanup
Severity: Medium
CWE: CWE-400
Location: Line 12 (Thread start)
Description: The `setUp` method initializes and starts a background server thread (`self.server_thread`) and binds a network socket. If the test suite fails or completes without explicitly stopping this server and cleaning up the resources, it will lead to resource leakage (the port remains bound) or unpredictable state for subsequent tests running in the same process.
Remediation: Implement a corresponding `tearDown` method that is guaranteed to run after every test case. This teardown logic must gracefully stop the IOLoop (`self.server_ioloop.stop()`), wait for the server thread to finish (`self.server_thread.join()`), and close any associated sockets or resources used during setup.