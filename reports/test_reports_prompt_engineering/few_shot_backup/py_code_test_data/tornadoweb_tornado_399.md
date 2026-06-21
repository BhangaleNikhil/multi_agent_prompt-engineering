Vulnerability: Plaintext Transmission of Sensitive Data
Severity: High
CWE: CWE-319
Location: Line 2 (Comment and implementation logic)
Description: The code explicitly notes that the connection is established in plaintext (`# Always connect in plaintext`). By using raw sockets and connecting without mandatory encryption, any data transmitted over this stream (including credentials, session tokens, or private information) is vulnerable to interception via network sniffing or Man-in-the-Middle (MITM) attacks.
Remediation: The connection must be secured using Transport Layer Security (TLS) or Secure Sockets Layer (SSL). Instead of connecting raw sockets, the application should enforce the use of secure wrappers (e.g., using `ssl.wrap_socket` in Python) immediately upon connection establishment to ensure all data is encrypted before transmission.