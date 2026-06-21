Vulnerability: Resource Exhaustion / Denial of Service (DoS)
Severity: High
CWE: CWE-400
Location: Line 40
Description: The function reads the entire content of the file into memory (`data = file.read()`) before checking if a `Range` header is present and slicing the data. If an attacker requests a very large file (e.g., several gigabytes), this operation will attempt to load the entire file into the application's memory space, potentially leading to memory exhaustion and causing a Denial of Service (DoS) condition for the application.
Remediation: Implement streaming techniques. Instead of reading the entire file into a variable (`data`), the application should use chunked reading and write the content directly to the response stream. This ensures that memory usage remains constant regardless of the file size. When handling `Range` headers, the file should be read and streamed only for the requested byte range, avoiding the need to load the full file content into memory.