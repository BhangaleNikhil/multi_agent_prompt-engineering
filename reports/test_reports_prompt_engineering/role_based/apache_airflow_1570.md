## SAST Audit Report: Link Construction Function

**Target Artifact:** `def _build_link(match_obj):`
**Audit Focus:** Input Validation, Output Encoding, Cross-Site Scripting (XSS), and Trust Boundary Enforcement.
**Severity Assessment:** Critical/High

---

### Executive Summary

The provided function, `_build_link`, constructs HTML anchor tags (`<a>`) using data extracted from a regular expression match object. The primary vulnerability identified is **Stored or Reflected Cross-Site Scripting (XSS)** due to the direct inclusion of unsanitized user-controlled input (`url` and `text`) into the resulting HTML structure. Furthermore, while basic scheme validation is performed, the function fails to adequately sanitize the destination URL, introducing potential risks related to protocol handling and resource misuse.

### Detailed Vulnerability Analysis

#### 1. Cross-Site Scripting (XSS) via Unsanitized Attributes and Content (High Severity)

**Vulnerability:** The function constructs the HTML output using f-strings: `Markup(f'<a href="{url}">{text}</a>')`. Both the link text (`{text}`) and the URL attribute value (`href="{url}"`) are derived directly from inputs captured by a regular expression match object, which is assumed to originate from untrusted source material.

**Exploitation Vector:**
1. **Content Injection (Text):** If an attacker controls the input corresponding to `text`, they can inject malicious HTML or JavaScript payloads that will be rendered when the resulting link is displayed on the client side. Example payload: `<script>alert('XSS')</script>`.
2. **Attribute Injection (URL/Href):** While the code attempts scheme validation, an attacker could potentially craft a URL input that breaks out of the `href` attribute context or injects additional attributes if the underlying regex matching is flawed or if the browser interprets malformed HTML leniently. More critically, even if the payload doesn't execute immediately, it can lead to data exfiltration or session hijacking when the link is clicked.

**Impact:** Successful exploitation allows an attacker to execute arbitrary client-side scripts in the context of the application domain, leading to session hijacking, credential theft, and unauthorized actions on behalf of the victim user.

#### 2. Insufficient URL Validation and Protocol Handling (Medium Severity)

**Vulnerability:** The code validates that the scheme is either `http` or `https`. However, this validation only checks the prefix; it does not validate the content or structure of the hostname/path components within the `url` variable.

**Exploitation Vector:**
1. **Protocol Misuse (Data URI):** Although the explicit check filters out non-HTTP/S schemes, if the underlying regex matching is bypassed or modified, an attacker could potentially inject a `javascript:` scheme payload into the URL input, leading to immediate script execution upon link rendering or clicking. While the current code mitigates this specific vector, relying solely on prefix checking is insufficient for robust security.
2. **Resource Misuse (SSRF Potential):** If the application context allows the resulting links to be processed by backend services (e.g., a preview service), an attacker could use the link construction mechanism to point to internal network resources or cloud metadata endpoints, leading to Server-Side Request Forgery (SSRF).

### Remediation and Mitigation Strategy

The core principle of remediation must be **Context-Aware Output Encoding** for all user-supplied data before it is rendered into HTML. Input validation alone is insufficient; output encoding is mandatory.

#### Recommended Code Fixes:

1. **Mandatory Contextual Encoding:** The `text` variable (link content) and the `url` variable (attribute value) must be encoded immediately prior to inclusion in the f-string.
2. **Robust URL Sanitization:** Implement a dedicated, strict library function for URL sanitization that validates not only the scheme but also ensures the hostname conforms to expected standards and prevents injection of non-standard characters or protocols.

**Refactored Code Implementation (Conceptual):**

```python
from urllib.parse import urlparse
# Assume 'escape' is a robust HTML entity encoder function, 
# and 'sanitize_url' is a dedicated security utility.

def _build_link(match_obj):
    text = match_obj.group(1)
    url = match_obj.group(2)

    parsed_url = urlparse(url)
    
    # 1. Strict Scheme Validation and Sanitization
    if not (parsed_url.scheme == "http" or parsed_url.scheme == "https"):
        return escape(match_obj.group(0)) # Return original raw text if invalid scheme

    # 2. Sanitize the URL to ensure it is safe for use in an href attribute
    sanitized_url = sanitize_url(url) 
    if not sanitized_url:
         return escape(match_obj.group(0))

    # 3. Encode both content and attributes using context-aware encoding
    encoded_text = escape(text) # Encodes characters like <, >, &
    
    # Note: While the URL is validated, it must still be encoded for safety 
    # if any non-standard characters might pass validation.
    encoded_url = sanitize_attribute_value(sanitized_url)

    return Markup(f'<a href="{encoded_url}">{encoded_text}</a>')
```

**Engineering Directives:**

*   **Action 1 (Critical):** Replace the direct f-string concatenation with a mechanism that utilizes an established, secure HTML templating engine (e.g., Jinja2) which automatically handles context-aware escaping by default.
*   **Action 2 (High):** Implement `sanitize_url(url)` to perform deep validation, ensuring the URL structure is strictly limited to standard domain characters and rejecting any input that could potentially contain protocol handlers other than HTTP/HTTPS.

---

### Files for Which Issues Were Encountered During Processing

No files were provided in this audit artifact submission. Therefore, no analysis of processing issues can be performed.