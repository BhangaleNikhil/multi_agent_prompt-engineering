Input File Path: (Not Provided - Assuming utility module)
Input Code:
def dataToStdout(data, forceOutput=False, bold=False, contentType=None, status=CONTENT_STATUS.IN_PROGRESS, coloring=True):
    """
    Writes text to the stdout (console) stream
    """

    if not IS_TTY and isinstance(data, six.string_types) and data.startswith("\r"):
        if re.search(r"\(\d+%\)", data):
            data = ""
        else:
            data = "\n%s" % data.strip("\r")

    if not kb.get("threadException"):
        if forceOutput or not (getCurrentThreadData().disableStdOut or kb.get("wizardMode")):
            multiThreadMode = kb.get("multiThreadMode")
            if multiThreadMode:
                logging._acquireLock()

            try:
                if conf.get("api"):
                    sys.stdout.write(stdoutEncode(clearColors(data)), status, contentType)
                else:
                    sys.stdout.write(stdoutEncode(setColor(data, bold=bold) if coloring else clearColors(data)))
            except IOError:
                pass
            except UnicodeEncodeError:
                sys.stdout.write(re.sub(r"[^ -~]", '?', clearColors(data)))
            finally:
                sys.stdout.flush()

            if multiThreadMode:
                logging._releaseLock()

            kb.prependFlag = isinstance(data, six.string_types) and (len(data) == 1 and data not in ('\n', '\r') or len(data) > 2 and data[0] == '\r' and data[-1] != '\n')

Expected Output:
Vulnerability: Potential Console/Terminal Injection (ANSI Escape Codes)
Severity: Medium
CWE: CWE-20
Location: Line 20 (sys.stdout.write calls)
Description: The function writes user-provided data (`data`) to the standard output stream. While the code attempts to sanitize colors and handle encoding errors, it relies on external functions (`clearColors`, `setColor`, `stdoutEncode`) which may not fully sanitize all possible control characters or ANSI escape sequences. If an attacker can inject malicious sequences (e.g., sequences that clear the screen, change terminal settings, or execute commands in advanced terminal environments), it could lead to a denial of service or information leakage.
Remediation: Implement strict validation and sanitization of all input data before writing it to the console. Specifically, ensure that the input data is stripped of all non-printable control characters and that color/formatting functions only accept whitelisted, safe inputs. If the output is intended for a specific terminal type, use a dedicated library that handles terminal output safely (e.g., `colorama` or similar platform-specific libraries) rather than raw string manipulation.