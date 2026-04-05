# SecureCheck — CLI Security Toolkit

#### Video Demo: <URL HERE>

#### Description:

SecureCheck is a command-line security toolkit built in Python that performs three essential security checks on a given host, URL, or password, and generates a professional PDF report of the findings. It was built as the final project for CS50P and demonstrates practical usage of networking, HTTP, regex validation, and PDF generation in Python.

---

## What It Does

SecureCheck accepts input via command-line flags and runs up to three independent security checks depending on what the user provides:

1. **Port Scanning** — checks a host for open network ports
2. **HTTP Header Analysis** — checks a URL for missing security headers
3. **Password Strength Scoring** — scores a password based on complexity rules

After running the checks, it generates a PDF report called `report.pdf` summarizing all findings.

---

## How To Run It

```
pip install -r requirements.txt
python project.py --host github.com --url https://github.com --password MyPass@123
```

You can run any combination of flags — all three, just one, or any two:

```
python project.py --password MyPass@123
python project.py --host github.com
python project.py --url https://github.com --password Hello@99
```

---

## Files

### `project.py`

The main program file containing all functions:

**`main()`** — Sets up argument parsing using `argparse`, collects `--host`, `--url`, and `--password` flags, validates them, runs the checks, and passes all results to `generate_report()`.

**`validate_input(host, url, password)`** — Validates all three inputs using regex before any network calls are made. A host must be a valid domain name or IPv4 address. A URL must start with `http://` or `https://`. A password just needs to be non-empty (strength is checked separately). Calls `sys.exit()` if invalid input is provided.

**`scan_ports(host)`** — Uses Python's built-in `socket` module to attempt connections on 12 well-known ports (FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, MySQL, PostgreSQL, HTTP alternate, HTTPS alternate, MongoDB). Returns a dictionary of open ports and their service names. Sets a 1-second timeout per port to keep things fast.

**`check_headers(url)`** — Uses the `requests` library to fetch the URL and inspect its HTTP response headers. Checks for 10 important security headers including `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, and others. Returns a list of headers that are missing.

**`password_strength(password)`** — Scores a password out of 6 points based on: presence of uppercase letters, lowercase letters, digits, special characters, starting with a letter, and minimum length of 8. Returns a tuple of `(score, label)` where label is `"Weak"`, `"Moderate"`, or `"High"`.

**`generate_report()`** — Takes all results and builds a formatted A4 PDF using `fpdf2`. Each section only appears if the corresponding input was provided. Open ports are displayed in a table. Missing headers are listed numerically. Password score and strength label are displayed clearly.

### `test_project.py`

Contains four pytest functions that test the core functions of the project:

- `test_input()` — Tests valid inputs return correct tuples, and invalid inputs trigger `SystemExit`.
- `test_password_strength()` — Tests weak, moderate, high, and empty password cases.
- `test_check_headers()` — Tests that a real URL returns a list and empty input returns `None`.
- `test_scan_ports()` — Tests that a real host returns a dict and empty input returns `None`.

### `requirements.txt`

Lists all third-party libraries required:
- `requests` — HTTP requests for header checking
- `fpdf2` — PDF generation

---

## Design Choices

**Why `argparse` instead of `input()`?** Professional CLI tools use flags, not interactive prompts. `argparse` makes the tool scriptable and composable — you can pipe it into other tools or automate it.

**Why separate validation from the checks?** `validate_input()` runs before any network calls. This avoids wasting time on a slow port scan only to fail on a bad input at the end. Fail fast, fail early.

**Why return `None` for empty inputs instead of raising exceptions?** Since all three flags are optional, functions need a clean way to signal "this check wasn't requested." `None` is falsy in Python, making it easy to conditionally build the PDF sections.

**Why `socket` and not a third-party port scanner?** `socket` is built into Python — no extra dependency. It's also more transparent and educational. The timeout of 1 second per port keeps total scan time reasonable for 12 ports.

**Why not show the password in the report?** Displaying a user's password in a PDF is a security risk — the file could be shared or stored. The report only shows the score and strength label, not the actual password.

**Why `fpdf2` over other PDF libraries?** It's lightweight, pure Python, and has a simple API that's easy to learn. It was already used in the course (Shirtificate problem), so extending that knowledge made sense.

---

## What I Learned

This project introduced several concepts not covered directly in the CS50P lectures:

- `socket` — Python's networking library for low-level TCP connections
- `argparse` — professional CLI argument parsing with flags and help text
- Basic cybersecurity concepts — open ports, HTTP security headers, password complexity
- Structuring a multi-function program where each function has one clear responsibility

---

## Requirements

```
requests
fpdf2
```

Install with:
```
pip install -r requirements.txt
```
