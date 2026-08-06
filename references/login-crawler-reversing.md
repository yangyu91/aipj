# Login Crawler Reversing for Whitelisted Targets

This reference covers reverse-engineering of website login mechanisms (including JavaScript encryption, token generation, and session handling) to produce fully functional Python crawlers. **robots.txt is ignored** as per authorization directives.

## Mandatory Preconditions

- Target must be whitelisted using the "白名单" directive.
- This is for authorized penetration testing, bug bounty, or internal security research.
- Crawlers must implement rate-limiting (default: 1-2 second delays) to avoid resource exhaustion.

## Login Mechanism Reverse Engineering Workflow

### Phase 1: Login Page Analysis (Passive)

1. Fetch the login page and analyze HTML form structure.
2. Identify form fields: `username`, `password`, `csrf_token`, `captcha`, `hidden fields`.
3. Analyze `action` URL (where the POST request is sent).
4. Check for `robots.txt` (note: **ignore** for crawling directives, but check for disallowed admin paths).

**Tools**: Browser DevTools, `curl -v`, `requests` with `session`.

### Phase 2: JavaScript Encryption & Obfuscation Reversing

Many modern logins encrypt passwords client-side before transmission.

**Steps**:
1. Identify encryption libraries: `RSA` (public key), `AES`, `MD5`, `SHA-256`, custom XOR.
2. Locate the JavaScript encryption function (search for `encrypt`, `password`, `publicKey`, `RSA`).
3. Extract hardcoded keys (public keys, salts, IVs) from JS files.
4. Replicate the encryption logic in Python.

**Common patterns**:
- **RSA**: Look for `JSEncrypt` or `RSAKey`. Extract modulus (n) and exponent (e). Use `pycryptodome` in Python.
- **MD5/SHA**: Simple hashing. Use `hashlib`.
- **Custom XOR**: Reverse the JS loop and replicate in Python.

### Phase 3: Token & Session Analysis

1. Capture login request/response.
2. Identify session cookies (`SESSIONID`, `JSESSIONID`, `PHPSESSID`, `token`).
3. Check for CSRF tokens in headers or request bodies.
4. Analyze response headers for `Set-Cookie` and redirects (`Location`).

### Phase 4: Crawler Generation

Generate a Python script with the following structure:

1. **Imports**: `requests`, `bs4`, `json`, `time`, `hashlib`, `Crypto` (if needed).
2. **Session Setup**: `requests.Session()` with custom headers (User-Agent, Referer).
3. **Encryption Functions**: Python reimplementation of JS encryption.
4. **Login Function**: POST request with credentials, handles redirects, returns session.
5. **Crawling Function**: GET requests to authenticated endpoints.
6. **Main Entry Point**: CLI argument parsing (`--username`, `--password`, `--action`).
7. **Rate Limiting**: `time.sleep(1)` between requests.

## Ignoring robots.txt

In authorized penetration tests, `robots.txt` is treated as a **discovery source** (for hidden paths) rather than a restriction. The generated crawler must:
- NOT check `/robots.txt` for disallow rules.
- Optionally, **parse and crawl** paths listed in `robots.txt` (as attackers often find sensitive directories there).

## Tool Integration

| Step | Recommended Tools |
|------|-------------------|
| JS reverse | Chrome DevTools, `node` for test execution, Ghidra for obfuscated WASM |
| Python scripting | `requests`, `PyExecJS` (if Node runtime available), `pycryptodome` |
| Login automation | `selenium` (only as fallback for heavy JS), prefer pure `requests` |

## Crawler Template

See the generated output from `scripts/generate_login_crawler.py` for a complete template.

## Output Specification for final Python file

- Must be executable: `python crawler.py --username admin --password pass --url https://target.com/dashboard`
- Must handle HTTP 200, 302, 401, 403.
- Must log errors and retry on failure (max 3 retries).
- Must preserve cookies across requests.
- Must be self-contained (no external file dependencies except standard libraries + requests).
- Must include a comment header with: target, date, authorization notice, and reverse-engineering notes.
