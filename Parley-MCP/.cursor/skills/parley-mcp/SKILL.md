---
name: parley-mcp
description: Operate the Parley-MCP penetration testing proxy. Use when intercepting, analyzing, or modifying TCP/TLS network traffic, performing security testing, capturing credentials, inspecting application protocols, or writing traffic modification modules.
---

# Parley-MCP Proxy Skill

Parley-MCP gives you full control of a multi-threaded TCP/TLS proxy via 14 MCP tools.
All traffic is captured to SQLite3. You write Python modules that modify traffic on-the-fly
for penetration testing — because protocols move fast and have timeouts, so modifications
must happen programmatically in the data stream, not manually.

## Core Workflow

```
1. proxy_start       → launch proxy, get instance_id
2. generate traffic  → route client through localhost:listen_port
3. traffic_query     → observe the raw protocol (understand it first!)
4. module_create     → write code to modify traffic on-the-fly
5. traffic_clear     → clean slate
6. re-test           → generate traffic again (now modified by modules)
7. traffic_query(show_modified=True) → verify modifications worked
8. iterate           → update modules, re-test, analyze
9. proxy_stop        → done
```

**For web/browser testing**, skip most of the above and use the one-call setup:

```
1. web_proxy_setup(target_domain="example.com", listen_port=8080)
2. Open browser to http://127.0.0.1:8080
3. traffic_query / traffic_search to analyze
4. module_create for any site-specific tweaks
5. proxy_stop when done
```

## Tool Quick Reference

### Web Proxy (One-Call Setup)

```
# Complete web proxy with all rewriting — just open the URL it returns
web_proxy_setup(target_domain="example.com", listen_port=8080)
```

### Proxy Lifecycle (Manual Setup)

```
# Plain TCP
proxy_start(target_host="10.0.0.5", target_port=80, listen_port=8080)

# TLS to server, plain to client (most common for web testing)
proxy_start(target_host="api.example.com", target_port=443,
            use_tls_server=True, no_verify=True, listen_port=8080)

# Full TLS both sides
proxy_start(target_host="api.example.com", target_port=443,
            use_tls_server=True, use_tls_client=True,
            certfile="server.crt", keyfile="server.key", listen_port=8443)
```

Returns an **instance_id** (8-char hex) — use it for everything else.

- `proxy_stop(instance_id)` — stop; captured data is preserved
- `proxy_list()` — all instances with status
- `proxy_status(instance_id)` — detailed stats

### Traffic Analysis

| Tool | Purpose |
|------|---------|
| `traffic_query(instance_id, decode_as, direction, connection_id, show_modified, order, limit, offset)` | Read captured messages |
| `traffic_search(instance_id, pattern)` | Find text in message data |
| `traffic_summary(instance_id)` | Counts, volumes, timing |
| `traffic_connections(instance_id)` | List connections |
| `traffic_clear(instance_id)` | Wipe data for clean re-test |

`decode_as` options: `utf8` (text protocols), `hexdump` (binary), `hex`, `repr`, `base64`.

### Module Management

| Tool | Purpose |
|------|---------|
| `module_create(name, direction, code, description, instance_id, priority, enabled)` | Create module |
| `module_update(module_id, code, ...)` | Update code/config |
| `module_set_enabled(module_id, bool)` | Toggle on/off |
| `module_delete(module_id)` | Remove |
| `module_list()` | Show all modules |

---

## Writing Traffic Modification Modules

This is the most important capability. Modules are Python code that intercept and
rewrite traffic in real-time as it flows through the proxy. You MUST understand
how they work to use Parley-MCP effectively.

### The Module Function Contract

Every module must define exactly this function:

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Your logic here
    return message_data
```

**Parameters explained:**

| Parameter | Type | Meaning |
|-----------|------|---------|
| `message_num` | `int` | Sequential counter per connection per direction (1, 2, 3...). Use to target specific messages (e.g., only modify the 1st request). |
| `source_ip` | `str` | IP of the sender. For client direction: the client's IP. For server direction: the server's IP. |
| `source_port` | `int` | Port of the sender. |
| `dest_ip` | `str` | IP of the receiver. |
| `dest_port` | `int` | Port of the receiver. |
| `message_data` | `bytearray` | **The actual traffic bytes.** This is what you inspect and modify. |

**Return value:** You MUST return the data to forward. Return `message_data` unchanged
for passthrough, or return a modified `bytearray`/`bytes` to alter what the other side receives.

### Direction: Which Side Are You Modifying?

This is critical to get right.

- **`direction="client"`** — Your module sits between the client and server, processing
  data the **client sends** before the **server sees it**. Use this to modify requests:
  swap auth tokens, change parameters, inject headers, tamper with POST bodies.

- **`direction="server"`** — Your module processes data the **server sends** before
  the **client sees it**. Use this to modify responses: alter status codes, change
  response bodies, strip security headers, inject content.

```
Client  ──[client modules]──►  Server
Client  ◄──[server modules]──  Server
```

### The Pipeline: Modules Chain Together

Multiple modules execute **in priority order** (lower number = runs first).
Each module's output becomes the next module's input:

```
Raw data → Module A (priority 10) → Module B (priority 50) → Module C (priority 100) → Forwarded
```

Use this to separate concerns:
- Priority 10: Logging/observation module (read-only, returns data unchanged)
- Priority 50: Authentication modification
- Priority 100: Body content tampering

### The Observe-Then-Modify Approach

**Never write a module blindly.** Always follow this process:

1. **Start the proxy and capture traffic** without any modules
2. **Use `traffic_query`** to read the actual protocol data
3. **Understand the byte patterns** — where are headers? delimiters? length fields?
4. **Then write a targeted module** based on what you actually saw
5. **Use `traffic_query(show_modified=True)`** to verify your changes worked
6. **Iterate with `module_update`** — don't delete and recreate

### Gotchas That Will Break Things

**HTTP Content-Length:** If you change the size of an HTTP body, you MUST update
the `Content-Length` header to match, or the receiver will read wrong:

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    if b'Content-Length:' not in data:
        return message_data

    # Split headers from body
    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    # Modify the body
    body = body.replace(b'"role":"user"', b'"role":"admin"')

    # Recalculate Content-Length
    headers = re.sub(
        rb'Content-Length: \d+',
        b'Content-Length: ' + str(len(body)).encode(),
        headers
    )
    return bytearray(headers + b'\r\n\r\n' + body)
```

**Binary protocol length fields:** Many binary protocols encode message length
in the first 2-4 bytes. If you change the payload size, update the length field:

```python
import struct
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Example: 4-byte big-endian length prefix
    if len(message_data) < 4:
        return message_data
    payload = message_data[4:]
    payload = payload.replace(b'\x00\x01', b'\x00\xFF')  # modify payload
    new_length = struct.pack('>I', len(payload))
    return bytearray(new_length + payload)
```

**Chunked Transfer-Encoding:** Don't just search/replace in chunked HTTP bodies —
the chunk size headers will be wrong. Reassemble first if you need to modify.

**Only modify what you target:** Use `if` conditions to avoid corrupting unrelated
messages. Check for protocol markers before modifying:

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # ONLY modify HTTP POST requests, leave everything else alone
    if not message_data.startswith(b'POST '):
        return message_data
    # ... safe to modify now
    return message_data
```

**message_data is a bytearray:** You can modify it in-place or create a new one.
Both work. Always return something — returning `None` will break the pipeline.

### Pentest Module Recipes

For detailed examples of pentest-focused modules, see [module-recipes.md](module-recipes.md).

## Web Proxy Setup (Browser Through Proxy)

### The Easy Way: `web_proxy_setup`

For browser-based web testing, use the single-call convenience tool:

```
web_proxy_setup(target_domain="example.com", listen_port=8080)
```

This creates the proxy AND deploys battle-tested client/server rewriting modules
that handle everything automatically. Just point your browser at the returned URL.

**What it handles out of the box:**
- Header rewriting: Host, Origin, Referer (case-insensitive matching)
- Stateful header buffering (handles headers split across TLS records)
- Chunked transfer-encoding de-chunking (prevents body corruption)
- Cookie fixing: strips `domain=`, `Secure`, fixes `SameSite`
- Cache busting on both client and server sides
- Security header stripping: HSTS, CSP, X-Frame-Options, Permissions-Policy
- URL rewriting in HTML/JS/CSS bodies (both `domain.com` and `www.domain.com`)
- JavaScript domain variable patching (`COOKIE_DOMAIN`, `cbDomainName`)
- Anti-hotlinking/referrer-check bypass
- Decompression (gzip, deflate)
- Forces `Connection: close` (required since chunked encoding is stripped)

**When you need more:** Add custom modules with `module_create` for site-specific
issues. Common additions:
- Rewriting additional subdomains (CDN, API endpoints)
- Modifying authentication tokens or POST bodies
- Handling site-specific JavaScript redirects or checks

### The Manual Way

If `web_proxy_setup` doesn't fit (e.g., non-standard port, custom TLS config,
or you need fine-grained control), you can set up modules manually. The issues
you must address:

**Client → Server problems:**
- `Host` header says `127.0.0.1:8080` instead of the real hostname (servers return 404)
- `Origin` and `Referer` headers have the proxy address (CORS/CSRF checks fail)
- `Accept-Encoding: gzip, br` causes compressed responses you can't read
- `Upgrade-Insecure-Requests` causes redirect loops
- Cache headers (`If-None-Match`, `If-Modified-Since`) cause empty 304 responses

**Server → Client problems:**
- `Location` redirects point to the real domain (browser escapes the proxy)
- `Set-Cookie` has `domain=`, `Secure`, `SameSite=None` flags that break on localhost
- HSTS, CSP, X-Frame-Options headers block things you need for testing
- HTML/JS/CSS contain absolute URLs to the real domain (links escape the proxy)
- Chunked Transfer-Encoding: modifying body content breaks chunk sizes
- Headers may span multiple TLS records (must buffer before processing)
- JavaScript `COOKIE_DOMAIN` and similar variables need patching
- Anti-hotlinking scripts check `window.location` against domain whitelists

**Critical lessons for manual module writing:**
- **Always use `re.IGNORECASE`** — servers may send headers in any case
- **Server modules must be stateful** — buffer until `\r\n\r\n` to get complete headers
- **Strip `Transfer-Encoding: chunked`** and de-chunk the body yourself, or body
  modifications will corrupt chunk sizes and the browser shows a blank page
- **Strip `Content-Length`** after de-chunking (you don't know the final size)
- **Force `Connection: close`** on both sides so the browser knows when the response ends
- **Replace URL patterns AND bare domain strings** in JS (`COOKIE_DOMAIN`, etc.)

For complete ready-to-use manual module examples, see [web-rewriting-guide.md](web-rewriting-guide.md).

## Automating Login Flows for Testing

After capturing a login flow through the proxy, you can build a standalone Python script
to replay it programmatically. This is essential for automated penetration testing — it
lets you authenticate quickly without a browser and then run targeted tests against
authenticated endpoints.

### How to Analyze a Captured Login

Use `traffic_search` and `traffic_query` to find the login flow:

```
1. traffic_search(instance_id, pattern="POST")        → find the login POST
2. traffic_query(instance_id, connection_id=N, show_modified=True) → see full request/response
3. traffic_search(instance_id, pattern="login")        → find login page and related URLs
```

Look for this typical pattern:

```
Step 1: GET /login-page      → HTML with form + hidden CSRF token
Step 2: POST /auth-endpoint   → form-urlencoded with credentials + token
Step 3: JSON response         → {"success":true} + Set-Cookie with session token
Step 4: GET /                 → authenticated request using session cookie
```

### Key Elements to Extract

From the **login page HTML** (GET response):
- **Hidden form fields**: CSRF tokens, nonces, anti-replay values (look for `<input type="hidden">`)
- **Form action URL**: The POST endpoint (may be relative or absolute)
- **Required cookies**: The GET response often sets prerequisite cookies via `Set-Cookie`

From the **login POST request**:
- **Content-Type**: Usually `application/x-www-form-urlencoded` or `application/json`
- **POST body fields**: All form parameters (credentials + hidden fields)
- **Required headers**: Origin, Referer, X-Requested-With, custom headers
- **Cookies**: Session cookies that must be present for the POST to succeed

From the **login response**:
- **Session token**: Usually in a `Set-Cookie` header (the critical auth cookie)
- **Response body**: JSON with success/failure status, redirect URL, user info
- **Additional cookies**: May set multiple cookies needed for subsequent requests

### Script Template

```python
"""
Login automation script generated from Parley-MCP traffic capture.

Usage:
    python login_test.py
    python login_test.py --email user@example.com --password secret

The script authenticates and then performs a test request to verify
the session is valid. Extend it with additional authenticated requests
for your testing needs.
"""

import requests
import re
import sys
import argparse
from urllib.parse import urljoin

# ============================================================
# Configuration — extracted from traffic capture
# ============================================================
BASE_URL = "https://www.example.com"
LOGIN_PAGE_PATH = "/login"             # GET this to obtain CSRF token
AUTH_ENDPOINT = "/api/authenticate"     # POST credentials here
TEST_PAGE_PATH = "/dashboard"          # GET this to verify auth works

# Default test credentials (override via command line)
DEFAULT_EMAIL = "test@example.com"
DEFAULT_PASSWORD = "testpassword"

# Headers that the server expects (extracted from captured request)
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/144.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}


def get_csrf_token(session):
    """Step 1: Fetch login page and extract CSRF token from HTML."""
    resp = session.get(
        urljoin(BASE_URL, LOGIN_PAGE_PATH),
        headers=COMMON_HEADERS
    )
    resp.raise_for_status()

    # Extract hidden token field — adjust regex to match the actual HTML
    # Common patterns:
    #   <input type="hidden" name="token" value="..."/>
    #   <meta name="csrf-token" content="..."/>
    #   var csrfToken = '...';
    match = re.search(
        r'<input[^>]*name="token"[^>]*value="([^"]*)"', resp.text
    )
    if not match:
        # Try alternate patterns
        match = re.search(
            r'<meta[^>]*name="csrf-token"[^>]*content="([^"]*)"', resp.text
        )
    if not match:
        print("[!] Could not find CSRF token in login page")
        print(f"    Response length: {len(resp.text)} bytes")
        print(f"    Status: {resp.status_code}")
        sys.exit(1)

    token = match.group(1)
    print(f"[+] Got CSRF token: {token[:40]}...")
    return token


def authenticate(session, email, password, token):
    """Step 2: POST credentials to the authentication endpoint."""
    # Build the POST body — match exactly what the browser sent
    post_data = {
        "email": email,
        "password": password,
        "token": token,
        "redirect": "",
        "from": "pc_login",           # site-specific field
        "segment": "straight",         # site-specific field
    }

    auth_headers = {
        **COMMON_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": BASE_URL,
        "Referer": urljoin(BASE_URL, LOGIN_PAGE_PATH),
        "X-Requested-With": "XMLHttpRequest",  # if the site expects AJAX
    }

    resp = session.post(
        urljoin(BASE_URL, AUTH_ENDPOINT),
        data=post_data,
        headers=auth_headers,
    )
    resp.raise_for_status()

    # Parse the response — most login APIs return JSON
    try:
        result = resp.json()
    except ValueError:
        print(f"[!] Non-JSON response: {resp.text[:200]}")
        sys.exit(1)

    # Check for success — field name varies by site
    if result.get("success") == "1" or result.get("success") is True:
        print(f"[+] Login successful! User: {result.get('username', 'unknown')}")
        return result
    else:
        print(f"[!] Login failed: {result.get('message', result)}")
        sys.exit(1)


def verify_session(session):
    """Step 3: Make an authenticated request to verify the session."""
    resp = session.get(
        urljoin(BASE_URL, TEST_PAGE_PATH),
        headers=COMMON_HEADERS,
    )
    print(f"[+] Auth test: {resp.status_code} - {len(resp.text)} bytes")

    # Check for signs of authentication
    if "logout" in resp.text.lower() or "sign out" in resp.text.lower():
        print("[+] Session is authenticated (found logout link)")
    elif resp.status_code == 302:
        print(f"[!] Redirected to: {resp.headers.get('Location', '?')}")
    return resp


def main():
    parser = argparse.ArgumentParser(description="Automated login test")
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    args = parser.parse_args()

    # Use a session to persist cookies across requests
    session = requests.Session()

    # Optional: set prerequisite cookies if needed
    # session.cookies.set("platform", "pc", domain="www.example.com")

    print(f"[*] Target: {BASE_URL}")
    print(f"[*] Fetching login page...")
    token = get_csrf_token(session)

    print(f"[*] Authenticating as {args.email}...")
    result = authenticate(session, args.email, args.password, token)

    print(f"[*] Verifying session...")
    verify_session(session)

    # Print session cookies for debugging
    print(f"\n[*] Session cookies:")
    for cookie in session.cookies:
        print(f"    {cookie.name} = {cookie.value[:50]}...")

    # === Add your authenticated test requests below ===
    # resp = session.get(urljoin(BASE_URL, "/api/private/endpoint"))
    # print(resp.json())


if __name__ == "__main__":
    main()
```

### Adapting the Script from Traffic Capture

When building this script from a real capture, follow these steps:

1. **Set `BASE_URL`** to the target's real HTTPS URL (not the proxy address)
2. **Set paths** from the captured URLs (e.g., `/login`, `/api/authenticate`)
3. **Match POST fields exactly** — copy field names and static values from the capture
4. **Match required headers** — some servers check Origin, Referer, X-Requested-With
5. **Handle the CSRF token regex** — view the login page HTML in the capture to find
   the exact `<input>` or `<meta>` tag pattern
6. **Check for additional hidden fields** — some sites include timestamps, hashes, or
   anti-bot values that change per page load
7. **Handle reCAPTCHA** — if present, automated login may not work without a solving
   service; check if the CAPTCHA is enforced (some sites only show it after failed attempts)
8. **Check for 2FA** — the response may include a 2FA challenge requiring an additional
   verification step

### Routing the Script Through Parley-MCP

To capture and modify the script's traffic through the proxy:

```python
# Route requests through Parley-MCP proxy
session.proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
# Disable SSL verification since proxy terminates TLS
session.verify = False
```

Or use Parley-MCP's direct TLS mode where the script connects plain and the proxy
adds TLS to the server:

```python
# Connect directly to proxy, which handles TLS to the real server
BASE_URL = "http://127.0.0.1:8080"  # Plain HTTP to proxy
# No proxy config needed — the script talks directly to the proxy
# Make sure client rewrite module fixes Host/Origin/Referer headers
```

### Python Script vs. Browser Automation

There are two approaches to automating login flows. Choose based on your goal:

**Python script (recommended for pen testing):**
- Full control over every HTTP parameter — headers, cookies, hidden fields, body
- Explicitly extracts CSRF tokens, nonces, and hidden fields from HTML
- Deterministic and repeatable — same result every run
- Fast — no browser overhead, just raw HTTP
- Easy to extend with authenticated endpoint testing after login
- All traffic captured by Parley-MCP when routed through the proxy

**Browser automation (Playwright, Selenium, Cursor browser tools):**
- Useful for visual demos or testing JavaScript-heavy login flows
- The page's JavaScript runs natively (reCAPTCHA, dynamic tokens, etc.)
- Good for verifying the full user experience through the proxy

**Critical lesson from real-world testing:** Browser automation tools that bypass
JavaScript form handlers will **miss hidden form fields**. For example, if a login
form has a hidden `<input type="hidden" name="token" value="...">` (CSRF token),
and the automation tool constructs a POST manually from the visible fields, the
token will be omitted and the server will reject the login with a "session timed out"
or "invalid token" error.

**Why this happens:**
- Normal browser form submission: JavaScript collects ALL form fields (visible + hidden)
  and submits them together
- Automation direct POST: Tool may only include fields it explicitly filled, skipping
  hidden inputs the developer added for CSRF/session protection

**Mitigation strategies:**
1. **Prefer the Python script approach** — explicitly extract all form fields from the
   HTML and include them in the POST body
2. **If using browser automation**, trigger the actual submit button click rather than
   constructing a POST request manually — let the page's JS handle form data collection
3. **Always verify the POST body** in Parley-MCP traffic capture — compare your automated
   POST against the captured browser POST to spot missing fields
4. **Use `traffic_query(show_modified=True)`** to compare the original request with what
   was actually sent to the server

## Key Design Notes

- **Original + modified data** are both stored per message — always recoverable
- **Modules are hot-loaded** — create/update takes effect on the next message
- **Global vs scoped** — `instance_id=""` makes a module apply to all instances
- **Multiple proxies** can run simultaneously on different ports
- **SQLite WAL mode** — proxy threads log concurrently without blocking queries
- **`traffic_clear`** between test iterations keeps the capture focused
- **`decode_as="hexdump"`** is best for binary protocols; `"utf8"` for text protocols

## Available Module Library Imports

| Import | Functions | Use case |
|--------|-----------|----------|
| `lib_http_basic` | `extract_basic_auth(data)`, `format_basic_auth(data)` | Decode HTTP Basic/Proxy Auth |
| `lib_jwt` | `extract_bearer_tokens(data)`, `decode_jwt(token)`, `find_and_format_jwts(data)` | Parse JWT tokens |
| `lib_ldap_bind` | LDAP bind decoding | Capture LDAP credentials |
| `lib_smtp_auth` | SMTP/IMAP AUTH decoding | Capture mail credentials |
| `lib3270` | EBCDIC translation | Mainframe terminal traffic |
| `lib8583` | ISO 8583 parsing | Payment card messages |
| `lib_fix` | FIX protocol parsing | Financial protocol |
| `solace_auth` | Solace auth decoding | Message broker credentials |

All Python standard library modules (`re`, `json`, `base64`, `struct`, `hashlib`,
`urllib.parse`, `html`, `zlib`, etc.) are always available.
