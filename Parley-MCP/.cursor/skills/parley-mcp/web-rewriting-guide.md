# Web Proxy Rewriting Guide

When proxying web traffic where a browser connects to `127.0.0.1:8080` but
the real target is `https://www.example.com`, many things break. This guide
covers every gotcha and provides ready-to-use modules to fix them.

## Recommended: Use `web_proxy_setup`

**For most web testing, use the one-call tool instead of manual module setup:**

```
web_proxy_setup(target_domain="example.com", listen_port=8080)
```

This automatically deploys all the modules described below. Only use the manual
approach if you need fine-grained control or have unusual requirements.

## The Problem

```
Browser ──HTTP──► 127.0.0.1:8080 (Parley) ──TLS──► www.example.com:443
```

The browser thinks it's talking to `127.0.0.1:8080` over plain HTTP.
The server thinks it's talking to a client that connected to `www.example.com` over HTTPS.
Everything about hostnames, protocols, cookies, security headers, and URLs will be wrong
unless you rewrite traffic in both directions.

## Critical Lessons (from real-world testing)

These issues caused blank pages, infinite loads, or redirects during testing:

1. **Always use `re.IGNORECASE`** — servers often send all-lowercase headers
   (`location:` not `Location:`, `set-cookie:` not `Set-Cookie:`)
2. **Server modules must be stateful** — HTTP headers can span multiple TLS records
   (~1.4KB each). Buffer data until `\r\n\r\n` is found before processing.
3. **Strip `Transfer-Encoding: chunked` and de-chunk the body** — if you modify body
   content inside chunks, the chunk size headers become wrong and the browser shows
   a blank page. De-chunk the body yourself and strip the TE header.
4. **Strip `Content-Length` after de-chunking** — you don't know the final body size
   after URL replacement changes content length.
5. **Force `Connection: close` on BOTH sides** — after stripping chunked TE and
   Content-Length, the browser relies on connection close to detect end of response.
6. **Handle both `domain.com` and `www.domain.com`** — many sites redirect between
   the bare domain and the www variant. Rewrite both.
7. **Patch JavaScript domain variables** — sites use `COOKIE_DOMAIN = 'example.com'`
   for `document.cookie`. Set to empty string so cookies default to current host.
8. **Bypass anti-hotlinking scripts** — some sites check `window.location.href`
   against a whitelist and redirect if it doesn't match.
9. **Replace `.domain.com` (dot-prefixed)** — catches cookie domain patterns in JS.
10. **When one side of the proxy disconnects, close both sides** — otherwise the
    browser hangs waiting for the proxy to close the connection.

---

## Manual Setup Checklist

When setting up a web proxy through Parley-MCP manually, create these modules
**in this order** before generating any browser traffic. All modules below use placeholders:

- `TARGET` = the real hostname (e.g., `www.example.com`)
- `PROXY` = your proxy address (e.g., `127.0.0.1:8080`)

---

## Client → Server Modules (direction="client")

### 1. Fix Host Header (CRITICAL — Priority 10)

The browser sends `Host: 127.0.0.1:8080`. The server needs `Host: www.example.com`.
Without this, virtual-hosted servers return 404 or the wrong site.

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    message_data = message_data.replace(
        b'Host: ' + PROXY,
        b'Host: ' + TARGET
    )
    return message_data
```

### 2. Fix Origin Header (CRITICAL for POST/CORS — Priority 11)

For POST requests, AJAX calls, and CORS preflight checks, the `Origin` header
must match the real server or requests get rejected.

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    message_data = message_data.replace(
        b'Origin: http://' + PROXY,
        b'Origin: https://' + TARGET
    )
    return message_data
```

### 3. Fix Referer Header (Priority 12)

The `Referer` header leaks the proxy address. Servers use it for CSRF checks
and may reject requests with the wrong referer.

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    message_data = message_data.replace(
        b'Referer: http://' + PROXY,
        b'Referer: https://' + TARGET
    )
    return message_data
```

### 4. Strip Accept-Encoding (CRITICAL — Priority 13)

If the client advertises `Accept-Encoding: gzip, deflate, br`, the server
compresses responses and you'll see binary garbage instead of readable text.
**Remove this header so the server sends plaintext.**

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Remove the Accept-Encoding header entirely
    message_data = bytearray(re.sub(
        rb'Accept-Encoding:.*?\r\n',
        b'',
        bytes(message_data)
    ))
    return message_data
```

### 5. Downgrade Upgrade-Insecure-Requests (Priority 14)

Browsers send `Upgrade-Insecure-Requests: 1` asking the server to redirect
to HTTPS. Since our client side is plain HTTP, this causes redirect loops.

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    message_data = bytearray(re.sub(
        rb'Upgrade-Insecure-Requests:.*?\r\n',
        b'',
        bytes(message_data)
    ))
    return message_data
```

### 6. Strip If-None-Match / If-Modified-Since (Priority 15)

Cache validation headers cause the server to return `304 Not Modified` with
no body, meaning you capture nothing. Strip them to always get full responses.

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    data = re.sub(rb'If-None-Match:.*?\r\n', b'', data)
    data = re.sub(rb'If-Modified-Since:.*?\r\n', b'', data)
    return bytearray(data)
```

---

## Server → Client Modules (direction="server")

### 7. Rewrite Location Redirects (CRITICAL — Priority 10)

Servers send `Location: https://www.example.com/path` for redirects.
The browser will follow these and bypass the proxy entirely.

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    # Rewrite https and http variants
    message_data = message_data.replace(
        b'Location: https://' + TARGET,
        b'Location: http://' + PROXY
    )
    message_data = message_data.replace(
        b'Location: http://' + TARGET,
        b'Location: http://' + PROXY
    )
    return message_data
```

### 8. Fix Set-Cookie Domain and Flags (CRITICAL — Priority 11)

Cookies set with `domain=.example.com` won't be stored for `127.0.0.1`.
The `Secure` flag prevents cookies over plain HTTP. `SameSite=None` requires
`Secure`. All of these break auth when proxying.

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    data = bytes(message_data)
    # Remove domain restriction so cookie applies to any host
    data = re.sub(rb';\s*[Dd]omain=[^;\r\n]+', b'', data)
    # Remove Secure flag (we're on plain HTTP)
    data = re.sub(rb';\s*[Ss]ecure\b', b'', data)
    # Remove SameSite=None (requires Secure which we removed)
    data = re.sub(rb';\s*[Ss]ame[Ss]ite=[Nn]one', b'; SameSite=Lax', data)
    return bytearray(data)
```

### 9. Strip Security Headers (Priority 12)

These headers block things you need for testing:

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    # HSTS forces HTTPS — breaks plain HTTP proxy
    data = re.sub(rb'Strict-Transport-Security:.*?\r\n', b'', data)
    # CSP can block loading from 127.0.0.1
    data = re.sub(rb'Content-Security-Policy:.*?\r\n', b'', data)
    # X-Frame-Options blocks iframe embedding
    data = re.sub(rb'X-Frame-Options:.*?\r\n', b'', data)
    # Permissions-Policy can restrict features
    data = re.sub(rb'Permissions-Policy:.*?\r\n', b'', data)
    return bytearray(data)
```

### 10. Rewrite URLs in HTML Body (Priority 50)

HTML contains absolute links, form actions, and resource URLs pointing to the
real domain. Without rewriting these, clicks navigate away from the proxy.

**This is the most complex module.** It must handle Content-Length recalculation.

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    data = bytes(message_data)

    # Only rewrite HTML responses
    if b'text/html' not in data:
        return message_data

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    # Rewrite absolute URLs in body
    body = body.replace(b'https://' + TARGET, b'http://' + PROXY)
    body = body.replace(b'http://' + TARGET, b'http://' + PROXY)
    # Also handle protocol-relative URLs
    body = body.replace(b'//' + TARGET, b'//' + PROXY)

    # Recalculate Content-Length if present
    if b'Content-Length:' in headers:
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(body)).encode(),
            headers
        )

    return bytearray(headers + b'\r\n\r\n' + body)
```

### 11. Rewrite URLs in JavaScript/CSS (Priority 51)

JavaScript and CSS files also contain absolute URLs. Same approach but
check for those content types.

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    data = bytes(message_data)

    # Only rewrite JS and CSS
    if b'javascript' not in data and b'text/css' not in data:
        return message_data

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    body = body.replace(b'https://' + TARGET, b'http://' + PROXY)
    body = body.replace(b'http://' + TARGET, b'http://' + PROXY)
    body = body.replace(b'//' + TARGET, b'//' + PROXY)

    if b'Content-Length:' in headers:
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(body)).encode(),
            headers
        )

    return bytearray(headers + b'\r\n\r\n' + body)
```

### 12. Handle Compressed Responses Anyway (Priority 5 — FIRST)

Even after stripping `Accept-Encoding` from requests, some servers or CDNs
send compressed responses regardless (especially with `Transfer-Encoding`).
This module decompresses so all downstream modules see plaintext.

```python
import re
import zlib
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    encoding = b''
    match = re.search(rb'Content-Encoding:\s*(\S+)', headers)
    if not match:
        return message_data  # not compressed, passthrough
    encoding = match.group(1).lower()

    try:
        if encoding == b'gzip':
            body = zlib.decompress(body, zlib.MAX_WBITS | 16)
        elif encoding == b'deflate':
            body = zlib.decompress(body, -zlib.MAX_WBITS)
        elif encoding == b'br':
            try:
                import brotli
                body = brotli.decompress(body)
            except ImportError:
                return message_data  # can't decompress brotli, pass through
        else:
            return message_data  # unknown encoding, pass through
    except Exception:
        return message_data  # decompression failed, pass through

    # Remove Content-Encoding header (body is now plain)
    headers = re.sub(rb'Content-Encoding:.*?\r\n', b'', headers)
    # Update Content-Length
    if b'Content-Length:' in headers:
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(body)).encode(),
            headers
        )

    return bytearray(headers + b'\r\n\r\n' + body)
```

**Note:** Brotli (`br`) decompression requires `pip install brotli`. Gzip and
deflate work with Python's built-in `zlib`.

---

## CORS Gotchas

If the site makes cross-origin API calls, the browser sends CORS preflight
requests (`OPTIONS`) and checks response headers. When proxying, these break.

### 13. Fix CORS Headers in Responses (Priority 13)

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    data = bytes(message_data)

    # Rewrite Access-Control-Allow-Origin
    data = data.replace(
        b'Access-Control-Allow-Origin: https://' + TARGET,
        b'Access-Control-Allow-Origin: http://' + PROXY
    )
    # If it's a wildcard, leave it. If it's missing and needed, inject it.
    if b'Access-Control-Allow-Origin' not in data and b'HTTP/' in data:
        data = data.replace(
            b'\r\n\r\n',
            b'\r\nAccess-Control-Allow-Origin: http://' + PROXY +
            b'\r\nAccess-Control-Allow-Credentials: true\r\n\r\n',
            1
        )
    return bytearray(data)
```

---

## Complete Setup: All-In-One Module

For convenience, here is a single client module and a single server module
that handle all of the above. Use these when you want a quick setup without
creating 12 individual modules.

### Client-Side All-In-One (direction="client", priority=10)

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    data = bytes(message_data)

    # Fix Host header
    data = data.replace(b'Host: ' + PROXY, b'Host: ' + TARGET)
    # Fix Origin
    data = data.replace(b'Origin: http://' + PROXY, b'Origin: https://' + TARGET)
    # Fix Referer
    data = data.replace(b'Referer: http://' + PROXY, b'Referer: https://' + TARGET)
    # Strip Accept-Encoding (force plaintext responses)
    data = re.sub(rb'Accept-Encoding:.*?\r\n', b'', data)
    # Strip Upgrade-Insecure-Requests
    data = re.sub(rb'Upgrade-Insecure-Requests:.*?\r\n', b'', data)
    # Strip cache validators (force full responses)
    data = re.sub(rb'If-None-Match:.*?\r\n', b'', data)
    data = re.sub(rb'If-Modified-Since:.*?\r\n', b'', data)

    return bytearray(data)
```

### Server-Side All-In-One (direction="server", priority=10)

```python
import re
import zlib
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET = b'www.example.com'
    PROXY = b'127.0.0.1:8080'
    data = bytes(message_data)

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    # --- Decompress if needed ---
    enc_match = re.search(rb'Content-Encoding:\s*(\S+)', headers)
    if enc_match:
        encoding = enc_match.group(1).lower()
        try:
            if encoding == b'gzip':
                body = zlib.decompress(body, zlib.MAX_WBITS | 16)
            elif encoding == b'deflate':
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            elif encoding == b'br':
                import brotli
                body = brotli.decompress(body)
            headers = re.sub(rb'Content-Encoding:.*?\r\n', b'', headers)
        except Exception:
            pass  # can't decompress, work with what we have

    # --- Fix redirect Location headers ---
    headers = headers.replace(
        b'Location: https://' + TARGET,
        b'Location: http://' + PROXY
    )
    headers = headers.replace(
        b'Location: http://' + TARGET,
        b'Location: http://' + PROXY
    )

    # --- Fix Set-Cookie ---
    headers = re.sub(rb';\s*[Dd]omain=[^;\r\n]+', b'', headers)
    headers = re.sub(rb';\s*[Ss]ecure\b', b'', headers)
    headers = re.sub(rb';\s*[Ss]ame[Ss]ite=[Nn]one', b'; SameSite=Lax', headers)

    # --- Strip security headers ---
    headers = re.sub(rb'Strict-Transport-Security:.*?\r\n', b'', headers)
    headers = re.sub(rb'Content-Security-Policy:.*?\r\n', b'', headers)
    headers = re.sub(rb'X-Frame-Options:.*?\r\n', b'', headers)
    headers = re.sub(rb'Permissions-Policy:.*?\r\n', b'', headers)

    # --- Fix CORS ---
    headers = headers.replace(
        b'Access-Control-Allow-Origin: https://' + TARGET,
        b'Access-Control-Allow-Origin: http://' + PROXY
    )

    # --- Rewrite URLs in body (HTML, JS, CSS) ---
    body = body.replace(b'https://' + TARGET, b'http://' + PROXY)
    body = body.replace(b'http://' + TARGET, b'http://' + PROXY)
    body = body.replace(b'//' + TARGET, b'//' + PROXY)

    # --- Fix Content-Length ---
    if b'Content-Length:' in headers:
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(body)).encode(),
            headers
        )

    return bytearray(headers + b'\r\n\r\n' + body)
```

---

## Additional Gotchas to Know

### Chunked Transfer-Encoding

When the server uses `Transfer-Encoding: chunked`, the body arrives in chunks
with hex size prefixes. If you modify the body, the chunk sizes become wrong.
Options:
- Strip `Transfer-Encoding: chunked` and set `Content-Length` instead
  (only works if you have the full response in one message)
- Reassemble chunks before modifying, then re-chunk or use Content-Length

### HTTP/2

Parley operates at the TCP stream level. HTTP/2 is a binary multiplexed protocol
and will not work through Parley as plain TCP forwarding. Ensure the client
and server negotiate HTTP/1.1. You can force this by stripping the ALPN extension
or by not advertising `h2` support. In practice, when the client connects via
plain HTTP to the proxy, HTTP/2 is not negotiated — this is only a concern
if you use `use_tls_client=True`.

### WebSockets

WebSocket upgrades (`Upgrade: websocket`) work through Parley because after
the handshake they become bidirectional TCP streams. However, WebSocket frames
are binary-framed (opcode + length + mask + payload), so you must parse the
frame structure if you want to modify WebSocket message content.

### Subresource Integrity (SRI)

Modern HTML includes `integrity="sha256-..."` attributes on `<script>` and
`<link>` tags. If you modify the content of these resources, the browser will
refuse to execute them because the hash won't match. Strip `integrity` attributes
from HTML if you need to modify referenced resources.

### Multiple Domains

Real websites load resources from many domains (CDN, APIs, analytics).
Your URL rewriting only handles the primary target domain. If the site loads
scripts from `cdn.example.com` or makes API calls to `api.example.com`,
you'll need additional rewrite rules or separate proxy instances for each domain.

### Certificate Transparency / HPKP

Some clients pin certificates or check Certificate Transparency logs.
When the proxy terminates TLS, the certificate changes. These checks will fail.
This is generally only an issue with non-browser clients (mobile apps, thick clients).

### Large Responses

Parley reads data in 4096-byte chunks and assembles them. Very large responses
(multi-MB) may arrive across multiple `module_function` calls (multiple messages
in the database). Each call sees one TCP read, not necessarily one complete HTTP
response. For large content modification, you may need to buffer across messages
or only modify headers (which come in the first message).
