# Parley-MCP

**Version:** 1.0.1

**AI-controlled multi-threaded TCP/TLS penetration testing proxy via Model Context Protocol.**

Based on [Parley](https://github.com/gglessner/Parley) by Garland Glessner.

---

## Overview

Parley-MCP gives an AI agent complete control of a multi-threaded application data proxy through MCP tools. The AI can:

- **Launch proxy instances** between any client and server with optional TLS on either side
- **Capture all traffic** automatically to a SQLite3 database
- **Create Python modules** that modify traffic on-the-fly (both directions)
- **Query and analyze** captured traffic for security testing
- **Iterate rapidly** — modify modules, clear captures, re-test, analyze results

This enables automated penetration testing workflows where the AI can set up a proxy, generate traffic through it (via browser or scripts), analyze what it sees, write modules to modify traffic programmatically, and repeat. The AI can also capture login flows, replay them with automated scripts, and identify security vulnerabilities from the captured traffic.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Cursor MCP Configuration

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "parley-mcp": {
      "command": "python",
      "args": ["run_server.py"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

---

## MCP Tools (15 total)

### Web Proxy (One-Call Setup)

| Tool | Description |
|------|-------------|
| `web_proxy_setup` | Complete web proxy with full HTTP rewriting in one call |

Creates a TLS-decrypting proxy and auto-deploys client/server rewriting modules
that handle header buffering, chunked de-encoding, cookie fixing, URL rewriting,
JS domain patching, security header stripping, cache busting, and hotlinker bypass.

### Proxy Lifecycle

| Tool | Description |
|------|-------------|
| `proxy_start` | Start a new TCP/TLS proxy instance |
| `proxy_stop` | Stop a running proxy instance |
| `proxy_list` | List all instances with status |
| `proxy_status` | Detailed status and statistics |

### Module Management

| Tool | Description |
|------|-------------|
| `module_create` | Create a traffic modification module |
| `module_update` | Update module code/config |
| `module_delete` | Delete a module |
| `module_set_enabled` | Enable or disable a module |
| `module_list` | List all modules with status |

### Traffic Analysis

| Tool | Description |
|------|-------------|
| `traffic_query` | Query captured traffic with filters |
| `traffic_summary` | Traffic statistics and volumes |
| `traffic_connections` | List all connections |
| `traffic_clear` | Clear captured data for re-test |
| `traffic_search` | Search traffic content for patterns |

---

## Architecture

```
+---------------+     +-------------------------------------------+
|   AI Agent    |---->|           Parley-MCP Server                |
|   (Cursor)    |<----|                                           |
+---------------+     |  +----------+  +------------------------+ |
      MCP             |  |  Proxy   |  |    Module Manager      | |
                      |  |  Engine  |--|  (compile/cache/exec)  | |
                      |  +----+-----+  +------------------------+ |
                      |       |                                    |
                      |  +----v--------------------------+         |
                      |  |      SQLite3 Database         |         |
                      |  |   (instances/connections/     |         |
                      |  |    messages/modules)          |         |
                      |  +------------------------------+         |
                      +-------------------------------------------+
                                    |
                  +-----------------+-----------------+
                  |                 |                 |
            +-----------+   +-----------+   +-----------+
            | Instance  |   | Instance  |   | Instance  |
            | Thread 1  |   | Thread 2  |   | Thread N  |
            +-----+-----+   +-----------+   +-----------+
                  |
     Client <-----+-----> Target Server
```

### Data Flow

1. Client connects to proxy listen port
2. Proxy connects to target server
3. Client data → module pipeline (client direction) → logged to SQLite → forwarded to server
4. Server data → module pipeline (server direction) → logged to SQLite → forwarded to client
5. AI queries SQLite to analyze captured traffic

### Module System

Modules are Python code stored in SQLite, compiled at runtime, and cached.
Each module processes traffic through a standard function:

```python
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    # message_data is a bytearray
    # Inspect, log, or modify the data
    # Return the (potentially modified) data
    return message_data
```

Modules can import from `module_libs` (HTTP Basic Auth, JWT, FIX, ISO 8583, etc.)
and the full Python standard library.

---

## Typical Workflows

### Web Testing (Quick Setup)

```
1. web_proxy_setup(target_domain="example.com", listen_port=8080)
   → Proxy + rewriting modules deployed, ready to browse

2. Open browser to http://127.0.0.1:8080

3. traffic_query / traffic_search to analyze captured traffic

4. module_create for any site-specific tweaks

5. proxy_stop when done
```

### Login Capture & Automation

```
1. web_proxy_setup(target_domain="example.com", listen_port=8080)
   → Proxy ready

2. Browse to http://127.0.0.1:8080 and log in manually

3. traffic_search(instance_id, pattern="POST")
   → Find the login POST request with credentials and CSRF tokens

4. traffic_query(instance_id, connection_id=N, show_modified=True)
   → See full request/response including hidden fields, cookies, tokens

5. Build a Python script using requests.Session() that:
   - GETs the login page and extracts CSRF tokens from HTML
   - POSTs credentials with all required fields/headers
   - Validates the JSON response and session cookies

6. Run the script through the proxy for ongoing traffic capture

7. Analyze captured traffic for security issues:
   - Unenforced CAPTCHAs, missing rate limiting
   - Predictable CSRF tokens, weak session management
   - Verbose error responses, username enumeration endpoints
```

### Protocol Testing (Manual Setup)

```
1. proxy_start(target_host="api.example.com", target_port=443,
               use_tls_server=True, no_verify=True,
               listen_port=8080)
   → Instance ID: a1b2c3d4

2. [Generate traffic through localhost:8080 via browser or script]

3. traffic_summary(instance_id="a1b2c3d4")
   → See message counts and data volumes

4. traffic_query(instance_id="a1b2c3d4", decode_as="utf8")
   → Inspect captured HTTP requests/responses

5. traffic_search(instance_id="a1b2c3d4", pattern="Authorization")
   → Find auth headers in traffic

6. module_create(name="Modify_Auth", direction="client",
                 code="...", description="Replace auth token")
   → Module active, modifying future traffic

7. traffic_clear(instance_id="a1b2c3d4")
   → Clean slate for next test

8. [Generate more traffic — now modified by the module]

9. traffic_query(instance_id="a1b2c3d4", show_modified=True)
   → Compare original vs modified traffic

10. proxy_stop(instance_id="a1b2c3d4")
```

---

## Directory Structure

```
Parley-MCP/
    run_server.py              # MCP server entry point
    requirements.txt           # Python dependencies
    README.md                  # This file
    parley_mcp/                # Core package
        __init__.py
        server.py              # MCP tool definitions
        proxy_engine.py        # Multi-threaded proxy engine
        database.py            # SQLite3 data layer
        module_manager.py      # Dynamic module system
        module_libs/           # Shared libraries for modules
            lib3270.py         # EBCDIC/3270 support
            lib8583.py         # ISO 8583 parsing
            lib_fix.py         # FIX protocol parsing
            lib_http_basic.py  # HTTP Basic Auth
            lib_jwt.py         # JWT token decoding
            lib_ldap_bind.py   # LDAP bind decoding
            lib_smtp_auth.py   # SMTP/IMAP auth
            log_utils.py       # Logging utilities
            solace_auth.py     # Solace auth decoding
    data/                      # SQLite database (created at runtime)
        parley_mcp.db
```

---

## License

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.

**Author:** Garland Glessner — gglessner@gmail.com
