# Corellium-MCP + Parley-MCP

Version: 1.1.1

**AI-driven mobile penetration testing** combining [Corellium](https://www.corellium.com/) virtual device control, [Parley-MCP](https://github.com/gglessner/Parley-MCP) active traffic interception, and Analysis-MCP forensic data decoding — all orchestrated by an AI agent through the Model Context Protocol.

## Why This Combination Is Devastating

Traditional mobile pentesting tools operate in isolation. You capture traffic with Burp, inspect files with objection, trace syscalls with Frida — all manually, all disconnected. This repo gives an AI agent **simultaneous programmatic control over the network layer, the device internals, and forensic data analysis**, creating a closed-loop automated attack platform.

| Layer | Parley-MCP | Corellium-MCP | Analysis-MCP |
|-------|-----------|---------------|--------------|
| **Network** | Active MITM — intercept, rewrite, search, scan, replay traffic; auto-cert CA for full TLS MITM; upstream proxy chaining | Passive PCAP download, Network Monitor with auto SSL bypass | — |
| **Application** | HTTP request/scan/replay tools; WebSocket detection; structured HTTP parsing | Sees app internals — filesystem, syscalls, crashes, panics; SSH shell access for FRIDA/objection/keychain-dumper | — |
| **Data** | Cookie jar management; HAR export for Burp/ZAP interop; pre-built security modules | Raw base64 file downloads; CoreTrace data retrieval with PID filtering | Decode AND encode plists, cookies, JWTs, provisioning profiles, SQLite, AEP configs, keychain dumps, Akamai sensor data, screenshot metadata |
| **Control** | Modify what the app **receives** from its backend; replay/scan endpoints directly | Modify what the app **contains** on the device; inject touch/keyboard input for UI automation | Parse, analyze, AND re-encode what the app **stores** (download → decode → modify → encode → upload) |

**The key insight**: Parley lets the AI *cause* things (tamper with API traffic, send HTTP requests, scan endpoints). Corellium lets the AI *observe* and *extract* (how the app reacts internally, raw file downloads, CoreTrace syscall data). Analysis-MCP lets the AI *understand* and *re-encode* extracted data (decode proprietary formats, modify, encode back for upload). Together: closed-loop automated testing.

## The Killer Workflows

### Automated Authorization Boundary Mapping (OWASP M3)
The AI uses Parley's `module_create` to write a Python module that increments `user_id` in every API request. Corellium's CoreTrace shows whether the app processes the unauthorized data or rejects it. The AI reads both sides and maps every endpoint's authorization boundary — automatically.

### Response Tampering for Client-Side Logic Bypass (OWASP M7)
Parley rewrites server responses: `"isPremium": false` becomes `true`, `"isJailbroken": true` becomes `false`. Corellium's CoreTrace observes whether the app enforces these checks server-side or blindly trusts them. Filesystem extraction shows whether tampered values get persisted to SharedPreferences or NSUserDefaults.

### Two-Sided Credential Audit (OWASP M1, M9)
Parley's `traffic_search` with patterns like `Authorization`, `Bearer`, `password`, `token` finds every credential crossing the wire. Corellium's `corellium_download_file` checks whether those same credentials are stored insecurely on disk. Complete credential audit — network and storage — in one pass.

### SSL Pinning Validation (OWASP M5)
Corellium's Network Monitor bypasses pinning transparently at the boringssl level. But does the app actually *implement* pinning? Route traffic through Parley instead (which presents its own cert) — if the app still works, there is **no pinning**. If it rejects Parley's cert, pinning is confirmed, and you use Corellium's bypass to test further.

### Fuzzing with Crash Correlation (OWASP M4)
Parley's module pipeline injects malformed data (oversized strings, format strings, SQL injection, null bytes) into API responses. Corellium's `corellium_get_kernel_panics` and `corellium_console_log` immediately show whether the app crashes, and CoreTrace reveals exactly which syscall it died on. Full cause-and-effect visibility.

### Closed-Loop Iterative Testing
The AI can autonomously: create a Parley rewriting module → exercise the app on Corellium → observe the result via CoreTrace/filesystem/panics → refine the module → repeat. This is automated adaptive penetration testing.

## Architecture

```
+-------------------+
|     AI Agent      |  Orchestrates all three MCPs simultaneously
|     (Cursor)      |
+--------+----------+
         |
    MCP Protocol
         |
+--------+----------+------------------+------------------+
|                   |                  |                  |
|  Corellium-MCP    |   Parley-MCP     |  Analysis-MCP    |
|  (68+ tools)      |   (25 tools)     |  (15 tools)      |
|                   |                  |                  |
|  Virtual Device   |  TCP/TLS Proxy   |  Plist decode/   |
|  Management       |  + Python Mods   |    encode        |
|  App Lifecycle    |  + SQLite DB     |  Cookie parser   |
|  Filesystem I/O   |  + HTTP Tools    |  JWT decoder     |
|  SSH Shell Access |  + Auto-Cert CA  |  SQLite analyzer |
|  CoreTrace        |  + Cookie Jar    |  Provisioning    |
|  MATRIX Assess.   |  + HAR Export    |    profiles      |
|  Hypervisor Hooks |  + Replay/Scan   |  Keychain dumps  |
|  UI Automation    |                  |  Screenshot meta |
+--------+----------+--------+---------+------------------+
         |                   |
         v                   v
+------------------+  +------------------+
| Corellium Cloud  |  | Target Backend   |
| Virtual Device   |<>| API Server       |
| (iOS / Android)  |  |                  |
+------------------+  +------------------+
  Mobile App Traffic ----> Parley Proxy ----> Backend
  (routed via proxy)      (intercept/rewrite)
```

## Combined Workflow Example

```
# --- PHASE 1: Setup ---

# Parley-MCP: Stand up a TLS-decrypting proxy for the target backend
web_proxy_setup(target_domain="api.targetapp.com", listen_port=8080)

# Corellium-MCP: Create device, install app, baseline snapshot
corellium_connect()
corellium_create_instance(project_id="...", flavor="iphone16pm", os_version="18.0", name="pentest")
corellium_agent_ready(instance_id="...")
corellium_create_snapshot(instance_id="...", name="clean-state")

# Corellium-MCP: Install Parley's proxy CA cert on the device
corellium_install_profile(instance_id="...", base64_profile="<parley-ca-cert-base64>")

# Corellium-MCP: Upload and install the target app
corellium_upload_file(instance_id="...", device_path="/tmp/target.ipa", base64_content="...")
corellium_install_app(instance_id="...", file_path="/tmp/target.ipa")

# --- PHASE 2: Reconnaissance ---

# Corellium-MCP: Start syscall tracing + launch the app
corellium_start_core_trace(instance_id="...")
corellium_run_app(instance_id="...", bundle_id="com.target.app")

# Parley-MCP: Watch traffic flow in, get summary
traffic_summary(instance_id="...")
traffic_search(instance_id="...", pattern="password|token|api_key|Bearer")

# --- PHASE 3: Active Testing ---

# Parley-MCP: Deploy IDOR testing module
module_create(name="IDOR_Probe", direction="client",
    code="def module_function(n, si, sp, di, dp, data):\n    return data.replace(b'user_id=123', b'user_id=456')")

# Corellium-MCP: Check app's reaction
corellium_download_file(instance_id="...", device_path="/data/data/com.target.app/databases/app.db")
corellium_get_kernel_panics(instance_id="...")

# Parley-MCP: Compare original vs modified traffic
traffic_query(instance_id="...", show_modified=True)

# --- PHASE 4: Automated Assessment ---

# Corellium-MCP: Run MATRIX while Parley captures everything
corellium_create_assessment(instance_id="...", bundle_id="com.target.app")
corellium_start_monitoring(instance_id="...", assessment_id="...")
# ... interact with app ...
corellium_stop_monitoring(instance_id="...", assessment_id="...")
corellium_run_security_tests(instance_id="...", assessment_id="...")
corellium_download_security_report(instance_id="...", assessment_id="...")

# --- PHASE 5: Cleanup ---
corellium_restore_snapshot(instance_id="...", snapshot_id="...")
proxy_stop(instance_id="...")
corellium_disconnect()
```

## What's In This Repo

```
Corellium-MCP/
├── README.md                        # This file
├── MCP_SETUP.md                     # Detailed setup instructions
├── requirements.txt                 # Corellium-MCP + Analysis-MCP dependencies
├── LICENSE                          # GNU General Public License v3
├── corellium_mcp/                   # Corellium MCP server (68+ tools)
│   ├── __init__.py
│   ├── __main__.py
│   ├── client.py                    #   REST API client (httpx)
│   └── server.py                    #   MCP tool definitions
├── analysis_mcp/                    # Analysis MCP server (15 tools)
│   ├── __init__.py
│   ├── __main__.py
│   └── server.py                    #   Forensic decoding/encoding tools
├── Parley-MCP/                      # Parley MCP server (25 tools)
│   ├── run_server.py                #   Entry point
│   ├── requirements.txt             #   Parley dependencies
│   ├── README.md                    #   Full Parley documentation
│   └── parley_mcp/                  #   Core package
│       ├── server.py                #     MCP tool definitions
│       ├── proxy_engine.py          #     Multi-threaded proxy engine
│       ├── database.py              #     SQLite3 data layer
│       ├── module_manager.py        #     Dynamic Python module system
│       └── module_libs/             #     Protocol libraries (JWT, HTTP, etc.)
└── .cursor/
    ├── mcp.json                     # All three servers configured
    └── skills/
        └── corellium-mcp/
            ├── SKILL.md             # Pentesting methodology + tool guide
            └── pentest-reference.md # Deep-dive reference (OWASP, paths, etc.)
```

## Prerequisites

- Python 3.10+
- A [Corellium](https://www.corellium.com/) account with API token
- Network route from Parley proxy to the target app's backend

## Installation

```bash
cd Corellium-MCP
pip install -r requirements.txt
pip install -r Parley-MCP/requirements.txt
```

## Configuration

Set your Corellium credentials in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "corellium-mcp": {
      "command": "python",
      "args": ["-m", "corellium_mcp"],
      "env": {
        "CORELLIUM_API_ENDPOINT": "https://app.corellium.com/api",
        "CORELLIUM_API_TOKEN": "your-token-here"
      }
    },
    "parley-mcp": {
      "command": "python",
      "args": ["Parley-MCP/run_server.py"]
    },
    "analysis-mcp": {
      "command": "python",
      "args": ["-m", "analysis_mcp"]
    }
  }
}
```

Or set environment variables `CORELLIUM_API_ENDPOINT` and `CORELLIUM_API_TOKEN`.

See [MCP_SETUP.md](MCP_SETUP.md) for detailed setup instructions.

## Tool Inventory

### Corellium-MCP (68+ tools)

| Category | Count | Highlights |
|----------|-------|------------|
| Connection | 3 | Connect, disconnect, list connections |
| Projects | 2 | List and inspect projects |
| Models | 2 | Browse device models and firmware versions |
| Instances | 13 | Create/start/stop/reboot/pause/delete, screenshot, console log, agent ready |
| Apps | 5 | Install, uninstall, run, kill, enumerate |
| Files | 5 | Upload, download, delete, list on jailbroken/rooted filesystem; find app data container by bundle ID |
| Snapshots | 4 | Create, list, restore, delete |
| Network | 4 | Start/stop network monitor, PCAP capture download, network info |
| SSH | 1 | Execute shell commands via paramiko (keychain-dumper, FRIDA, objection, app launch) |
| UI Automation | 1 | Inject touch, keyboard, and text input events |
| MATRIX | 7 | Full automated security assessment pipeline |
| Hooks | 5 | Hypervisor-level execution hooks |
| CoreTrace | 4 | Start, stop, get (with PID filter), clear hypervisor-level syscall tracing |
| System | 9 | Lock/unlock, properties, peripherals, panics, hostname, shutdown |
| Ports | 2 | Expose SSH (22), FRIDA (27042), ADB (5555) |
| Profiles | 3 | iOS configuration profile management |

### Parley-MCP (25 tools)

| Category | Count | Highlights |
|----------|-------|------------|
| Web Proxy | 1 | One-call TLS-decrypting proxy with full HTTP rewriting |
| Proxy Lifecycle | 4 | Start (with auto-cert, upstream proxy), stop, list, status |
| Module Management | 6 | Create/update/delete/enable/list Python rewriting modules; deploy pre-built security templates |
| Traffic Analysis | 7 | Query (HTTP decode), summary, connections, clear, search, export (HAR), replay |
| HTTP Tools | 2 | Direct HTTP request through proxy with cookie jar; multi-path endpoint scanning |
| Certificates | 1 | Generate MITM root CA (per-host certs auto-generated) |
| Cookie Jar | 2 | Show and clear automatic cross-request cookie persistence |

### Analysis-MCP (15 tools)

| Category | Count | Highlights |
|----------|-------|------------|
| Plist/Config | 3 | Decode binary/XML plists, encode JSON to plist, decode provisioning profiles |
| Data Formats | 4 | Decode base64 JSON, iOS binary cookies, JWTs, Adobe AEP configs |
| Binary Analysis | 3 | Extract strings with keyword filtering, binary search, SQLite schema + string extraction |
| Keychain | 1 | Parse iOS keychain-dumper output with security analysis |
| Anti-Bot | 1 | Decode Akamai BMP sensor payloads |
| Screenshots | 1 | Analyze PNG/JPEG metadata for SplashBoard data leakage |
| File Utility | 1 | Save base64-encoded data (screenshots, binaries, databases) to local files |

**108+ tools total** for comprehensive AI-driven mobile penetration testing.

## Cursor Skill

The skill at `.cursor/skills/corellium-mcp/` teaches the AI agent the complete pentesting methodology across all three MCPs:

- **SKILL.md** — 8-phase OWASP-aligned workflow, Mobile Top 10 tool mapping, three-MCP integration patterns, 55 critical rules from real-world testing
- **pentest-reference.md** — iOS/Android filesystem paths, MASTG test mapping, MATRIX categories, CoreTrace patterns, Core Data analysis, FRIDA targets, Parley module examples, 20+ high-yield finding patterns

## Author

Garland Glessner — [gglessner@gmail.com](mailto:gglessner@gmail.com)

## Credits

- **Corellium-MCP** — Corellium REST API integration for virtual device management
- **Analysis-MCP** — Mobile forensics data decoding, encoding, and analysis toolkit
- **[Parley-MCP](https://github.com/gglessner/Parley-MCP)** — AI-controlled TCP/TLS penetration testing proxy by [Garland Glessner](https://github.com/gglessner)
- Based on [Parley](https://github.com/gglessner/Parley) by Garland Glessner

## License

Copyright (C) 2025 Garland Glessner ([gglessner@gmail.com](mailto:gglessner@gmail.com))

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
