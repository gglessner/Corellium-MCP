# Corellium-MCP + Parley-MCP Setup Guide

Step-by-step instructions for configuring both MCP servers in **Cursor** and **Microsoft Visual Studio Code**.

This repo contains **two MCP servers** that work together:

- **Corellium-MCP** (60 tools) — Virtual iOS/Android device management, app security testing, MATRIX assessments, CoreTrace, hypervisor hooks
- **Parley-MCP** (15 tools) — Active MITM proxy with AI-authored Python rewriting modules, traffic capture and analysis

---

## Prerequisites

1. **Python 3.10+** installed and available on your PATH
2. **A Corellium account** with an API token ([generate one here](https://support.corellium.com/administration/api-token))
3. **Install dependencies:**

```bash
cd /path/to/Corellium-MCP
pip install -r requirements.txt
pip install -r Parley-MCP/requirements.txt
```

4. **Verify installation:**

```bash
python -c "from corellium_mcp.server import mcp; print('Corellium-MCP loaded successfully')"
python -c "import sys; sys.path.insert(0,'Parley-MCP'); from parley_mcp.server import mcp; print('Parley-MCP loaded successfully')"
```

---

## Cursor Setup

### Quick Start (Clone and Go)

This repository is pre-configured for Cursor. Clone, install, and open:

```bash
git clone https://github.com/gglessner/Corellium-MCP.git
cd Corellium-MCP
pip install -r requirements.txt
pip install -r Parley-MCP/requirements.txt
```

Then open the `Corellium-MCP` directory as a project in Cursor. Everything is automatic:

- **`.cursor/mcp.json`** — registers both MCP servers (75 tools appear immediately)
- **`.cursor/skills/corellium-mcp/SKILL.md`** — skill that teaches the AI the full pentesting methodology, all tools, and combined workflows
- **`.cursor/skills/corellium-mcp/pentest-reference.md`** — deep-dive reference with OWASP mappings, filesystem paths, Parley module patterns

No manual configuration needed beyond setting your Corellium credentials.

### Setting Your Corellium Credentials

**Option A: Edit `.cursor/mcp.json`** (project-level):

```json
{
  "mcpServers": {
    "corellium-mcp": {
      "command": "python",
      "args": ["-m", "corellium_mcp.server"],
      "env": {
        "CORELLIUM_API_ENDPOINT": "https://app.corellium.com/api",
        "CORELLIUM_API_TOKEN": "your-token-here"
      }
    },
    "parley-mcp": {
      "command": "python",
      "args": ["Parley-MCP/run_server.py"]
    }
  }
}
```

**Option B: Set system environment variables** (no file edits needed):

```bash
# Windows (PowerShell)
$env:CORELLIUM_API_ENDPOINT = "https://app.corellium.com/api"
$env:CORELLIUM_API_TOKEN = "your-token-here"

# macOS / Linux
export CORELLIUM_API_ENDPOINT="https://app.corellium.com/api"
export CORELLIUM_API_TOKEN="your-token-here"
```

**Option C: Pass credentials at runtime** — leave the env fields empty and provide them when connecting:

```
corellium_connect(api_endpoint="https://app.corellium.com/api", api_token="your-token-here")
```

**API Endpoint URLs:**

| Deployment | Endpoint |
|-----------|----------|
| Solo Cloud | `https://app.corellium.com/api` |
| Business Cloud | `https://<domain>.enterprise.corellium.com/api` |
| On-Premise | `https://<hostname-or-ip>/api` |

### Verifying in Cursor

1. Open Cursor Settings (`Ctrl+Shift+P` > "Cursor Settings")
2. Navigate to the **MCP** section
3. You should see both servers listed:
   - `corellium-mcp` — 60 tools
   - `parley-mcp` — 15 tools
4. If either shows "Error", click the restart button next to the server name

### Quick Verification Test

Ask the AI assistant:

1. *"List all Corellium connections"* — should respond with "No active connections"
2. *"List all proxy instances"* — should respond with "No proxy instances found"
3. *"Connect to Corellium"* — should authenticate and list visible projects

### Using from a Different Project

If you want these tools available from another workspace, add to that project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "corellium-mcp": {
      "command": "python",
      "args": ["-m", "corellium_mcp.server"],
      "cwd": "/absolute/path/to/Corellium-MCP",
      "env": {
        "CORELLIUM_API_ENDPOINT": "https://app.corellium.com/api",
        "CORELLIUM_API_TOKEN": "your-token-here"
      }
    },
    "parley-mcp": {
      "command": "python",
      "args": ["Parley-MCP/run_server.py"],
      "cwd": "/absolute/path/to/Corellium-MCP"
    }
  }
}
```

Optionally copy `.cursor/skills/corellium-mcp/` into that project's `.cursor/skills/` so the AI knows the full pentesting methodology.

### Global Configuration (All Projects)

To make both servers available across all Cursor projects, edit your global MCP config:

- **Windows:** `%APPDATA%\Cursor\mcp.json`
- **macOS:** `~/Library/Application Support/Cursor/mcp.json`
- **Linux:** `~/.config/Cursor/mcp.json`

Use the same format as above with absolute paths for `cwd`.

---

## Visual Studio Code Setup

### MCP Server Configuration

Create `.vscode/mcp.json` in the project root:

```json
{
  "servers": {
    "corellium-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "corellium_mcp.server"],
      "cwd": "${workspaceFolder}",
      "env": {
        "CORELLIUM_API_ENDPOINT": "https://app.corellium.com/api",
        "CORELLIUM_API_TOKEN": "your-token-here"
      }
    },
    "parley-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["Parley-MCP/run_server.py"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

> **Note:** VS Code uses `"servers"` as the top-level key (not `"mcpServers"` like Cursor), and requires `"type": "stdio"` on each server.

**To activate:**

1. Open the Corellium-MCP folder in VS Code
2. Create the `.vscode/mcp.json` file as shown above
3. VS Code will detect the new MCP server configuration
4. When prompted, confirm that you trust both servers
5. Open Copilot Chat in Agent mode and ask: *"List Corellium connections"*

### AI Instructions for VS Code

VS Code doesn't have Cursor's skill system. Provide AI context via `.github/copilot-instructions.md`:

```markdown
# Corellium-MCP + Parley-MCP Instructions

You have access to two MCP servers for mobile penetration testing:

## Corellium-MCP (60 tools) — Virtual Device Control

- `corellium_connect` / `corellium_disconnect` — Connection management
- `corellium_create_instance` / `corellium_delete_instance` — Device lifecycle
- `corellium_agent_ready` — MUST call before app/file/system operations
- `corellium_list_apps` / `corellium_install_app` / `corellium_run_app` — App management
- `corellium_upload_file` / `corellium_download_file` — Filesystem access (jailbroken/rooted)
- `corellium_create_snapshot` / `corellium_restore_snapshot` — State management
- `corellium_download_network_capture` — PCAP traffic capture
- `corellium_create_assessment` / `corellium_start_monitoring` / `corellium_stop_monitoring` / `corellium_run_security_tests` / `corellium_download_security_report` — MATRIX automated security assessment
- `corellium_start_core_trace` / `corellium_stop_core_trace` — Hypervisor-level syscall tracing
- `corellium_create_hook` / `corellium_execute_hooks` — Hypervisor execution hooks
- `corellium_enable_port` — Expose SSH (22), FRIDA (27042), ADB (5555)
- `corellium_install_profile` — Install CA certs for MITM

## Parley-MCP (15 tools) — Active MITM Proxy

- `web_proxy_setup` — One-call TLS-decrypting proxy with full HTTP rewriting
- `proxy_start` / `proxy_stop` / `proxy_list` / `proxy_status` — Proxy lifecycle
- `module_create` / `module_update` / `module_delete` / `module_set_enabled` / `module_list` — Python traffic rewriting modules
- `traffic_query` / `traffic_summary` / `traffic_connections` / `traffic_clear` / `traffic_search` — Traffic analysis

## Module Signature

    def module_function(message_num, source_ip, source_port,
                        dest_ip, dest_port, message_data):
        return message_data  # bytearray — modify and return

## Workflow: Parley causes, Corellium observes

1. Set up Parley proxy → 2. Install Parley CA cert on Corellium device →
3. Start CoreTrace → 4. Run app (traffic flows through Parley) →
5. Search/analyze traffic → 6. Deploy rewriting modules →
7. Observe app reaction via Corellium (filesystem, CoreTrace, panics) →
8. Iterate
```

---

## Quick Comparison

| Feature | Cursor | VS Code |
|---------|--------|---------|
| Config file | `.cursor/mcp.json` | `.vscode/mcp.json` |
| Top-level key | `"mcpServers"` | `"servers"` |
| Type field | Not required | `"type": "stdio"` required |
| `cwd` support | Yes | Yes |
| `${workspaceFolder}` | Yes | Yes |
| AI instructions | `.cursor/skills/` (auto-discovered) | `.github/copilot-instructions.md` |
| AI requirement | Built-in | GitHub Copilot extension |
| Min version | Any recent | 1.99+ recommended |

---

## Troubleshooting

### Server won't start or shows "Error"

1. Check Python is on your PATH: `python --version`
2. Check dependencies: `pip list | grep mcp` and `pip list | grep httpx`
3. Test manually:
   ```bash
   cd /path/to/Corellium-MCP
   python -c "from corellium_mcp.server import mcp; print('OK')"
   python -c "import sys; sys.path.insert(0,'Parley-MCP'); from parley_mcp.server import mcp; print('OK')"
   ```
4. Restart the MCP server in Cursor settings

### Corellium connection fails

- Verify your API token is valid and hasn't expired
- Check the endpoint URL matches your deployment type (Solo/Business/On-Premise)
- Test network connectivity: `python -c "import httpx; r=httpx.get('https://app.corellium.com/api/v1/supported'); print(r.status_code)"`

### Parley proxy doesn't capture traffic

- Verify the proxy is running: `proxy_list()`
- Ensure the Corellium device's traffic is routed through the proxy
- Check that the Parley CA certificate is installed on the device: `corellium_list_profiles(instance_id="...")`

### Tools show 0 or server appears but no tools

1. Restart the MCP server (click restart button in settings)
2. Verify the `cwd` or `args` paths are correct
3. On Windows, use forward slashes or escaped backslashes in JSON paths

### Windows-specific issues

- Use `python` not `python3` in the command field
- Ensure paths use forward slashes in JSON: `"C:/Users/name/Corellium-MCP"`
- If using a virtual environment, use the full path to the Python executable:
  ```json
  "command": "C:/Users/yourname/venv/Scripts/python.exe"
  ```

### "httpx not found" error

```bash
pip install httpx>=0.27.0
```

### "mcp not found" error

```bash
pip install "mcp[cli]>=1.2.0"
```

---

## Verifying the Full Setup

Once both servers are running, test with these steps:

1. **Test Corellium connection:**
   > "Connect to Corellium and list my projects"
   - Expected: Successful authentication, list of projects

2. **Test Parley proxy:**
   > "List all proxy instances"
   - Expected: "No proxy instances found"

3. **Test combined workflow:**
   > "Set up a Parley proxy for example.com on port 8080, then show its status"
   - Expected: Proxy starts, status shows listening

4. **Clean up:**
   > "Stop the proxy"
   - Expected: Proxy stops gracefully

If all steps work, both MCP servers are fully operational and ready for mobile penetration testing.

---

## File Summary

```
Corellium-MCP/
├── README.md                              # Project overview and killer workflows
├── MCP_SETUP.md                           # This file
├── requirements.txt                       # Corellium-MCP dependencies (mcp, httpx)
├── corellium_mcp/                         # Corellium MCP server (60 tools)
│   ├── __init__.py
│   ├── __main__.py                        #   python -m corellium_mcp entry point
│   ├── client.py                          #   Corellium REST API client (httpx)
│   └── server.py                          #   MCP tool definitions
├── Parley-MCP/                            # Parley MCP server (15 tools)
│   ├── run_server.py                      #   Entry point
│   ├── requirements.txt                   #   Parley dependencies (mcp)
│   ├── README.md                          #   Full Parley documentation
│   ├── MCP_SETUP.md                       #   Parley-specific setup guide
│   └── parley_mcp/                        #   Core package
│       ├── server.py                      #     MCP tool definitions
│       ├── proxy_engine.py                #     Multi-threaded proxy engine
│       ├── database.py                    #     SQLite3 data layer
│       ├── module_manager.py              #     Dynamic Python module system
│       └── module_libs/                   #     Protocol libraries (JWT, HTTP, etc.)
└── .cursor/
    ├── mcp.json                           #   Both servers configured for Cursor
    └── skills/
        └── corellium-mcp/
            ├── SKILL.md                   #   Pentesting methodology + tool guide
            └── pentest-reference.md       #   OWASP mappings, paths, module patterns
```

For VS Code, create `.vscode/mcp.json` and optionally `.github/copilot-instructions.md` as described above.
