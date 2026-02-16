# Parley-MCP Setup Guide

How to set up the Parley-MCP server and AI skill for **Cursor** and **Microsoft Visual Studio Code**.

---

## Prerequisites

- **Python 3.10+** installed and available on your system PATH
- **pip** package manager

Install the Python dependency:

```bash
pip install mcp
```

Optional (only if using ISO 8583 payment message modules):

```bash
pip install iso8583
```

---

## 1. Cursor Setup

### MCP Server Configuration

Cursor uses `.cursor/mcp.json` in the project root.

This file is already included in the repository at `.cursor/mcp.json`:

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

**To activate:**

1. Open the Parley-MCP folder as your workspace in Cursor
2. Go to **Settings** > **MCP** (or look for the MCP panel in the sidebar)
3. The `parley-mcp` server should appear automatically from the `.cursor/mcp.json`
4. Click the start/enable button if it doesn't auto-start
5. Verify by asking the AI: *"List proxy instances"* — it should respond with
   "No proxy instances found"

**If you cloned this repo elsewhere**, no path changes are needed. The
`${workspaceFolder}` variable resolves to whatever directory you opened.

### Skill Installation

The skill files are included in the repository under `.cursor/skills/parley-mcp/`:

```
.cursor/skills/parley-mcp/
    SKILL.md                  # Core skill (tool reference, module writing guide)
    module-recipes.md         # Pentest module patterns by attack category
    web-rewriting-guide.md    # Web proxy rewriting (Host, cookies, compression, etc.)
```

**No action needed** — Cursor automatically discovers project skills in
`.cursor/skills/`. The AI will use them whenever you ask about proxying,
traffic modification, or penetration testing.

### Cursor Troubleshooting

| Problem | Solution |
|---------|----------|
| Server won't start | Check Python is on PATH: `python --version` in terminal |
| "Module not found" error | Run `pip install mcp` in the same Python environment |
| Tools not appearing | Restart Cursor, or go to MCP settings and restart the server |
| Server starts but tools fail | Check the MCP output log in the Cursor panel for errors |

---

## 2. Microsoft Visual Studio Code Setup

VS Code uses `.vscode/mcp.json` for MCP server configuration. The format is
slightly different from Cursor's.

### Prerequisites

- **GitHub Copilot extension** installed and active (Copilot Pro or Business)
- **VS Code 1.99+** (recommended for full MCP support)

### MCP Server Configuration

Create `.vscode/mcp.json` in the project root:

```json
{
  "servers": {
    "parley-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["run_server.py"],
      "cwd": "${workspaceFolder}"
    }
  }
}
```

> **Note:** VS Code uses `"servers"` as the top-level key (not `"mcpServers"`
> like Cursor), and requires `"type": "stdio"` to be specified.

**To activate:**

1. Open the Parley-MCP folder in VS Code
2. Create the `.vscode/mcp.json` file as shown above
3. VS Code will detect the new MCP server configuration
4. When prompted, confirm that you trust the Parley-MCP server
5. The server starts automatically (or use Command Palette: **MCP: List Servers**
   to start it manually)
6. Open Copilot Chat and ask: *"List proxy instances"* — it should use the
   `proxy_list` tool

**Alternative: Add to User Profile (global)**

If you want Parley-MCP available in all your VS Code workspaces:

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run **MCP: Open User Configuration**
3. Add the server configuration (use an absolute path for `args` since there's
   no workspace folder context):

```json
{
  "servers": {
    "parley-mcp": {
      "type": "stdio",
      "command": "python",
      "args": ["C:/path/to/Parley-MCP/run_server.py"]
    }
  }
}
```

### AI Instructions for VS Code

VS Code doesn't have Cursor's "skills" system, but you can provide AI instructions
via `.github/copilot-instructions.md` in the project root.

Create `.github/copilot-instructions.md`:

```markdown
# Parley-MCP Instructions

You have access to Parley-MCP, a multi-threaded TCP/TLS penetration testing proxy.

## Available Tools (14 total)

### Proxy Lifecycle
- `proxy_start` — Start a proxy instance (target_host required)
- `proxy_stop` — Stop a running instance
- `proxy_list` — List all instances
- `proxy_status` — Detailed instance stats

### Module Management
- `module_create` — Create traffic modification module (name, direction, code)
- `module_update` — Update module code/config
- `module_delete` — Delete a module
- `module_set_enabled` — Toggle module on/off
- `module_list` — List all modules

### Traffic Analysis
- `traffic_query` — Query captured traffic (decode_as: utf8/hexdump/hex/repr/base64)
- `traffic_search` — Search traffic for text patterns
- `traffic_summary` — Message counts and volumes
- `traffic_connections` — List connections
- `traffic_clear` — Clear data for re-test

## Module Function Signature

Every module must define:

    def module_function(message_num, source_ip, source_port,
                        dest_ip, dest_port, message_data):
        # message_data is a bytearray — modify and return
        return message_data

- direction="client" → modifies client-to-server traffic
- direction="server" → modifies server-to-client traffic
- Modules run in priority order (lower number = runs first)
- Available imports: re, json, base64, struct, zlib, plus module_libs
  (lib_http_basic, lib_jwt, lib_ldap_bind, lib_smtp_auth, lib3270,
  lib8583, lib_fix, solace_auth)

## Workflow

1. Start proxy → 2. Generate traffic → 3. Query/search traffic →
4. Write modules to modify traffic → 5. Clear and re-test → 6. Iterate

## Web Proxy Gotchas

When proxying a browser (127.0.0.1:8080 → real HTTPS site), you must:
- Fix Host/Origin/Referer headers (client direction)
- Strip Accept-Encoding to prevent compressed responses
- Strip cache validators (If-None-Match, If-Modified-Since)
- Rewrite Location redirects (server direction)
- Fix Set-Cookie domain/Secure/SameSite flags
- Strip HSTS/CSP/X-Frame-Options security headers
- Rewrite absolute URLs in HTML/JS/CSS response bodies
- Recalculate Content-Length after any body modification
```

### VS Code Troubleshooting

| Problem | Solution |
|---------|----------|
| Server not detected | Verify `.vscode/mcp.json` syntax — use `"servers"` not `"mcpServers"` |
| Trust dialog doesn't appear | Run Command Palette > **MCP: List Servers** and start manually |
| Copilot doesn't use MCP tools | Make sure Copilot Chat is in Agent mode (not just Ask mode) |
| "Cannot find tools" | Run Command Palette > **MCP: Reset Cached Tools**, then restart |
| Python not found | Use full path in command: `"command": "C:/Python310/python.exe"` |
| Server crashes on start | Check output: Command Palette > **MCP: List Servers** > Show Output |

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

## Verifying the Setup

Once the MCP server is running in either IDE, test with these steps:

1. **Ask the AI:** *"List all proxy instances"*
   - Expected: "No proxy instances found"

2. **Ask the AI:** *"Start a proxy to example.com on port 443 with TLS"*
   - Expected: Proxy starts, returns an instance ID

3. **Ask the AI:** *"Show proxy status"*
   - Expected: Shows the running instance with connection details

4. **Ask the AI:** *"Stop the proxy"*
   - Expected: Proxy stops, shows capture summary

If all four steps work, Parley-MCP is fully operational.

---

## File Summary

```
Parley-MCP/
    run_server.py                          # Entry point (both IDEs call this)
    requirements.txt                       # Python dependencies
    README.md                              # Project documentation
    MCP_SETUP.md                           # This file
    LICENSE                                # GNU GPL v3
    .gitignore                             # Excludes data/ and __pycache__/
    parley_mcp/                            # Core package
        __init__.py
        server.py                          # MCP tool definitions
        proxy_engine.py                    # Multi-threaded proxy
        database.py                        # SQLite3 data layer
        module_manager.py                  # Dynamic module system
        module_libs/                       # Protocol libraries for modules
    .cursor/                               # Cursor IDE configuration
        mcp.json                           # MCP server config (Cursor)
        skills/parley-mcp/                 # AI skill files
            SKILL.md
            module-recipes.md
            web-rewriting-guide.md
```

For VS Code, create `.vscode/mcp.json` and optionally
`.github/copilot-instructions.md` as described above.
