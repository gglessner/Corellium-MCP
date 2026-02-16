"""
Parley-MCP Server

MCP server providing AI-controlled TCP/TLS proxy capabilities for
penetration testing. Exposes tools for proxy lifecycle management,
dynamic traffic modification modules, and SQLite-based traffic analysis.

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys
import base64
import atexit

from mcp.server.fastmcp import FastMCP

# Ensure module_libs is importable (for modules that import helpers)
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_module_libs_path = os.path.join(_pkg_dir, 'module_libs')
if _module_libs_path not in sys.path:
    sys.path.insert(0, _module_libs_path)

from parley_mcp.database import Database
from parley_mcp.module_manager import ModuleManager
from parley_mcp.proxy_engine import ProxyEngine

# ========== Initialize components ==========

_project_dir = os.path.dirname(_pkg_dir)
_db_path = os.path.join(_project_dir, 'data', 'parley_mcp.db')
db = Database(_db_path)
db.cleanup_stale_instances()  # Mark any leftover "running" from previous sessions

module_manager = ModuleManager(db)
proxy_engine = ProxyEngine(db, module_manager)

# Clean shutdown handler
atexit.register(proxy_engine.shutdown_all)

# ========== Create MCP Server ==========

mcp = FastMCP(
    "Parley-MCP",
    instructions=(
        "Parley-MCP is a multi-threaded TCP/TLS penetration testing proxy. "
        "You can start proxy instances to intercept traffic between a client "
        "and server, create Python modules to modify traffic on-the-fly, "
        "and analyze all captured traffic via SQLite queries. "
        "Workflow: proxy_start -> generate traffic through the proxy -> "
        "traffic_query/traffic_summary to analyze -> module_create to modify "
        "traffic -> iterate. All traffic is automatically logged to SQLite."
    )
)


# ========== Helpers ==========

def _render_data(data: bytes, decode_as: str = "utf8") -> str:
    """Render binary data in the specified format for display."""
    if data is None:
        return "<no data>"
    if isinstance(data, memoryview):
        data = bytes(data)
    if not isinstance(data, bytes):
        data = bytes(data)

    if decode_as == "utf8":
        return data.decode("utf-8", errors="replace")
    elif decode_as == "hex":
        return data.hex()
    elif decode_as == "hexdump":
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(
                chr(b) if 32 <= b <= 126 else '.' for b in chunk
            )
            lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
        return '\n'.join(lines) if lines else "<empty>"
    elif decode_as == "repr":
        return repr(data)
    elif decode_as == "base64":
        return base64.b64encode(data).decode("ascii")
    else:
        return data.decode("utf-8", errors="replace")


def _format_size(num_bytes) -> str:
    """Format byte count as human-readable string."""
    if num_bytes is None:
        num_bytes = 0
    num_bytes = int(num_bytes)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024:
            if unit == 'B':
                return f"{num_bytes} {unit}"
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


# =====================================================================
#  PROXY LIFECYCLE TOOLS
# =====================================================================

@mcp.tool()
def proxy_start(
    target_host: str,
    target_port: int = 80,
    listen_host: str = "localhost",
    listen_port: int = 8080,
    name: str = "",
    use_tls_client: bool = False,
    use_tls_server: bool = False,
    no_verify: bool = False,
    certfile: str = "",
    keyfile: str = "",
    client_certfile: str = "",
    client_keyfile: str = "",
    cipher: str = "",
    ssl_version: str = ""
) -> str:
    """Start a new multi-threaded TCP/TLS proxy instance.

    Creates a proxy that listens for client connections and forwards them
    to the target host, with optional TLS on either side. All traffic is
    automatically logged to SQLite for later analysis.

    Args:
        target_host: Remote host to proxy traffic to (IP or hostname)
        target_port: Remote port to connect to (default: 80)
        listen_host: Local address to listen on (default: localhost)
        listen_port: Local port to listen on (default: 8080)
        name: Human-readable name for this proxy instance
        use_tls_client: Present TLS to connecting clients (needs certfile/keyfile)
        use_tls_server: Use TLS when connecting to the target server
        no_verify: Skip TLS certificate verification for server connection
        certfile: Path to SSL certificate for client-side TLS
        keyfile: Path to SSL private key for client-side TLS
        client_certfile: Client certificate for mutual TLS with target
        client_keyfile: Client key for mutual TLS with target
        cipher: Specific cipher suite string for TLS
        ssl_version: Force TLS version (TLSv1, TLSv1.1, TLSv1.2)
    """
    if not name:
        name = f"{target_host}:{target_port}"

    config = {
        'listen_host': listen_host,
        'listen_port': listen_port,
        'target_host': target_host,
        'target_port': target_port,
        'use_tls_client': use_tls_client,
        'use_tls_server': use_tls_server,
        'no_verify': no_verify,
        'certfile': certfile or None,
        'keyfile': keyfile or None,
        'client_certfile': client_certfile or None,
        'client_keyfile': client_keyfile or None,
        'cipher': cipher or None,
        'ssl_version': ssl_version or None,
    }

    try:
        instance_id = db.create_instance(name=name, **config)
        proxy_engine.start_instance(instance_id, config)

        tls_info = []
        if use_tls_client:
            tls_info.append("TLS client-side")
        if use_tls_server:
            tls_info.append(
                "TLS server-side" + (" (no verify)" if no_verify else "")
            )
        tls_str = ", ".join(tls_info) if tls_info else "Plain TCP"

        return (
            f"Proxy started successfully.\n\n"
            f"  Instance ID : {instance_id}\n"
            f"  Name        : {name}\n"
            f"  Listening   : {listen_host}:{listen_port}\n"
            f"  Target      : {target_host}:{target_port}\n"
            f"  Mode        : {tls_str}\n\n"
            f"All traffic is being logged to SQLite.\n"
            f"Use instance ID '{instance_id}' for all subsequent operations."
        )
    except OSError as e:
        return f"ERROR: Failed to start proxy - {e}"
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def proxy_stop(instance_id: str) -> str:
    """Stop a running proxy instance.

    Closes the listener socket and all active connections. Captured traffic
    data is preserved in the SQLite database for analysis.

    Args:
        instance_id: The instance ID returned by proxy_start
    """
    instance = proxy_engine.get_instance(instance_id)
    if not instance:
        return f"ERROR: No running instance with ID '{instance_id}'"

    active = instance.active_connections
    proxy_engine.stop_instance(instance_id)

    summary = db.get_traffic_summary(instance_id)
    return (
        f"Proxy instance '{instance_id}' stopped.\n\n"
        f"  Active connections closed : {active}\n"
        f"  Total messages captured   : {summary['total_messages']}\n"
        f"  Total data captured       : {_format_size(summary['total_original_bytes'])}\n\n"
        f"Traffic data is preserved. Use traffic_query/traffic_summary to analyze."
    )


@mcp.tool()
def proxy_list() -> str:
    """List all proxy instances (running and stopped) with status and stats."""
    instances = db.list_instances()
    running = proxy_engine.list_running()

    if not instances:
        return "No proxy instances found. Use proxy_start to create one."

    lines = ["Proxy Instances:\n"]
    for inst in instances:
        iid = inst['id']
        is_running = iid in running
        status = "RUNNING" if is_running else "STOPPED"
        active = running[iid].active_connections if is_running else 0
        summary = db.get_traffic_summary(iid)

        tls_parts = []
        if inst['use_tls_client']:
            tls_parts.append("client-TLS")
        if inst['use_tls_server']:
            tls_parts.append(
                "server-TLS" + ("(no-verify)" if inst['no_verify'] else "")
            )
        tls_str = ', '.join(tls_parts) if tls_parts else 'plain TCP'

        lines.append(f"  [{status}] {iid} - {inst['name']}")
        lines.append(
            f"    {inst['listen_host']}:{inst['listen_port']} -> "
            f"{inst['target_host']}:{inst['target_port']} ({tls_str})"
        )
        if is_running:
            lines.append(f"    Active connections: {active}")
        lines.append(
            f"    Messages: {summary['total_messages']} "
            f"({_format_size(summary['total_original_bytes'])})"
        )
        lines.append(f"    Created: {inst['created_at']}")
        lines.append("")

    return '\n'.join(lines)


@mcp.tool()
def proxy_status(instance_id: str) -> str:
    """Get detailed status and statistics for a proxy instance.

    Args:
        instance_id: The proxy instance ID to query
    """
    inst = db.get_instance(instance_id)
    if not inst:
        return f"ERROR: No instance with ID '{instance_id}'"

    running_inst = proxy_engine.get_instance(instance_id)
    is_running = running_inst is not None
    summary = db.get_traffic_summary(instance_id)
    modules = db.list_modules(instance_id=instance_id)
    enabled_client = sum(
        1 for m in modules if m['direction'] == 'client' and m['enabled']
    )
    enabled_server = sum(
        1 for m in modules if m['direction'] == 'server' and m['enabled']
    )

    lines = [
        f"Proxy Instance: {instance_id}",
        f"{'=' * 50}",
        f"  Name          : {inst['name']}",
        f"  Status        : {'RUNNING' if is_running else 'STOPPED'}",
        f"  Listen        : {inst['listen_host']}:{inst['listen_port']}",
        f"  Target        : {inst['target_host']}:{inst['target_port']}",
        f"",
        f"  TLS Client    : {'Yes' if inst['use_tls_client'] else 'No'}",
        f"  TLS Server    : {'Yes' if inst['use_tls_server'] else 'No'}",
    ]
    if inst['use_tls_server']:
        lines.append(
            f"  No Verify     : {'Yes' if inst['no_verify'] else 'No'}"
        )

    active_conns = running_inst.active_connections if is_running else 0
    lines.extend([
        f"",
        f"  Active Conns  : {active_conns}",
        f"  Total Conns   : {summary['connection_count']}",
        f"",
        f"  Client -> Srv : {summary['client_messages']} msgs "
        f"({_format_size(summary['client_bytes'])})",
        f"  Server -> Clt : {summary['server_messages']} msgs "
        f"({_format_size(summary['server_bytes'])})",
        f"  Total         : {summary['total_messages']} msgs "
        f"({_format_size(summary['total_original_bytes'])})",
        f"  Modified      : {summary['modified_messages']} msgs",
        f"",
        f"  Modules (clt) : {enabled_client} enabled",
        f"  Modules (srv) : {enabled_server} enabled",
        f"",
        f"  Created       : {inst['created_at']}",
    ])

    if inst['stopped_at']:
        lines.append(f"  Stopped       : {inst['stopped_at']}")
    if summary['first_message']:
        lines.append(f"  First msg     : {summary['first_message']}")
        lines.append(f"  Last msg      : {summary['last_message']}")

    return '\n'.join(lines)


# =====================================================================
#  WEB PROXY CONVENIENCE TOOL
# =====================================================================

_CLIENT_REWRITE_TEMPLATE = r'''
import re
def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    TARGET_WWW = b'{target_www}'
    PROXY = b'{proxy_addr}'
    data = bytes(message_data)
    data = re.sub(rb'(host:\s*)' + re.escape(PROXY), b'\\1' + TARGET_WWW, data, flags=re.IGNORECASE)
    data = re.sub(rb'(origin:\s*)http://' + re.escape(PROXY), b'\\1https://' + TARGET_WWW, data, flags=re.IGNORECASE)
    data = re.sub(rb'(referer:\s*)http://' + re.escape(PROXY), b'\\1https://' + TARGET_WWW, data, flags=re.IGNORECASE)
    data = re.sub(rb'accept-encoding:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'if-modified-since:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'if-none-match:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'cache-control:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'pragma:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'upgrade-insecure-requests:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = re.sub(rb'connection:.*?\r\n', b'', data, flags=re.IGNORECASE)
    data = data.replace(b'\r\n\r\n', b'\r\nConnection: close\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n', 1)
    return bytearray(data)
'''

_SERVER_REWRITE_TEMPLATE = r'''
import re
import zlib

_state = {{}}

def _conn_key(src_ip, src_port, dst_ip, dst_port):
    return f"{{src_ip}}:{{src_port}}-{{dst_ip}}:{{dst_port}}"

def _process_headers(headers, PROXY):
    headers = re.sub(rb'(location:\s*)https?://(?:www\.)?{target_re}', b'\\1http://' + PROXY, headers, flags=re.IGNORECASE)
    headers = re.sub(rb';\s*domain=[^;\r\n]+', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb';\s*secure\b', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb';\s*samesite=none', b'; SameSite=Lax', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'transfer-encoding:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'content-length:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'content-encoding:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'connection:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'strict-transport-security:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'content-security-policy:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'content-security-policy-report-only:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'x-frame-options:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'permissions-policy:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'cache-control:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'etag:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'last-modified:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'expires:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'age:.*?\r\n', b'', headers, flags=re.IGNORECASE)
    headers = re.sub(rb'(access-control-allow-origin:\s*)https?://(?:www\.)?{target_re}', b'\\1http://' + PROXY, headers, flags=re.IGNORECASE)
    headers += b'\r\nConnection: close'
    headers += b'\r\nCache-Control: no-store, no-cache, must-revalidate, max-age=0'
    headers += b'\r\nPragma: no-cache'
    headers += b'\r\nExpires: 0'
    return headers

def _do_body_replace(data):
    PROXY = b'{proxy_addr}'
    PROXY_HOST = b'{proxy_host}'
    data = data.replace(b'https://{target_www}', b'http://' + PROXY)
    data = data.replace(b'http://{target_www}', b'http://' + PROXY)
    data = data.replace(b'https://{target_bare}', b'http://' + PROXY)
    data = data.replace(b'http://{target_bare}', b'http://' + PROXY)
    data = data.replace(b'//{target_www}', b'//' + PROXY)
    data = data.replace(b'//{target_bare}', b'//' + PROXY)
    data = data.replace(b"COOKIE_DOMAIN = '{target_bare}'", b"COOKIE_DOMAIN = ''")
    data = data.replace(b"COOKIE_DOMAIN = '{target_www}'", b"COOKIE_DOMAIN = ''")
    data = data.replace(b"cbDomainName = '{target_bare}'", b"cbDomainName = ''")
    data = data.replace(b'.{target_bare}', b'.' + PROXY_HOST)
    data = data.replace(b'!func.isInWhitelist()', b'false')
    return data

def _dechunk(st, raw):
    result = bytearray()
    buf = st.get('chunk_buf', bytearray()) + raw
    while buf:
        remaining = st.get('chunk_remaining', 0)
        if remaining > 0:
            take = min(remaining, len(buf))
            result.extend(buf[:take])
            buf = buf[take:]
            st['chunk_remaining'] = remaining - take
            if st['chunk_remaining'] == 0:
                if buf.startswith(b'\r\n'):
                    buf = buf[2:]
                elif len(buf) == 1 and buf == b'\r':
                    st['chunk_buf'] = bytearray(buf)
                    return bytes(result)
            continue
        idx = buf.find(b'\r\n')
        if idx == -1:
            st['chunk_buf'] = bytearray(buf)
            return bytes(result)
        size_line = bytes(buf[:idx]).strip()
        buf = buf[idx + 2:]
        if not size_line:
            continue
        if b';' in size_line:
            size_line = size_line.split(b';')[0]
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            result.extend(size_line + b'\r\n')
            result.extend(buf)
            buf = bytearray()
            break
        if chunk_size == 0:
            st['done'] = True
            break
        st['chunk_remaining'] = chunk_size
    st['chunk_buf'] = bytearray()
    return bytes(result)

def module_function(message_num, source_ip, source_port,
                    dest_ip, dest_port, message_data):
    PROXY = b'{proxy_addr}'
    key = _conn_key(source_ip, source_port, dest_ip, dest_port)
    data = bytes(message_data)
    if data.startswith(b'HTTP/'):
        _state[key] = {{
            'phase': 'headers',
            'header_buf': bytearray(),
            'chunked': False,
            'chunk_buf': bytearray(),
            'chunk_remaining': 0,
        }}
    st = _state.get(key)
    if st is None:
        return bytearray(_do_body_replace(data))
    if st['phase'] == 'headers':
        st['header_buf'].extend(data)
        if b'\r\n\r\n' not in st['header_buf']:
            return bytearray()
        raw = bytes(st['header_buf'])
        header_bytes, body_start = raw.split(b'\r\n\r\n', 1)
        if re.search(rb'transfer-encoding:\s*chunked', header_bytes, re.IGNORECASE):
            st['chunked'] = True
        enc_match = re.search(rb'content-encoding:\s*(\S+)', header_bytes, re.IGNORECASE)
        if enc_match and body_start:
            encoding = enc_match.group(1).lower()
            try:
                if encoding == b'gzip':
                    body_start = zlib.decompress(body_start, zlib.MAX_WBITS | 16)
                elif encoding == b'deflate':
                    body_start = zlib.decompress(body_start, -zlib.MAX_WBITS)
            except Exception:
                pass
        processed_headers = _process_headers(header_bytes, PROXY)
        st['phase'] = 'body'
        if st['chunked'] and body_start:
            body_start = _dechunk(st, body_start)
        body_start = _do_body_replace(body_start)
        return bytearray(processed_headers + b'\r\n\r\n' + body_start)
    elif st['phase'] == 'body':
        if st['chunked']:
            data = _dechunk(st, data)
        data = _do_body_replace(data)
        return bytearray(data)
    return message_data
'''


@mcp.tool()
def web_proxy_setup(
    target_domain: str,
    listen_port: int = 8080,
    listen_host: str = "127.0.0.1",
    target_port: int = 443
) -> str:
    """Set up a complete web proxy with full HTTP rewriting in one call.

    Creates a TLS-decrypting proxy and automatically deploys battle-tested
    client and server rewriting modules that handle:
    - Header rewriting (Host, Origin, Referer, cookies, security headers)
    - Chunked transfer-encoding (stateful de-chunking across TCP segments)
    - Header buffering (handles headers split across TLS records)
    - Cookie fixing (strips domain/Secure, fixes SameSite)
    - Cache busting (strips and replaces all cache headers)
    - URL rewriting in HTML/JS/CSS bodies
    - JavaScript domain variable patching (COOKIE_DOMAIN, etc.)
    - Anti-hotlinking bypass
    - HSTS, CSP, X-Frame-Options stripping

    Point your browser at http://{listen_host}:{listen_port} after setup.

    Args:
        target_domain: Domain to proxy (e.g. "example.com"). Handles
                       both bare and www-prefixed variants automatically.
        listen_port: Local port to listen on (default: 8080)
        listen_host: Local address to listen on (default: 127.0.0.1)
        target_port: Target HTTPS port (default: 443)
    """
    import re as _re

    # Normalize domain: strip protocol and trailing slashes
    domain = target_domain.strip().lower()
    domain = _re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')

    # Determine bare and www variants
    if domain.startswith('www.'):
        target_bare = domain[4:]
        target_www = domain
    else:
        target_bare = domain
        target_www = f"www.{domain}"

    proxy_addr = f"{listen_host}:{listen_port}"
    proxy_host = listen_host

    # Escape domain for regex (dots become literal)
    target_re = target_bare.replace('.', r'\.')

    try:
        # 1. Start the proxy
        name = f"web-{target_bare}"
        config = {
            'listen_host': listen_host,
            'listen_port': listen_port,
            'target_host': target_bare,
            'target_port': target_port,
            'use_tls_client': False,
            'use_tls_server': True,
            'no_verify': True,
            'certfile': None,
            'keyfile': None,
            'client_certfile': None,
            'client_keyfile': None,
            'cipher': None,
            'ssl_version': None,
        }
        instance_id = db.create_instance(name=name, **config)
        proxy_engine.start_instance(instance_id, config)

        # 2. Generate and deploy client rewrite module
        client_code = _CLIENT_REWRITE_TEMPLATE.format(
            target_www=target_www,
            proxy_addr=proxy_addr,
        )
        is_valid, error = module_manager.validate_module_code(client_code)
        if not is_valid:
            return f"ERROR: Client module validation failed - {error}"

        client_mod_id = db.create_module(
            name="Web_Client_Rewrite",
            direction="client",
            code=client_code,
            description=f"Rewrite client headers for {target_bare} web proxy",
            instance_id=instance_id,
            enabled=True,
            priority=10
        )

        # 3. Generate and deploy server rewrite module
        server_code = _SERVER_REWRITE_TEMPLATE.format(
            target_www=target_www,
            target_bare=target_bare,
            target_re=target_re,
            proxy_addr=proxy_addr,
            proxy_host=proxy_host,
        )
        is_valid, error = module_manager.validate_module_code(server_code)
        if not is_valid:
            return f"ERROR: Server module validation failed - {error}"

        server_mod_id = db.create_module(
            name="Web_Server_Rewrite",
            direction="server",
            code=server_code,
            description=f"Stateful rewrite for {target_bare}: headers, de-chunk, cookies, URLs, security",
            instance_id=instance_id,
            enabled=True,
            priority=10
        )

        module_manager.invalidate()

        return (
            f"Web proxy setup complete!\n\n"
            f"  Instance ID  : {instance_id}\n"
            f"  Proxy URL    : http://{proxy_addr}\n"
            f"  Target       : {target_bare}:{target_port} (TLS, no verify)\n"
            f"  Client Mod   : {client_mod_id} (Web_Client_Rewrite)\n"
            f"  Server Mod   : {server_mod_id} (Web_Server_Rewrite)\n\n"
            f"Modules handle: header buffering, chunked de-encoding,\n"
            f"cookie fixing, URL rewriting, JS domain patching,\n"
            f"security header stripping, cache busting, hotlinker bypass.\n\n"
            f"Open your browser to: http://{proxy_addr}\n\n"
            f"Use instance ID '{instance_id}' for traffic_query, traffic_search, etc.\n"
            f"Add custom modules with module_create for site-specific tweaks."
        )
    except OSError as e:
        return f"ERROR: Failed to start web proxy - {e}"
    except Exception as e:
        return f"ERROR: {e}"


# =====================================================================
#  MODULE MANAGEMENT TOOLS
# =====================================================================

@mcp.tool()
def module_create(
    name: str,
    direction: str,
    code: str,
    description: str = "",
    instance_id: str = "",
    priority: int = 100,
    enabled: bool = True
) -> str:
    """Create a new traffic modification module.

    Modules are Python code that process traffic flowing through the proxy.
    Each module receives message data and can inspect, modify, or log it.
    Modules execute in priority order (lower number = runs first).

    The code MUST define a module_function with this exact signature:

        def module_function(message_num, source_ip, source_port,
                            dest_ip, dest_port, message_data):
            # message_data is a bytearray - modify in place or return new
            return message_data

    Available imports from module_libs: lib3270, lib8583, lib_fix,
    lib_http_basic, lib_jwt, lib_ldap_bind, lib_smtp_auth, solace_auth.
    All Python standard library modules are also available.

    Args:
        name: Descriptive module name (e.g. "Replace_Auth_Header")
        direction: Traffic direction - "client" (C->S) or "server" (S->C)
        code: Complete Python source code defining module_function
        description: Brief description of what the module does
        instance_id: Apply to specific instance only (empty = all instances)
        priority: Execution order, lower runs first (default: 100)
        enabled: Whether module is immediately active (default: True)
    """
    if direction not in ('client', 'server'):
        return "ERROR: direction must be 'client' or 'server'"

    # Validate before storing
    is_valid, error = module_manager.validate_module_code(code)
    if not is_valid:
        return f"ERROR: Invalid module code - {error}"

    module_id = db.create_module(
        name=name,
        direction=direction,
        code=code,
        description=description,
        instance_id=instance_id or None,
        enabled=enabled,
        priority=priority
    )

    # Invalidate cache so proxy threads pick up the new module
    module_manager.invalidate()

    scope = f"instance {instance_id}" if instance_id else "all instances"
    status = "ACTIVE - processing traffic now" if enabled else "INACTIVE"
    return (
        f"Module created successfully.\n\n"
        f"  Module ID   : {module_id}\n"
        f"  Name        : {name}\n"
        f"  Direction   : {direction}\n"
        f"  Priority    : {priority}\n"
        f"  Status      : {status}\n"
        f"  Scope       : {scope}\n"
        f"  Description : {description}\n"
    )


@mcp.tool()
def module_update(
    module_id: str,
    code: str = "",
    description: str = "",
    priority: int = -1,
    name: str = ""
) -> str:
    """Update an existing module's code, description, priority, or name.

    Only non-empty/non-default fields are updated. Use this to iterate on
    module logic during testing.

    Args:
        module_id: The module ID to update
        code: New Python source code (must define module_function)
        description: New description
        priority: New priority (-1 = don't change)
        name: New name
    """
    existing = db.get_module(module_id)
    if not existing:
        return f"ERROR: No module with ID '{module_id}'"

    kwargs = {}
    if code:
        is_valid, error = module_manager.validate_module_code(code)
        if not is_valid:
            return f"ERROR: Invalid module code - {error}"
        kwargs['code'] = code
    if description:
        kwargs['description'] = description
    if priority >= 0:
        kwargs['priority'] = priority
    if name:
        kwargs['name'] = name

    if not kwargs:
        return (
            "ERROR: No fields to update. "
            "Provide code, description, priority, or name."
        )

    db.update_module(module_id, **kwargs)
    module_manager.invalidate(module_id)

    updated = db.get_module(module_id)
    return (
        f"Module updated successfully.\n\n"
        f"  Module ID   : {module_id}\n"
        f"  Name        : {updated['name']}\n"
        f"  Direction   : {updated['direction']}\n"
        f"  Priority    : {updated['priority']}\n"
        f"  Enabled     : {bool(updated['enabled'])}\n"
        f"  Updated     : {', '.join(kwargs.keys())}"
    )


@mcp.tool()
def module_delete(module_id: str) -> str:
    """Permanently delete a module.

    Args:
        module_id: The module ID to delete
    """
    existing = db.get_module(module_id)
    if not existing:
        return f"ERROR: No module with ID '{module_id}'"

    db.delete_module(module_id)
    module_manager.invalidate(module_id)

    return (
        f"Module deleted: '{existing['name']}' ({module_id})\n"
        f"Direction: {existing['direction']}, "
        f"was {'enabled' if existing['enabled'] else 'disabled'}"
    )


@mcp.tool()
def module_set_enabled(module_id: str, enabled: bool) -> str:
    """Enable or disable a module.

    Disabled modules remain stored but do not process traffic.
    Re-enable at any time to resume processing.

    Args:
        module_id: The module ID
        enabled: True to enable, False to disable
    """
    existing = db.get_module(module_id)
    if not existing:
        return f"ERROR: No module with ID '{module_id}'"

    db.set_module_enabled(module_id, enabled)
    module_manager.invalidate(module_id)

    state = "ENABLED - now processing traffic" if enabled else "DISABLED"
    return f"Module '{existing['name']}' ({module_id}): {state}"


@mcp.tool()
def module_list(instance_id: str = "", direction: str = "") -> str:
    """List all modules with their status, priority, and scope.

    Args:
        instance_id: Show modules for a specific instance (empty = show all)
        direction: Filter by "client" or "server" (empty = show both)
    """
    modules = db.list_modules(
        instance_id=instance_id or None,
        direction=direction or None
    )

    if not modules:
        return "No modules found. Use module_create to create one."

    lines = [f"Modules ({len(modules)} total):\n"]
    for mod in modules:
        icon = "[ON] " if mod['enabled'] else "[OFF]"
        scope = (
            f"instance:{mod['instance_id']}"
            if mod['instance_id'] else "global"
        )
        lines.append(f"  {icon} {mod['id']} | {mod['name']}")
        lines.append(
            f"       Dir: {mod['direction']} | "
            f"Priority: {mod['priority']} | Scope: {scope}"
        )
        if mod['description']:
            lines.append(f"       Desc: {mod['description']}")
        lines.append(f"       Updated: {mod['updated_at']}")
        lines.append("")

    return '\n'.join(lines)


# =====================================================================
#  TRAFFIC ANALYSIS TOOLS
# =====================================================================

@mcp.tool()
def traffic_query(
    instance_id: str,
    direction: str = "",
    connection_id: int = 0,
    limit: int = 20,
    offset: int = 0,
    decode_as: str = "utf8",
    show_modified: bool = False,
    order: str = "ASC"
) -> str:
    """Query captured traffic messages from the SQLite database.

    Returns message data with metadata, decoded in the requested format.
    Use for detailed inspection of specific traffic flows.

    Args:
        instance_id: The proxy instance to query
        direction: "client_to_server", "server_to_client", or "" for both
        connection_id: Filter to specific connection (0 = all)
        limit: Max messages to return (default: 20, max: 100)
        offset: Skip first N messages for pagination
        decode_as: Data rendering - "utf8", "hex", "hexdump", "repr", "base64"
        show_modified: Also show modified data when messages were changed
        order: "ASC" (oldest first) or "DESC" (newest first)
    """
    limit = min(limit, 100)

    messages = db.query_messages(
        instance_id=instance_id,
        connection_id=connection_id or None,
        direction=direction or None,
        limit=limit,
        offset=offset,
        order=order
    )

    if not messages:
        return (
            f"No traffic found for instance '{instance_id}' "
            f"with the given filters."
        )

    lines = [f"Traffic Query Results ({len(messages)} messages):\n"]

    for msg in messages:
        arrow = "->" if msg['direction'] == 'client_to_server' else "<-"
        label = "C->S" if msg['direction'] == 'client_to_server' else "S->C"
        mod_flag = " [MODIFIED]" if msg['was_modified'] else ""

        lines.append(
            f"--- Msg #{msg['id']} | {label} | "
            f"Conn:{msg['connection_id']} | "
            f"Seq:{msg['message_num']}{mod_flag} ---"
        )
        lines.append(
            f"  {msg['source_ip']}:{msg['source_port']} {arrow} "
            f"{msg['dest_ip']}:{msg['dest_port']}  "
            f"@ {msg['timestamp']}"
        )

        data = msg['original_data']
        if data:
            data_bytes = bytes(data) if not isinstance(data, bytes) else data
            lines.append(f"  Size: {_format_size(len(data_bytes))}")
            lines.append(f"  Data ({decode_as}):")
            rendered = _render_data(data_bytes, decode_as)
            for line in rendered.split('\n'):
                lines.append(f"    {line}")
        else:
            lines.append("  Data: <empty>")

        if show_modified and msg['was_modified'] and msg['modified_data']:
            mod_data = msg['modified_data']
            mod_bytes = (
                bytes(mod_data) if not isinstance(mod_data, bytes)
                else mod_data
            )
            lines.append(f"  Modified data ({decode_as}):")
            rendered = _render_data(mod_bytes, decode_as)
            for line in rendered.split('\n'):
                lines.append(f"    {line}")

        lines.append("")

    # Pagination hint
    hint = f"Showing offset {offset} to {offset + len(messages)}"
    if len(messages) == limit:
        hint += f". More available (use offset={offset + limit})."
    lines.append(hint)

    return '\n'.join(lines)


@mcp.tool()
def traffic_summary(instance_id: str) -> str:
    """Get traffic summary statistics for a proxy instance.

    Shows connection counts, message counts, data volumes, and timing.

    Args:
        instance_id: The proxy instance to summarize
    """
    inst = db.get_instance(instance_id)
    if not inst:
        return f"ERROR: No instance with ID '{instance_id}'"

    summary = db.get_traffic_summary(instance_id)
    running_inst = proxy_engine.get_instance(instance_id)

    lines = [
        f"Traffic Summary: {inst['name']} ({instance_id})",
        f"{'=' * 50}",
        f"  Status      : {'RUNNING' if running_inst else 'STOPPED'}",
        f"  Target      : {inst['target_host']}:{inst['target_port']}",
        f"",
        f"  Connections : {summary['connection_count']}",
        f"",
        f"  Client->Srv : {summary['client_messages']} msgs "
        f"({_format_size(summary['client_bytes'])})",
        f"  Server->Clt : {summary['server_messages']} msgs "
        f"({_format_size(summary['server_bytes'])})",
        f"  Total       : {summary['total_messages']} msgs "
        f"({_format_size(summary['total_original_bytes'])})",
        f"  Modified    : {summary['modified_messages']} msgs",
    ]

    if summary['first_message']:
        lines.extend([
            f"",
            f"  First msg   : {summary['first_message']}",
            f"  Last msg    : {summary['last_message']}",
        ])

    return '\n'.join(lines)


@mcp.tool()
def traffic_connections(instance_id: str) -> str:
    """List all connections for a proxy instance.

    Shows each connection's client/server endpoints and timing.

    Args:
        instance_id: The proxy instance to list connections for
    """
    connections = db.list_connections(instance_id)

    if not connections:
        return f"No connections found for instance '{instance_id}'."

    lines = [f"Connections for {instance_id} ({len(connections)} total):\n"]

    for conn in connections:
        status = "[ACTIVE]" if not conn['ended_at'] else "[CLOSED]"
        lines.append(f"  {status} Connection #{conn['id']}")
        lines.append(
            f"    Client: {conn['client_ip']}:{conn['client_port']}"
        )
        lines.append(
            f"    Server: {conn['server_ip']}:{conn['server_port']}"
        )
        lines.append(f"    Started: {conn['started_at']}")
        if conn['ended_at']:
            lines.append(f"    Ended:   {conn['ended_at']}")
        lines.append("")

    return '\n'.join(lines)


@mcp.tool()
def traffic_clear(instance_id: str) -> str:
    """Clear all captured traffic data for a proxy instance.

    Deletes all messages and connection records from SQLite.
    The instance record itself is preserved. Use this to start a
    clean capture session between test iterations.

    Args:
        instance_id: The proxy instance to clear traffic for
    """
    inst = db.get_instance(instance_id)
    if not inst:
        return f"ERROR: No instance with ID '{instance_id}'"

    result = db.clear_traffic(instance_id)
    return (
        f"Traffic cleared for instance '{instance_id}'.\n\n"
        f"  Messages deleted    : {result['messages_deleted']}\n"
        f"  Connections deleted : {result['connections_deleted']}\n\n"
        f"Instance is ready for a fresh capture session."
    )


@mcp.tool()
def traffic_search(
    instance_id: str,
    pattern: str,
    direction: str = "",
    decode_as: str = "utf8",
    limit: int = 20
) -> str:
    """Search captured traffic for a text pattern.

    Searches through message data (original and modified) for the
    given substring. Useful for finding specific requests, responses,
    headers, tokens, credentials, error messages, etc.

    Args:
        instance_id: The proxy instance to search
        pattern: Text to search for (case-sensitive substring match)
        direction: "client_to_server", "server_to_client", or "" for both
        decode_as: How to render matches - "utf8", "hex", "hexdump", "repr"
        limit: Maximum results to return (default: 20)
    """
    messages = db.search_messages(
        instance_id=instance_id,
        pattern=pattern,
        direction=direction or None,
        limit=limit
    )

    if not messages:
        return (
            f"No matches for '{pattern}' in instance '{instance_id}'."
        )

    lines = [
        f"Search Results for '{pattern}' "
        f"({len(messages)} match{'es' if len(messages) != 1 else ''}):\n"
    ]

    for msg in messages:
        label = "C->S" if msg['direction'] == 'client_to_server' else "S->C"
        mod_flag = " [MODIFIED]" if msg['was_modified'] else ""

        lines.append(
            f"--- Msg #{msg['id']} | {label} | "
            f"Conn:{msg['connection_id']}{mod_flag} ---"
        )
        lines.append(
            f"  {msg['source_ip']}:{msg['source_port']} -> "
            f"{msg['dest_ip']}:{msg['dest_port']}  "
            f"@ {msg['timestamp']}"
        )

        data = msg['original_data']
        if data:
            data_bytes = bytes(data) if not isinstance(data, bytes) else data
            lines.append(f"  Size: {_format_size(len(data_bytes))}")
            lines.append(f"  Data ({decode_as}):")
            rendered = _render_data(data_bytes, decode_as)
            for line in rendered.split('\n'):
                lines.append(f"    {line}")
        lines.append("")

    return '\n'.join(lines)


# =====================================================================
#  ENTRY POINT
# =====================================================================

def main():
    """Start the Parley-MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
