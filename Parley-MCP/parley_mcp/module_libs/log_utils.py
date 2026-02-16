# Log Utilities
# Compatibility shim — Parley-MCP logs all traffic to SQLite automatically.
# This module exists so that legacy Parley module code that imports
# write_to_log won't break. Calls are silently ignored.


def write_to_log(source_ip, source_port, dest_ip, dest_port, message):
    """No-op in Parley-MCP. Traffic is logged to SQLite automatically."""
    pass
