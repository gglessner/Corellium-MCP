# Changelog

All notable changes to Parley-MCP will be documented in this file.

---

## [1.0.1] - 2026-02-15

### Added
- **`web_proxy_setup` tool** — one-call web proxy with full HTTP rewriting (header
  buffering, chunked de-encoding, cookie fixing, URL rewriting, JS domain patching,
  security header stripping, cache busting, anti-hotlinker bypass)
- **Login automation guidance** in skill documentation with a complete Python script
  template for replaying captured login flows
- **Browser automation vs. scripted login** analysis documenting the hidden field /
  CSRF token pitfall when browser automation bypasses JavaScript form handlers
- **Login Capture & Automation workflow** in README covering capture, replay script
  creation, and security analysis
- **Web rewriting critical lessons** — 10 documented gotchas from real-world web
  proxy testing added to skill and web-rewriting-guide

### Fixed
- **Proxy engine buffer size** increased from 4,096 to 65,536 bytes to handle large
  HTTP headers and responses
- **TLS header fragmentation** — added `ssl.SSLSocket.pending()` draining to ensure
  all available TLS records are read before passing data to modules
- **Connection closure deadlock** — when one side of a proxied connection disconnects,
  both client and server sockets are now properly closed, preventing the proxy thread
  from hanging indefinitely in the select loop

---

## [1.0.0] - 2026-02-14

### Added
- Initial release of Parley-MCP
- **14 MCP tools** for proxy lifecycle, module management, and traffic analysis
- **Multi-threaded TCP/TLS proxy engine** with optional TLS on client and/or server side
- **Dynamic Python module system** — modules stored in SQLite, compiled at runtime,
  executed in priority-ordered pipelines for both client and server traffic directions
- **SQLite3 traffic capture** with WAL mode for concurrent writes from proxy threads
- **Traffic analysis tools** — query, search, summarize, list connections, clear
- **Module library imports** — HTTP Basic Auth, JWT, LDAP bind, SMTP/IMAP auth,
  EBCDIC/3270, ISO 8583, FIX protocol, Solace auth
- Skill documentation with module writing guide, pentest recipes, and web rewriting guide
- GNU GPL v3 license
