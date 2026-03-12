# Changelog

All notable changes to Corellium-MCP will be documented in this file.

---

## [1.1.0] - 2026-03-11

### Fixed
- **`corellium_create_assessment`** — include `instanceId` in the JSON request
  body; the URL path parameter alone is insufficient and causes a `400 Bad
  Request` on enterprise deployments
- **HTTP error handling in `client.py`** — replace `resp.raise_for_status()` with
  custom error handling that captures the full response body text on `4xx`/`5xx`
  errors, making API debugging significantly easier

---

## [1.0.0] - 2025-12-01

### Added
- Initial release with 72 MCP tools for Corellium virtual device management
- Instance lifecycle management (create, start, stop, destroy, snapshot)
- MATRIX security assessment workflow (create, monitor, test, report)
- App management (install, uninstall, list, run)
- File system operations (upload, download, list, delete)
- Network monitoring and capture
- SSH and shell command execution
- Device input injection (touch, swipe, text, keypress)
- Core trace and kernel panic inspection
- Frida hook management (create, list, execute, delete)
- SSL pinning bypass support
- Port and network configuration
- System property and hostname management
- Screenshot capture
- Multi-connection support with named connection IDs
