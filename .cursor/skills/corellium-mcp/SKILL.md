---
name: corellium-mcp
description: Perform mobile penetration testing using Corellium virtual iOS/Android devices (corellium-mcp) and Parley active traffic interception proxy (parley-mcp). Covers OWASP Mobile Top 10, MASVS-aligned testing, MATRIX automated assessments, active MITM with on-the-fly Python rewriting modules, filesystem data extraction, network interception, SSL pinning bypass, FRIDA dynamic analysis, CoreTrace syscall tracing, and hypervisor hooks. Use when the user asks about mobile security testing, app pentesting, Corellium device management, traffic interception, or mobile vulnerability assessment.
---

# Corellium-MCP + Parley-MCP: Mobile Penetration Testing

Two MCP servers working together — **Corellium-MCP** (60 tools) controls virtual iOS/Android devices, **Parley-MCP** (15 tools) provides active MITM traffic interception with AI-authored Python rewriting modules. The AI agent uses both simultaneously for closed-loop automated penetration testing.

For detailed filesystem paths, OWASP mappings, and technique deep-dives, see [pentest-reference.md](pentest-reference.md).

## How They Work Together

| Layer | Parley-MCP | Corellium-MCP |
|-------|-----------|---------------|
| **Network** | Active MITM — intercept, rewrite, search traffic in real time | Passive PCAP download, Network Monitor with auto SSL bypass |
| **Application** | Sees HTTP/TLS protocol data, headers, tokens, payloads | Sees app internals — filesystem, syscalls, crashes, panics |
| **Control** | Modify what the app **receives** from its backend | Modify what the app **contains** on the device |

Parley lets the AI **cause** things (tamper with traffic). Corellium lets the AI **observe** consequences (how the app reacts internally). Together: closed-loop automated testing.

## Quick Start

```
# Corellium: Connect and provision device
corellium_connect(api_endpoint="https://app.corellium.com/api", api_token="...")
corellium_create_instance(project_id="...", flavor="iphone16pm", os_version="18.0", name="pentest")
corellium_agent_ready(instance_id="...")
corellium_create_snapshot(instance_id="...", name="clean-state")

# Parley: Stand up MITM proxy for the target backend
web_proxy_setup(target_domain="api.targetapp.com", listen_port=8080)

# Corellium: Install proxy CA cert, then install and run target app
corellium_install_profile(instance_id="...", base64_profile="<parley-ca-cert>")
corellium_upload_file(instance_id="...", device_path="/tmp/target.ipa", base64_content="...")
corellium_install_app(instance_id="...", file_path="/tmp/target.ipa")
corellium_run_app(instance_id="...", bundle_id="com.target.app")

# Parley: Analyze intercepted traffic
traffic_summary(instance_id="...")
traffic_search(instance_id="...", pattern="password|token|Bearer|api_key")
```

## Pentesting Methodology

### Phase 1: Reconnaissance & Setup

**Goal**: Provision device, set up proxy, install target, baseline snapshot.

```
# Corellium: Device setup
corellium_connect()
corellium_list_models()
corellium_get_model_software(model="...")
corellium_create_instance(project_id="...", flavor="...", os_version="...", name="pentest-target")
corellium_agent_ready(instance_id="...")    # WAIT — required before all agent ops
corellium_create_snapshot(instance_id="...", name="pre-app-clean")

# Parley: Start proxy targeting the app's backend API
web_proxy_setup(target_domain="api.targetapp.com", listen_port=8080)
# OR for non-HTTP protocols:
proxy_start(target_host="api.targetapp.com", target_port=443, use_tls_server=True, listen_port=8080)

# Corellium: Install Parley's proxy CA cert on the device
corellium_install_profile(instance_id="...", base64_profile="<parley-ca-cert>")
```

Upload and install the target app:

```
# iOS: upload IPA to /tmp/
corellium_upload_file(instance_id="...", device_path="/tmp/target.ipa", base64_content="...")
corellium_install_app(instance_id="...", file_path="/tmp/target.ipa")

# Android: upload APK to /data/local/tmp/
corellium_upload_file(instance_id="...", device_path="/data/local/tmp/target.apk", base64_content="...")
corellium_install_app(instance_id="...", file_path="/data/local/tmp/target.apk")
```

Snapshot after install: `corellium_create_snapshot(instance_id="...", name="app-installed")`

### Phase 2: Automated Security Assessment (MATRIX)

MATRIX tests 7 MASVS-aligned categories: Authentication, Code, Cryptography, Network, Platform, Storage, Resilience. Reports map to OWASP MASTG, MASWE, CVE, CWE, GDPR, PCI, HIPAA.

**Run MATRIX while Parley captures all traffic simultaneously** — this gives you both the automated findings AND the raw traffic for manual analysis.

```
corellium_create_assessment(instance_id="...", bundle_id="com.target.app")
corellium_start_monitoring(instance_id="...", assessment_id="...")
corellium_run_app(instance_id="...", bundle_id="com.target.app")
# Exercise all app features — login, data entry, payments, settings
corellium_stop_monitoring(instance_id="...", assessment_id="...")
corellium_run_security_tests(instance_id="...", assessment_id="...")
corellium_download_security_report(instance_id="...", assessment_id="...")

# Parley: Analyze the traffic captured during the MATRIX session
traffic_summary(instance_id="...")
traffic_search(instance_id="...", pattern="password|secret|token|Authorization")
traffic_query(instance_id="...", decode_as="utf8")
```

### Phase 3: Data Storage Analysis (MASVS-STORAGE)

**Maps to OWASP M9 (Insecure Data Storage)**. Extract files from known sensitive locations.

**iOS** (jailbroken, sandbox at `/var/mobile/Containers/Data/Application/[APP-ID]/`):

| Path | What to look for |
|------|-----------------|
| `Library/Preferences/*.plist` | NSUserDefaults — plaintext keys, tokens, passwords |
| `Documents/*.sqlite` / `*.db` | SQLite databases — user data, cached content |
| `Library/Cookies/Cookies.binarycookies` | Session cookies |
| `Library/Caches/` | HTTP cache, WebKit data |
| `tmp/` | Temporary files that may persist |

**Android** (rooted, internal at `/data/data/[package]/`):

| Path | What to look for |
|------|-----------------|
| `shared_prefs/*.xml` | SharedPreferences — plaintext credentials |
| `databases/*.db` | SQLite databases — user data |
| `cache/` | WebView cache, temp data |
| `/sdcard/Android/data/[package]/` | World-readable external storage |

```
corellium_download_file(instance_id="...", device_path="/data/data/com.target.app/shared_prefs/...")
corellium_download_file(instance_id="...", device_path="/data/data/com.target.app/databases/app.db")
```

**Cross-reference with Parley**: Compare credentials found in storage against credentials seen in network traffic. If the same token appears in both SharedPreferences AND HTTP headers, it's being stored insecurely.

### Phase 4: Active Network Testing (MASVS-NETWORK) — Parley + Corellium

**Maps to OWASP M5 (Insecure Communication)**. This is where the combined stack is most powerful.

**Step 1 — Passive reconnaissance** (Parley captures everything):
```
corellium_run_app(instance_id="...", bundle_id="com.target.app")
traffic_summary(instance_id="...")
traffic_search(instance_id="...", pattern="HTTP/1")       # Find cleartext
traffic_search(instance_id="...", pattern="Authorization") # Find auth headers
traffic_connections(instance_id="...")                      # Map all endpoints
```

**Step 2 — Active testing with rewriting modules** (Parley modifies, Corellium observes):
```
# IDOR test: swap user IDs in requests
module_create(name="IDOR_Probe", direction="client",
    code="def module_function(n, si, sp, di, dp, data):\n    return data.replace(b'user_id=123', b'user_id=456')")

# Response tampering: bypass client-side checks
module_create(name="Admin_Bypass", direction="server",
    code='def module_function(n, si, sp, di, dp, data):\n    return data.replace(b\'"isAdmin":false\', b\'"isAdmin":true \')')

# Observe app reaction via Corellium
corellium_start_core_trace(instance_id="...")
# Exercise the app through the modified proxy
corellium_stop_core_trace(instance_id="...")
corellium_download_file(instance_id="...", device_path="...")  # Check what got persisted

# Compare original vs modified traffic
traffic_query(instance_id="...", show_modified=True)
```

**Step 3 — SSL pinning validation**:
Corellium's Network Monitor bypasses boringssl pinning transparently. To test if the app actually *implements* pinning, route through Parley instead — if traffic flows, there's **no pinning**.

**Step 4 — Also grab Corellium's passive PCAP** for offline Wireshark analysis:
```
corellium_download_network_capture(instance_id="...", capture_type="netdump")
```

### Phase 5: Dynamic Analysis with CoreTrace

**Maps to OWASP M1, M3, M8**. CoreTrace monitors syscalls at the hypervisor level — undetectable.

```
corellium_start_core_trace(instance_id="...")
corellium_run_app(instance_id="...", bundle_id="com.target.app")
corellium_stop_core_trace(instance_id="...")
```

**Combine with Parley**: Start CoreTrace, then trigger specific app behavior by modifying API responses via Parley modules. CoreTrace reveals exactly what the app does internally when it receives tampered data.

### Phase 6: Fuzzing with Crash Correlation — Parley + Corellium

Parley injects malformed data, Corellium detects crashes. Full cause-and-effect.

```
# Parley: Deploy a fuzzing module
module_create(name="Fuzz_Responses", direction="server",
    code="import random\ndef module_function(n, si, sp, di, dp, data):\n    if b'Content-Type: application/json' in data:\n        data = data.replace(b'\"name\":', b'\"name\":' + b'A'*10000 + b'//')\n    return data")

# Corellium: Monitor for crashes
corellium_get_kernel_panics(instance_id="...")
corellium_console_log(instance_id="...")

# Iterate: clear traffic, adjust module, re-test
traffic_clear(instance_id="...")
module_update(name="Fuzz_Responses", code="...")
```

### Phase 7: Hypervisor Hooks (Advanced)

Kernel hooks intercept execution at specific addresses without pausing the VM. Written in `csmfcc` or `csmfvm`. Run lockless across cores.

```
corellium_create_hook(instance_id="...", hook_json='{"address":"0x100abc", "patch":"...", "enabled":true}')
corellium_execute_hooks(instance_id="...")
corellium_clear_hooks(instance_id="...")
```

### Phase 8: Cleanup & Reporting

```
proxy_stop(instance_id="...")                                   # Stop Parley proxy
corellium_restore_snapshot(instance_id="...", snapshot_id="...") # Reset device
corellium_delete_instance(instance_id="...")                      # Release resources
corellium_disconnect()
```

## OWASP Mobile Top 10 → Tool Mapping

| # | OWASP Risk | Corellium Tools | Parley Tools | Technique |
|---|-----------|----------------|--------------|-----------|
| M1 | Improper Credential Usage | `download_file`, `core_trace` | `traffic_search` | Extract stored creds + search traffic for hardcoded keys |
| M2 | Inadequate Supply Chain | `list_apps`, `download_file` | — | Enumerate libs, check CVEs |
| M3 | Insecure Authentication | `create_assessment`, `core_trace` | `module_create`, `traffic_query` | MATRIX auth checks + tamper auth tokens via Parley |
| M4 | Insufficient Validation | `create_hook`, `get_kernel_panics` | `module_create` | Parley injects payloads, Corellium detects crashes |
| M5 | Insecure Communication | `download_network_capture`, `install_profile` | `web_proxy_setup`, `traffic_search` | Parley active MITM + Corellium passive PCAP |
| M6 | Inadequate Privacy | `download_file` | `traffic_search` | Check stored PII + search traffic for PII leaks |
| M7 | Insufficient Binary Protections | `create_hook` | `module_create` | Hook detection functions + tamper responses to bypass |
| M8 | Security Misconfiguration | `console_log`, `get_assessment` | `traffic_query` | MATRIX checks + inspect HTTP security headers |
| M9 | Insecure Data Storage | `download_file`, `create_assessment` | `traffic_search` | Extract DBs + cross-reference with network credentials |
| M10 | Insufficient Cryptography | `core_trace`, `create_assessment` | `traffic_search` | Trace crypto syscalls + search for plaintext in traffic |

## Tool Quick Reference

### Corellium-MCP (60 tools)

**Connection**: `corellium_connect`, `corellium_disconnect`, `corellium_connections`, `corellium_list_projects`, `corellium_get_project`

**Devices**: `corellium_list_models`, `corellium_get_model_software`, `corellium_create_instance`, `corellium_list_instances`, `corellium_get_instance`, `corellium_start_instance`, `corellium_stop_instance`, `corellium_reboot_instance`, `corellium_pause_instance`, `corellium_unpause_instance`, `corellium_delete_instance`, `corellium_screenshot`, `corellium_console_log`, `corellium_agent_ready`

**Apps**: `corellium_list_apps`, `corellium_install_app`, `corellium_uninstall_app`, `corellium_run_app`, `corellium_kill_app`

**Filesystem**: `corellium_upload_file`, `corellium_download_file`, `corellium_delete_file`

**Snapshots**: `corellium_list_snapshots`, `corellium_create_snapshot`, `corellium_restore_snapshot`, `corellium_delete_snapshot`

**Network**: `corellium_download_network_capture`, `corellium_get_network_info`

**MATRIX**: `corellium_create_assessment`, `corellium_get_assessment`, `corellium_start_monitoring`, `corellium_stop_monitoring`, `corellium_run_security_tests`, `corellium_download_security_report`, `corellium_delete_assessment`

**Hooks**: `corellium_list_hooks`, `corellium_create_hook`, `corellium_delete_hook`, `corellium_execute_hooks`, `corellium_clear_hooks`

**CoreTrace**: `corellium_start_core_trace`, `corellium_stop_core_trace`, `corellium_clear_core_trace`

**System**: `corellium_lock_device`, `corellium_unlock_device`, `corellium_get_system_property`, `corellium_set_device_peripherals`, `corellium_get_device_peripherals`, `corellium_get_kernel_panics`, `corellium_clear_kernel_panics`

**Ports/Profiles**: `corellium_enable_port`, `corellium_disable_port`, `corellium_list_profiles`, `corellium_install_profile`, `corellium_uninstall_profile`

### Parley-MCP (15 tools)

**Proxy**: `web_proxy_setup`, `proxy_start`, `proxy_stop`, `proxy_list`, `proxy_status`

**Modules**: `module_create`, `module_update`, `module_delete`, `module_set_enabled`, `module_list`

**Traffic**: `traffic_query`, `traffic_summary`, `traffic_connections`, `traffic_clear`, `traffic_search`

## Critical Rules

1. **Always** call `corellium_agent_ready` before any agent operation (apps, files, system)
2. **Always** snapshot before destructive testing
3. MATRIX flow is strictly: create → start_monitoring → interact → stop_monitoring → run_tests → download_report
4. Network Monitor requires both Wi-Fi and cellular enabled on the device
5. iOS filesystem access requires jailbroken device; Android requires root
6. SSH default credentials: `root` / `alpine` (iOS jailbroken)
7. Common exposed ports: SSH=22, FRIDA=27042, ADB=5555
8. Binary data (files, screenshots, PCAPs, reports) is base64-encoded in Corellium tool responses
9. CoreTrace is hypervisor-level — **undetectable** by the target app
10. Parley modules are Python functions: `def module_function(msg_num, src_ip, src_port, dst_ip, dst_port, data)` → return modified `data` (bytearray)
11. Use `traffic_clear` between test iterations to isolate results
12. Use `show_modified=True` in `traffic_query` to compare original vs rewritten traffic
