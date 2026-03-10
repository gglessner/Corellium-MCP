---
name: corellium-mcp
description: Perform mobile penetration testing using Corellium virtual iOS/Android devices (corellium-mcp) and Parley active traffic interception proxy (parley-mcp). Covers OWASP Mobile Top 10, MASVS-aligned testing, MATRIX automated assessments, active MITM with on-the-fly Python rewriting modules, filesystem data extraction, network interception, SSL pinning bypass, FRIDA dynamic analysis, CoreTrace syscall tracing, and hypervisor hooks. Use when the user asks about mobile security testing, app pentesting, Corellium device management, traffic interception, or mobile vulnerability assessment.
---

# Corellium-MCP + Parley-MCP: Mobile Penetration Testing

Three MCP servers working together — **Corellium-MCP** (68+ tools) controls virtual iOS/Android devices with SSH shell access via paramiko, CoreTrace data retrieval, and automatic app data container discovery, **Parley-MCP** (25 tools) provides active MITM traffic interception with AI-authored Python rewriting modules, built-in HTTP request/scan/replay capabilities, automatic certificate generation, cookie jar management, and traffic export, and **Analysis-MCP** (15 tools) provides forensic decoding/parsing and encoding for mobile app data formats including keychain dumps, Akamai sensor data, plist encoding, screenshot metadata, and base64-to-file saving. The AI agent uses all three simultaneously for closed-loop automated penetration testing.

For detailed filesystem paths, OWASP mappings, and technique deep-dives, see [pentest-reference.md](pentest-reference.md).

## How They Work Together

| Layer | Parley-MCP | Corellium-MCP | Analysis-MCP |
|-------|-----------|---------------|--------------|
| **Network** | Active MITM — intercept, rewrite, search, scan, replay traffic; auto-cert CA for full TLS MITM; upstream proxy chaining | Passive PCAP download, Network Monitor with auto SSL bypass | — |
| **Application** | HTTP request/scan/replay tools; WebSocket detection; structured HTTP parsing | Sees app internals — filesystem, syscalls, crashes, panics; SSH shell access for FRIDA/objection/keychain-dumper | — |
| **Data** | Cookie jar management; HAR export for Burp/ZAP interop; pre-built security modules | Raw base64 file downloads; CoreTrace data retrieval with PID filtering | Decode AND encode plists, cookies, JWTs, provisioning profiles, SQLite, AEP configs, keychain dumps, Akamai sensor data, screenshot metadata |
| **Control** | Modify what the app **receives** from its backend; replay/scan endpoints directly | Modify what the app **contains** on the device; inject touch/keyboard input for UI automation | Parse, analyze, AND re-encode what the app **stores** (download → decode → modify → encode → upload) |

Parley lets the AI **cause** things (tamper with traffic, send HTTP requests, scan endpoints, replay captured traffic). Corellium lets the AI **observe** and **extract** (how the app reacts internally, raw file downloads, CoreTrace syscall data). Analysis-MCP lets the AI **understand** and **re-encode** extracted data (decode proprietary formats, modify, and encode back for upload). Together: closed-loop automated testing.

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

### Phase 1.5: Static Analysis of App Bundle (CRITICAL — do this BEFORE launching)

**Goal**: Extract maximum intelligence from the app binary and config files before any dynamic analysis. This often produces high-severity findings with zero risk of detection.

**iOS App Bundle** (at `/private/var/containers/Bundle/Application/[UUID]/[AppName].app/`):

```
# Step 1: List installed apps and find the target
corellium_list_apps(instance_id="...")

# Step 2: Browse the app bundle directory
corellium_list_files(instance_id="...", path="/private/var/containers/Bundle/Application/")
# Find the UUID, then:
corellium_list_files(instance_id="...", path="/private/var/containers/Bundle/Application/[UUID]/[App].app/")

# Step 3: Download and analyze key files (prioritize these)
```

| Priority | File / Pattern | What to Extract |
|----------|---------------|-----------------|
| **P0** | `Info.plist` | URL schemes, ATS config (`NSAppTransportSecurity`), permissions, bundle ID, `LSApplicationQueriesSchemes` (jailbreak detection) |
| **P0** | `embedded.mobileprovision` | Entitlements (`get-task-allow`, keychain-access-groups), team ID, capabilities, associated domains, profile expiry |
| **P0** | `Frameworks/` (directory listing) | Complete SDK/library inventory — reveals security stack |
| **P0** | `GoogleService-Info.plist` | Firebase API keys, project ID, storage bucket, GCM sender ID — enables backend enumeration |
| **P0** | `*.momd/` (Core Data model) | Database schema with entity names and attribute types — reveals sensitive field storage (e.g., credit card, password columns) before any data is written |
| **P1** | `*.plist` (non-Info) | Host allowlists, environment configs, pre-prod endpoints |
| **P1** | `*.json` | Service configs, feature flags, analytics endpoints, menu/product data with internal references |
| **P1** | `env.txt` or similar | Internal environment names (dev/staging/prod) |
| **P1** | `*.js` files | JavaScript bridges (native<->web API), test harnesses |
| **P2** | `*.html` | Test pages, debug interfaces shipped in production |
| **P2** | Main binary (strings) | Hardcoded URLs, API keys, debug strings |

**Key analysis techniques:**

1. **Framework inventory**: List `Frameworks/` to identify the full security stack:
   - Certificate pinning libs (TrustKit, etc.) — primary bypass target
   - Anti-fraud/bot detection (Akamai, ArkoseLabs, etc.)
   - Behavioral biometrics (BioCatch, NuDetect, etc.)
   - Testing frameworks in production (OHHTTPStubs, etc.) — **Critical finding**
   - GraphQL clients (Apollo) — indicates GraphQL API surface
   - Analytics suites — supply chain risk surface

2. **JavaScript bridge analysis**: Many apps use WebView bridges for native<->web communication. Bridge files reveal the complete native API surface, URL schemes, auth mechanisms, and available commands.

3. **Test artifact detection**: Look for test harnesses, stub libraries, commented-out debug functions, and cross-platform code leakage (e.g., Android paths in iOS builds).

4. **Binary plist decoding**: Use `decode_plist(data_base64, keys_of_interest="token,password,key")` from Analysis-MCP. It handles both binary and XML plists and can highlight security-relevant keys.

5. **Core Data model analysis**: The `.momd/` directory contains `.mom` plist files (NSKeyedArchiver format) that define the complete database schema — entity names, attribute types, and relationships. This reveals sensitive field storage (plaintext credit card columns, password fields, PII) before any user data exists. Core Data prefixes SQL columns with `Z` (e.g., `creditCardNumber` → `ZCREDITCARDNUMBER`). If `decode_plist` fails with "UID is not JSON serializable", the partial output before the error often contains the critical schema info.

6. **Firebase/Google Service config analysis**: `GoogleService-Info.plist` contains API keys, project IDs, storage bucket names, and GCM sender IDs. Use these to enumerate Firebase Realtime Database/Firestore, test Cloud Storage bucket access rules, and probe for misconfigured security rules. Always check if the Firebase project is publicly accessible.

7. **Pre-production endpoint discovery**: Use `extract_strings(data_base64, keywords="dev,staging,test,preprod,uat")` or `binary_search(data_base64, keywords="staging,preprod,internal,dev")` from Analysis-MCP to find internal hostnames in any binary data.

8. **Cookie analysis**: Use `decode_binarycookies(data_base64)` from Analysis-MCP to parse iOS `Cookies.binarycookies` into structured JSON with domains, names, values, flags, and expiry.

9. **JWT token analysis**: Use `decode_jwt(token)` from Analysis-MCP to decode tokens found in plists or traffic. Shows header, claims, expiry status, and lifetime.

10. **Provisioning profile analysis**: Use `decode_mobileprovision(data_base64)` from Analysis-MCP to extract entitlements, team info, and capabilities from `embedded.mobileprovision`. Key checks: `get-task-allow` (debug entitlement — Critical if true in distribution), keychain-access-groups (wildcard = Medium), profile expiry, payment entitlements (`com.apple.developer.in-app-payments`).

11. **Adobe AEP config analysis**: Use `decode_aep_config(data_base64)` from Analysis-MCP to expand nested JSON in Adobe Experience Platform files and highlight security-relevant fields (environment, config IDs, org IDs).

12. **SQLite database analysis**: Use `summarize_sqlite_strings(data_base64, keywords="password,token,key,credit,card,ssn")` from Analysis-MCP to extract schemas and search for sensitive data in SQLite files without needing a full SQL client. For Core Data databases, look for `Z`-prefixed column names matching the `.mom` schema.

**OWASP Classification**: Static bundle findings map to **M7 — Insufficient Binary Protections** (binary/code exposure), **M1 — Improper Platform Usage** (ATS disabled, debug entitlements, Firebase misconfiguration), and **M9 — Insecure Data Storage** (Core Data schema revealing plaintext sensitive fields).

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

**IMPORTANT**: The Data Container UUID is DIFFERENT from the Bundle UUID. To find it:
1. **Use `corellium_find_app_data_container(instance_id, bundle_id)`** — automatically scans all containers and returns the UUID, full path, and common sub-paths (Preferences, Caches, Documents, SplashBoard). This is the recommended approach.
2. Fallback: List `/var/mobile/Containers/Data/Application/` and match timestamps with app install time from `corellium_list_apps`, or browse each UUID looking for `Library/Preferences/[bundleId].plist`.

| Path | What to look for | Analysis-MCP Tool |
|------|-----------------|-------------------|
| `Library/Preferences/*.plist` | NSUserDefaults — plaintext keys, tokens, passwords, analytics config | `decode_plist` |
| `Library/Preferences/[bundleId].plist` | Main app prefs — often contains auth tokens, device IDs, environment flags | `decode_plist` with `keys_of_interest="token,password,key,session"` |
| `Library/Cookies/Cookies.binarycookies` | Session cookies, HttpOnly/Secure flag analysis | `decode_binarycookies` |
| `Documents/*.sqlite` / `*.db` | SQLite databases — user data, cached content, analytics events | `summarize_sqlite_strings` |
| `Library/com.adobe.aep.datastore/` | Adobe AEP config files — environment IDs, staging mode indicators | `decode_aep_config` |
| `Library/WebKit/WebsiteData/HSTS.plist` | HSTS-enforced domains — reveals the app's complete network contact map | `decode_plist` |
| `Library/Caches/` | HTTP cache, WebKit data, CMS content | `extract_strings` |
| `tmp/` | Temp files, cached downloads, analytics rule ZIPs | varies |

**Android** (rooted, internal at `/data/data/[package]/`):

| Path | What to look for |
|------|-----------------|
| `shared_prefs/*.xml` | SharedPreferences — plaintext credentials |
| `databases/*.db` | SQLite databases — user data |
| `cache/` | WebView cache, temp data |
| `/sdcard/Android/data/[package]/` | World-readable external storage |

```
# iOS: Download and decode preferences
corellium_download_file(instance_id="...", device_path="/var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/com.target.app.plist")
# Pass the base64 result directly to Analysis-MCP:
decode_plist(data_base64="...", keys_of_interest="token,password,key,session,auth,jwt")

# iOS: Analyze cookies
corellium_download_file(instance_id="...", device_path="/var/mobile/Containers/Data/Application/[UUID]/Library/Cookies/Cookies.binarycookies")
decode_binarycookies(data_base64="...")

# Android:
corellium_download_file(instance_id="...", device_path="/data/data/com.target.app/shared_prefs/...")
```

**Key analysis patterns from real-world testing:**
- **Core Data SQLite databases**: Check `Library/Application Support/*.sqlite` for Core Data databases. Cross-reference column names against the `.mom` schema from the app bundle. Core Data prefixes columns with `Z` — look for `ZCREDITCARDNUMBER`, `ZPASSWORD`, `ZSSN`, etc. as plaintext `VARCHAR` columns. Also check `Documents/*.sqlite`.
- **JWT tokens in NSUserDefaults**: Apps commonly store long-lived JWT auth tokens in plaintext plists. Decode with `decode_jwt` to check expiry (90-day tokens are common and exploitable).
- **Analytics SDKs store sensitive data**: Glassbox, Adobe AEP, Tealium, and AppDynamics all create their own plist/JSON/SQLite files with session IDs, device fingerprints, and sometimes captured user input.
- **Session replay analytics**: Some analytics SDKs (e.g., Glassbox) capture unmasked usernames and report to pre-production (UAT) environments — Critical finding when data hardening is disabled.
- **HSTS plist as recon**: The WebKit HSTS plist contains every domain the app enforces HTTPS on, including internal/pre-production domains the app contacted.
- **100-year tracking IDs**: Analytics SDKs often store persistent visitor/device IDs with extremely long expiry (100 years) — a privacy finding.
- **Data container UUIDs change across reboots**: Always use `corellium_find_app_data_container` at the start of each session — never cache a UUID from a previous session. UUIDs regenerate on device reboot/state changes, and stale UUIDs produce silent 400 errors on every file operation.
- **Virtual environment detection keys**: Apps may detect they are running on a virtual device and write platform-specific keys to NSUserDefaults (e.g., keys prefixed with `Corellium.`). Check for these — if the app adjusts behavior based on environment detection, pentest results may differ from physical devices. This maps to MASVS-RESILIENCE.
- **Debug features active in production**: Look for diagnostic flags in NSUserDefaults like cookie loggers, debug modes, or introspection flags that should be disabled in release builds. These are M9/M8 findings.
- **AppDynamics screenshot capture**: AppDynamics creates `Library/Caches/com.appdynamics.screenshots/` with `Upload/`, `ScreenshotCache/`, `ScreenshotDemandCache/`, and `ScreenshotCrash/` directories. Even if empty, this infrastructure means the SDK can capture and upload screenshots of app screens — a data leakage vector for sensitive financial or personal data.

**Cross-reference with Parley**: Compare credentials found in storage against credentials seen in network traffic. If the same token appears in both NSUserDefaults/SharedPreferences AND HTTP headers, it's being stored insecurely.

### Phase 4: Active Network Testing (MASVS-NETWORK) — Parley + Corellium

**Maps to OWASP M5 (Insecure Communication)**. This is where the combined stack is most powerful.

**Two strategies** — use both:

#### Strategy A: Direct Backend Probing (No Device Traffic Routing)

Extract tokens/cookies/endpoints from the device (Phase 3), then use Parley to probe backends directly from the local machine. This is faster and avoids tunneling complexity.

```
# 1. Start separate proxy instances for each backend discovered in static analysis
proxy_start(target_host="auth.target.com", target_port=443, use_tls_server=True, no_verify=True, listen_port=8081, name="auth-probe")
proxy_start(target_host="api.target.com", target_port=443, use_tls_server=True, no_verify=True, listen_port=8082, name="api-probe")
proxy_start(target_host="cdn.target.com", target_port=443, use_tls_server=True, no_verify=True, listen_port=8083, name="cdn-probe")

# 2. Deploy security analysis modules on all proxies
module_deploy_template(template_name="security_header_audit")
module_deploy_template(template_name="auth_token_extractor")

# 3. Probe endpoints with extracted JWT/cookies
http_request(instance_id="abc123", method="GET", path="/api/v1/profile",
    headers='{"Authorization": "Bearer <extracted-jwt>"}')

# 4. Scan for common paths
http_scan(instance_id="abc123",
    paths='["/", "/api", "/admin", "/graphql", "/.env", "/robots.txt", "/sitemap.xml", "/.well-known/openid-configuration"]')

# 5. Check CDN for information disclosure (404 pages leak CSP headers)
http_request(instance_id="cdn123", path="/nonexistent-path-12345")

# 6. Test JWT replay
http_request(instance_id="abc123", path="/api/v1/session",
    headers='{"Authorization": "Bearer <jwt-from-plist>"}')
```

**Key probing patterns discovered through real-world testing:**
- **Pre-production endpoints are often internet-accessible** — protected only by WAF, not network segmentation
- **404 error pages return CSP headers** that expose the complete third-party service map (40+ services in real tests)
- **Server headers leak infrastructure** — look for `Server:`, `X-Powered-By:`, custom headers revealing CDN/WAF/framework info
- **WAFs may return 200 for blocked requests** — always inspect response bodies, not just status codes
- **CDN-hosted analytics configs** (Adobe Launch rules, etc.) may be publicly downloadable without authentication

#### Strategy B: Device Traffic Interception (Full MITM)

```
# 1. Start Parley with auto-cert for device MITM
cert_generate_ca()
proxy_start(target_host="api.target.com", target_port=443, use_tls_server=True, no_verify=True,
    auto_cert=True, listen_port=8080)

# 2. Install Parley CA cert on device
corellium_install_profile(instance_id="...", base64_profile="<parley-ca-cert>")

# 3. Run app and analyze
corellium_run_app(instance_id="...", bundle_id="com.target.app")
traffic_summary(instance_id="...")
traffic_search(instance_id="...", pattern="password|token|Bearer|api_key")
traffic_query(instance_id="...", decode_as="http")
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

### Phase 5: Dynamic Analysis with CoreTrace + SSH

**Maps to OWASP M1, M3, M8**. CoreTrace monitors syscalls at the hypervisor level — undetectable.

```
corellium_start_core_trace(instance_id="...")
corellium_run_app(instance_id="...", bundle_id="com.target.app")
# Retrieve trace data (with optional PID filtering)
corellium_get_core_trace(instance_id="...", lines=2000)
corellium_get_core_trace(instance_id="...", pid_filter="1234")
corellium_stop_core_trace(instance_id="...")
```

**SSH shell access** — when `run_app` returns 400 or you need direct shell control:

```
# Launch app via SSH (bypasses REST run_app issues)
corellium_ssh_exec(instance_id="...", command="uiopen com.target.app")

# Run keychain-dumper to extract stored credentials
corellium_ssh_exec(instance_id="...", command="/usr/bin/keychain-dumper")
# Then: decode_keychain_dump(data="<output>")

# Binary string extraction (highest-yield dynamic analysis step)
corellium_ssh_exec(instance_id="...", command="strings /path/to/AppBinary | grep -iE 'password|credential|secret|admin|http|key|token'")

# Process enumeration (check for Frida, security services)
corellium_ssh_exec(instance_id="...", command="ps aux")
corellium_ssh_exec(instance_id="...", command="netstat -an | grep LISTEN")

# Run FRIDA to hook specific functions (pre-installed on Corellium devices)
corellium_ssh_exec(instance_id="...", command="frida -U -n TargetApp -e 'ObjC.classes.NSURLSession...'")

# Run objection for runtime exploration
corellium_ssh_exec(instance_id="...", command="objection --gadget com.target.app explore")

# Monitor file I/O in real-time (CoreTrace fallback)
corellium_ssh_exec(instance_id="...", command="fs_usage -w -f filesys TargetApp")

# Enumerate files with find
corellium_ssh_exec(instance_id="...", command="find /var/mobile/Containers/Data/Application/ -name '*.plist' -mmin -5")

# Check running processes
corellium_ssh_exec(instance_id="...", command="ps aux | grep -i target")
```

**UI automation** — for login flows, consent dialogs, or exercising app features (may be blocked on enterprise instances — see rule 47):

```
# Take screenshot to see current UI state
corellium_screenshot(instance_id="...")

# Inject touch event (x, y coordinates from screenshot analysis)
corellium_inject_input(instance_id="...", input_json='[{"type":"touch","x":200,"y":400}]')

# Type text into focused field
corellium_inject_input(instance_id="...", input_json='[{"type":"text","value":"test@example.com"}]')

# If inject_input returns 400, use FRIDA as fallback (pre-installed on Corellium devices)
corellium_ssh_exec(instance_id="...", command="frida -U -n TargetApp -e '...'")
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

### Corellium-MCP (68+ tools)

**Connection**: `corellium_connect`, `corellium_disconnect`, `corellium_connections`, `corellium_list_projects`, `corellium_get_project`

**Devices**: `corellium_list_models`, `corellium_get_model_software`, `corellium_create_instance`, `corellium_list_instances`, `corellium_get_instance`, `corellium_start_instance`, `corellium_stop_instance`, `corellium_reboot_instance`, `corellium_pause_instance`, `corellium_unpause_instance`, `corellium_delete_instance`, `corellium_screenshot`, `corellium_console_log`, `corellium_agent_ready`

**Apps**: `corellium_list_apps`, `corellium_install_app`, `corellium_uninstall_app`, `corellium_run_app`, `corellium_kill_app`

**Filesystem**: `corellium_list_files`, `corellium_upload_file`, `corellium_download_file`, `corellium_delete_file`, `corellium_find_app_data_container` (find data container UUID by bundle ID — essential first step for any app data analysis)

**Snapshots**: `corellium_list_snapshots`, `corellium_create_snapshot`, `corellium_restore_snapshot`, `corellium_delete_snapshot`

**Network**: `corellium_start_network_monitor`, `corellium_stop_network_monitor`, `corellium_download_network_capture`, `corellium_get_network_info`

**SSL**: `corellium_disable_ssl_pinning`, `corellium_enable_ssl_pinning` (note: jailbroken devices have SSL pinning disabled by default; these are WebSocket-based agent ops and may require the JS SDK)

**SSH**: `corellium_ssh_exec` — execute shell commands on the device via SSH (paramiko). **Preferred method** for shell access since REST `shell_exec` uses WebSocket protocol. Auto-exposes port 22. Unlocks `strings` on large binaries, keychain-dumper, FRIDA, objection, class-dump, process enumeration, `fs_usage`, app launching via `uiopen`, and arbitrary device commands. Default creds: `root`/`alpine`.

**UI Automation**: `corellium_inject_input` — inject touch/keyboard/text input events for UI automation during dynamic testing

**MATRIX**: `corellium_create_assessment`, `corellium_get_assessment`, `corellium_start_monitoring`, `corellium_stop_monitoring`, `corellium_run_security_tests`, `corellium_download_security_report`, `corellium_delete_assessment`

**Hooks**: `corellium_list_hooks`, `corellium_create_hook`, `corellium_delete_hook`, `corellium_execute_hooks`, `corellium_clear_hooks`

**CoreTrace**: `corellium_start_core_trace`, `corellium_stop_core_trace`, `corellium_get_core_trace` (retrieve trace data with optional PID filter — avoids needing UI access for large trace files), `corellium_clear_core_trace`

**System**: `corellium_lock_device`, `corellium_unlock_device`, `corellium_get_system_property`, `corellium_set_device_peripherals`, `corellium_get_device_peripherals`, `corellium_get_kernel_panics`, `corellium_clear_kernel_panics`, `corellium_set_hostname`, `corellium_system_shutdown`

**Ports/Profiles**: `corellium_enable_port`, `corellium_disable_port`, `corellium_list_profiles`, `corellium_install_profile`, `corellium_uninstall_profile`

### Parley-MCP (25 tools)

**Proxy**: `web_proxy_setup`, `proxy_start` (now with `auto_cert` and `upstream_proxy` params), `proxy_stop`, `proxy_list`, `proxy_status`

**Modules**: `module_create`, `module_update`, `module_delete`, `module_set_enabled`, `module_list`, `module_deploy_template` (pre-built security modules)

**Traffic**: `traffic_query` (now with `decode_as="http"` for parsed HTTP), `traffic_summary`, `traffic_connections`, `traffic_clear`, `traffic_search`, `traffic_export` (HAR format), `traffic_replay` (replay captured requests with modifications)

**HTTP Tools**: `http_request` (send HTTP through proxy with auto cookie jar; structured error handling for timeouts/TLS/connection failures), `http_scan` (multi-path endpoint scanning with security header audit; use `include_headers=True` for full response headers per request)

**Certificates**: `cert_generate_ca` (generate MITM root CA; per-host certs auto-generated via `auto_cert=True` on `proxy_start`)

**Cookie Jar**: `cookie_jar_show`, `cookie_jar_clear` (automatic cross-request cookie persistence)

**Templates**: 5 pre-built security modules via `module_deploy_template`: `security_header_audit`, `cors_tester`, `auth_token_extractor`, `response_scanner`, `request_logger`

### Analysis-MCP (15 tools)

**Plist/Config**: `decode_plist` (binary + XML plists with key highlighting), `encode_plist` (JSON → binary/XML plist as base64; enables download → decode → modify → encode → upload workflow), `decode_mobileprovision` (iOS provisioning profiles with entitlement extraction)

**Data Formats**: `decode_base64_json` (base64 JSON with nested expansion), `decode_binarycookies` (iOS Cookies.binarycookies parser), `decode_jwt` (JWT decode with expiry analysis), `decode_aep_config` (Adobe AEP identity/config with security highlights)

**Binary Analysis**: `extract_strings` (ASCII string extraction with keyword filtering), `binary_search` (keyword search with byte-offset context), `summarize_sqlite_strings` (SQLite schema + string extraction)

**Keychain**: `decode_keychain_dump` — parse iOS keychain-dumper output (XML plist or text). Extracts service names, accounts, access groups, data values, accessibility flags. Provides a security summary with counts by class and items with dangerous accessibility (e.g., `kSecAttrAccessibleAlways`). Use with `corellium_ssh_exec` to run keychain-dumper and pipe output here.

**Anti-Bot**: `decode_akamai_sensor` — decode Akamai BMP sensor payloads from `com.akamai.botman.defaults.sensor_data`. Auto-detects delimiter format (semicolon, dollar, or comma). Extracts timestamps, URLs, encoded blocks, and payload statistics. Used for understanding device fingerprint data and preparing sensor replay attacks.

**Screenshots**: `analyze_screenshot` — analyze PNG/JPEG screenshots or SplashBoard snapshots. Extracts dimensions, format, PNG text chunks, EXIF metadata, sensitive content keywords, and blank screen detection. Use for SplashBoard data leakage analysis.

**File Utility**: `save_base64_to_file` — save base64-encoded data to a local file. Handles padding correction automatically. Use to save Corellium screenshots as viewable PNGs, downloaded binaries/databases locally, or any base64 content for external tool analysis. Eliminates the need for ad-hoc Python/shell scripts to decode base64.

**Usage pattern**: Corellium downloads raw base64 files → pass directly to Analysis-MCP tools → get structured JSON back. No temp scripts needed. For saving files locally: `corellium_screenshot` or `corellium_download_file` → `save_base64_to_file(data_base64, "output.png")`. For keychain analysis: `corellium_ssh_exec` runs `keychain-dumper` → pass output to `decode_keychain_dump`. For config modification: `decode_plist` → modify JSON → `encode_plist` → `corellium_upload_file`.

## Critical Rules

1. **Always** call `corellium_agent_ready` before any agent operation (apps, files, system). After `corellium_start_instance`, the agent can take **2-3 minutes** to become ready — poll every 20-30 seconds. If not ready, the tool returns `Agent ready: False` with the error details (e.g., 503).
2. **Always** snapshot before destructive testing
3. **Always** perform static analysis of the app bundle BEFORE launching the app — this phase alone often produces Critical/High findings
4. **Always** check `corellium_list_apps` before `corellium_run_app` — if the app shows `"running": true`, you must `corellium_kill_app` first or `run_app` will return 400
5. MATRIX monitoring (`start_monitoring`/`stop_monitoring`) requires an `assessment_id` — it is separate from the network monitor (sslsplit). Create the assessment first.
6. Network Monitor uses sslsplit endpoints (`/sslsplit/enable`, `/sslsplit/disable`) and requires both Wi-Fi and cellular enabled
7. iOS filesystem access requires jailbroken device; Android requires root
8. SSH default credentials: `root` / `alpine` (iOS jailbroken)
9. Common exposed ports: SSH=22, FRIDA=27042, ADB=5555
10. Binary data (files, screenshots, PCAPs, reports) is base64-encoded in Corellium tool responses. Use **Analysis-MCP** tools (`decode_plist`, `decode_binarycookies`, `decode_jwt`, etc.) to decode — pass the base64 string directly.
11. Jailbroken devices have iOS SSL pinning disabled by default — no need to call `disableSSLPinning` unless re-enabled
12. Some agent operations (`shellExec`, `disableSSLPinning`, `runFrida`, `runFridaPs`) use the WebSocket agent protocol, not REST. They may require the Corellium JS SDK or SSH access instead.
13. CoreTrace is hypervisor-level — **undetectable** by the target app
14. Parley modules are Python functions: `def module_function(msg_num, src_ip, src_port, dst_ip, dst_port, data)` → return modified `data` (bytearray)
15. Use `traffic_clear` between test iterations to isolate results
16. Use `show_modified=True` in `traffic_query` to compare original vs rewritten traffic
17. iOS app bundles are at `/private/var/containers/Bundle/Application/[UUID]/[App].app/` — use `corellium_list_files` to browse
18. Document findings progressively in a markdown report with OWASP Mobile Top 10 classifications
19. **iOS Data Container** path is `/var/mobile/Containers/Data/Application/[UUID]/` (NOT `/private/var/containers/Data/Application/` — the latter returns 400). The Data UUID is **different** from the Bundle UUID — use `corellium_find_app_data_container(instance_id, bundle_id)` to find it automatically instead of manually scanning.
20. **Parley can probe backends independently** — extract tokens/cookies from the device, then use `http_request` or `http_scan` to test backend endpoints directly from the local machine without routing device traffic through the proxy.
21. **Deploy multiple Parley proxies** for different backend endpoints (auth server, CDN, API gateway, etc.) — each gets its own instance ID and traffic database.
22. **CDN/404 pages leak CSP headers** — even error responses often include Content-Security-Policy headers that expose the complete third-party service map. Always request a non-existent path.
23. **WAFs return misleading status codes** — some WAFs (e.g., Akamai) return HTTP 200 for blocked requests instead of 403/405, which can confuse automated scanners. Always inspect response bodies, not just status codes.
24. **Use `corellium_ssh_exec` for shell commands** — the REST API's `shell_exec` uses WebSocket protocol and fails with 404. SSH via paramiko is the reliable alternative for running `strings`, keychain-dumper, FRIDA, objection, `plutil`, `sqlite3`, `find`, `ps aux`, `netstat`, `lsof`, `fs_usage`, and any arbitrary device commands. Port 22 is auto-exposed on first use. VPN access is required to reach the device's `serviceIp`. If the device is unreachable, the tool performs a fast 5-second connectivity pre-check and returns a clear diagnostic message.
25. **Keychain analysis requires SSH** — iOS keychain databases (`keychain-2.db`) are encrypted SQLite and cannot be parsed by `sqlite3` directly. Use `corellium_ssh_exec` to run `keychain-dumper` on the device, then pass the output to `decode_keychain_dump` in Analysis-MCP.
26. **UI automation via `corellium_inject_input`** — when the app needs user interaction (login flows, consent dialogs), use `corellium_inject_input` with touch/keyboard events. Combine with `corellium_screenshot` to verify UI state. **Enterprise limitation**: `corellium_inject_input` may return HTTP 400 on enterprise Corellium instances. If blocked, alternatives include: FRIDA scripting (if Frida is running on the device — check with `ps aux | grep frida`), `cycript`, or `simulatetouch` (if installed). As a last resort, rely on static/filesystem analysis without UI interaction.
27. **SplashBoard snapshots leak data** — iOS caches app screenshots in SplashBoard directories for the task switcher. These often contain sensitive data visible on screen at the time of backgrounding. **Confirmed limitation**: While `corellium_list_files` can list the SplashBoard parent directory (proving snapshots exist), the Corellium agent cannot access subdirectories with colons in their names (e.g., `sceneID:com.example.app-default`) — all attempts return 504/500 regardless of URL encoding. **However, the existence of the directory alone is a valid finding**: it proves the app does NOT implement `applicationDidEnterBackground` screenshot protection. Document as M1 — Improper Platform Usage. To extract actual snapshot images, use SSH or the Corellium UI.
28. **Akamai sensor data in NSUserDefaults** — anti-bot SDKs store device fingerprint data in plists. Use `decode_akamai_sensor` from Analysis-MCP to decode this. The presence and contents of this data reveals which endpoints are fingerprint-protected.
29. **Proxy instances with TLS** — when the target backend uses HTTPS, ensure `use_tls_server=True` on `proxy_start`. For full client-side TLS wrapping (needed when `http_request`/`http_scan`/`traffic_replay` connect to the proxy's local port), the proxy engine now supports TLS client wrapping based on the instance's `use_tls_client` setting.
30. **Plist modification workflow** — use `encode_plist` from Analysis-MCP to modify app configuration on-device: `corellium_download_file` → `decode_plist` → modify JSON → `encode_plist(json_data, output_format="binary")` → `corellium_upload_file`. Supports both binary and XML output formats.
31. **CoreTrace data retrieval** — use `corellium_get_core_trace` to download trace data directly via the API. Supports `lines` parameter (default 1000) and `pid_filter` to isolate a specific process. **Known limitation**: On some enterprise Corellium instances, `start_core_trace` and `stop_core_trace` work correctly, but the data retrieval endpoint (`/strace`) returns 404. In this case, CoreTrace data must be accessed through the Corellium web UI or VPN.
32. **`http_scan` with full headers** — use `include_headers=True` on `http_scan` to see complete response headers for each probed path. Essential for discovering CSP, Set-Cookie, X-Powered-By, and other security-relevant headers across multiple endpoints in one pass.
33. **File path URL encoding** — Corellium file operations (`list_files`, `download_file`, `upload_file`, `delete_file`) now URL-encode paths automatically. Paths containing colons, spaces, or other special characters (common in iOS SplashBoard scene IDs) no longer cause 504 errors.
34. **MATRIX enterprise restrictions** — On enterprise Corellium instances, MATRIX security assessments (`corellium_create_assessment`) may return 400 Bad Request. This is an enterprise policy restriction, not a code error. Document as a test limitation and rely on manual testing phases instead.
35. **WAF cookie naming conventions leak info** — Akamai cache directive cookies (e.g., `akacd_*`) often embed environment identifiers in their names (e.g., `m2eve` = Mobile v2 + EVE environment). These reveal internal naming conventions and confirm which environment the app connects to. Always inspect `Set-Cookie` names in WAF responses.
36. **`corellium_find_app_data_container` is the essential first step** — Before ANY data container analysis, always call this tool with the target's bundle ID. It replaces the error-prone manual approach of listing hundreds of UUIDs and guessing timestamps. The tool scans each container's `.com.apple.mobile_container_manager.metadata.plist` and matches the `MCMMetadataIdentifier` field. Returns the UUID, full path, and ready-to-use sub-paths for Preferences, Caches, Documents, SplashBoard, and tmp.
37. **ATS (App Transport Security) is a P0 check** — `NSAppTransportSecurity` in `Info.plist` with `NSAllowsArbitraryLoads: true` is a **Critical** finding (M3 — Insecure Communication). When combined with sensitive data storage (plaintext credentials, credit cards in Core Data), it creates a scenario where sensitive data may be both stored and transmitted without protection.
38. **Core Data schema reveals sensitive storage before data exists** — The `.momd/` directory in the app bundle contains `.mom` plist files defining the complete database schema. Download and decode these to identify sensitive attributes (credit card numbers, passwords, SSNs) stored as plaintext `VARCHAR` — a Critical M9 finding even if the database is empty at analysis time.
39. **`get-task-allow` entitlement in distribution builds** — This debug entitlement in `embedded.mobileprovision` permits debugger attachment (`lldb`, `dtrace`), runtime memory inspection, method swizzling, and encryption key extraction. It should never appear in App Store or Ad Hoc distribution builds. Combined with sensitive data storage, it dramatically lowers the exploitation barrier. **High** severity (M1).
40. **Jailbreak detection strength assessment** — Check `LSApplicationQueriesSchemes` in `Info.plist` for `cydia` URL scheme checks. This is a single-point detection method trivially bypassed by removing Cydia, hooking `canOpenURL:`, or using rootless jailbreaks. Classify as **Medium** (M8) and document the bypass difficulty. Multi-layered detection (file checks, sandbox tests, `_dyld_image_count`, code signature validation) is significantly stronger.
41. **Keychain access group scope** — Check entitlements for wildcard keychain access groups (e.g., `TEAMID.*`). A wildcard allows any app signed by the same Team ID to read keychain items, which expands the attack surface if any app from that developer is compromised. Recommend restricting to the specific app identifier. **Medium** (M9).
42. **SplashBoard scene ID format varies** — Not all apps use colons in SplashBoard scene IDs. Some use formats like `{DEFAULT GROUP}` with braces and spaces, which the Corellium agent CAN access (unlike colon-based `sceneID:...` paths). Always attempt to list and download SplashBoard snapshots — the accessibility depends on the app's scene naming convention.
43. **Large binary files require SSH for string extraction** — App binaries over ~1MB produce base64 output that exceeds API character limits. The `extract_strings` tool from Analysis-MCP works for smaller files, but for large binaries, use SSH: `corellium_ssh_exec(command="strings /path/to/binary | grep -iE 'password|key|token|http|secret|admin|credential'")`. This is one of the highest-yield dynamic analysis steps — hardcoded credentials, URLs, XSS endpoints, and debug messages are commonly found. Always pipe through `grep` to filter for security-relevant strings.
44. **Enterprise `corellium_run_app` 400 is a persistent limitation** — On enterprise Corellium instances, `corellium_run_app` may consistently return 400 regardless of app state (running or stopped). This is distinct from the "app already running" 400 error. Workaround: use `corellium_ssh_exec(command="uiopen com.target.app")` via SSH. Note: `open` is NOT a valid iOS command — use `uiopen <bundleid>` (without `--bundleid` flag).
45. **Frida is pre-installed on Corellium jailbroken devices** — Check with `corellium_ssh_exec(command="ps aux | grep frida")`. Frida server typically runs as root on PID ~200, listening on `127.0.0.1:27042`. This means: runtime instrumentation is available out of the box, method hooking requires zero setup, and all app security controls (jailbreak detection, SSL pinning, root checks) can be bypassed with Frida scripts. Verify with `netstat -an | grep 27042`.
46. **`fs_usage` as CoreTrace fallback** — When `corellium_get_core_trace` returns 404 (enterprise restriction), use `corellium_ssh_exec(command="fs_usage -w -f filesys <AppName>")` or `fs_usage -w -f network <AppName>` to monitor file and network I/O in real-time via SSH. Less comprehensive than CoreTrace (no syscall-level detail) but useful for observing which files the app reads/writes during specific operations.
47. **Enterprise `corellium_inject_input` 400** — On enterprise instances, `corellium_inject_input` may return HTTP 400 for all input types (touch, keyboard, text — both single events and arrays). This blocks UI automation entirely. Fallbacks: FRIDA scripting for UI interaction, or focus on static/filesystem/network analysis without exercising UI flows. Document as a test limitation and note which findings require UI interaction to fully validate.
48. **Process enumeration via SSH** — `corellium_ssh_exec(command="ps aux")` reveals all running processes including security-relevant services (Frida, sshd, system daemons). `netstat -an` shows listening ports and active connections. `lsof -i` shows which processes have network sockets open. These commands provide runtime context that static analysis cannot — always run them at the start of a dynamic analysis session.
49. **Keychain analysis without keychain-dumper** — If `keychain-dumper` is not installed on the device, you can still query `keychain-2.db` metadata via `corellium_ssh_exec(command="sqlite3 /var/Keychains/keychain-2.db '.schema'")` and `sqlite3 /var/Keychains/keychain-2.db 'SELECT agrp, srvr, sdmn FROM inet'`. The data column is encrypted, but metadata (access groups, server names, domains) may reveal which services the app stores credentials for. No app-specific entries found before login confirms the keychain is populated post-authentication.
50. **Binary string categories to search** — When running `strings` on app binaries via SSH, search for these categories with separate grep passes: credentials (`grep -iE 'password|credential|secret|admin|login'`), URLs (`grep -iE 'https?://'`), XSS/injection (`grep -iE 'script|xss|inject|alert'`), jailbreak detection (`grep -iE 'cydia|jailbreak|/Applications/'`), debug messages (`grep -iE 'debug|test|TODO|FIXME|HACK'`), and developer info (`grep -iE '/Users/|DerivedData|Xcode'`). Each category frequently yields different finding severities.
51. **iOS Frida touch simulation is unreliable — call handlers directly** — On iOS, Frida cannot reliably simulate coordinate-based taps like on Android. `ObjC.Block` has bugs in Frida 16.6.6 for completion handlers. Synthetic `UITouch`/`UIEvent` via private APIs is fragile and timing-sensitive. Instead: (a) For UIKit buttons, use `sendActionsForControlEvents_(1 << 6)` (UIControlEventTouchUpInside). (b) For tab navigation, use `UITabBarController.setSelectedIndex_(n)`. (c) For Firebase Auth, call the REST API directly with the embedded API key. (d) For SwiftUI buttons with no ObjC bridge, consider PTFakeTouch/simulatetouch dylibs or call the underlying handler directly. Pure Swift classes have `$ownMethods: []` in Frida's ObjC bridge — use `valueForKey:` for KVO properties or find the function via `Module.enumerateExports`.
52. **Authorization bypass via UITabBarController** — On apps with tabbed navigation, test if all tabs are accessible without login by setting `UITabBarController.setSelectedIndex_(n)` via Frida. This is a common authorization bypass in iOS apps that rely solely on the login screen being the initial tab. Classify as **High** (M6: Insecure Authorization) if sensitive functionality (ordering, payment, profile) is accessible.
53. **SwiftUI apps have limited Frida ObjC bridge access** — Pure Swift classes (e.g., `@ObservableObject` view models) have `$ownMethods: []` and `$ownProperties` throws `TypeError`. The ObjC bridge only sees methods annotated with `@objc` or inherited from NSObject. For SwiftUI text input, use `becomeFirstResponder()` + `insertText:` instead of `setText:` (which bypasses SwiftUI bindings and gets cleared). For navigation, target UIKit hosting controllers (`UITabBarController`, `UINavigationController`) rather than SwiftUI views.
54. **Firebase REST API for credential verification** — When you have an app's Firebase API key (from `GoogleService-Info.plist`), test the credentials directly via: `curl -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=API_KEY' -d '{"email":"...","password":"...","returnSecureToken":true}'`. If the backend returns `CONFIGURATION_NOT_FOUND`, the Firebase project is decommissioned/misconfigured — note as Informational finding.
55. **Ask the human to tap on iOS when programmatic touch fails** — iOS SwiftUI apps resist programmatic touch simulation (Frida ObjC.Block bugs, no PTFakeTouch, `corellium_inject_input` 400). Do NOT waste time on synthetic UITouch/UIEvent private APIs or IOKit HID events. Instead: (a) Use Frida to fill text fields (`insertText:`), set state, and prepare the app. (b) **Ask the user to tap buttons** in the Corellium web console — they can see and interact with the virtual device screen directly. (c) Take a screenshot and tell the user exactly what to tap (e.g., "Please tap the Login button on the device screen"). (d) After they tap, take another screenshot to verify and continue analysis. This human-in-the-loop approach is far more reliable and efficient than fighting iOS touch simulation. Reserve programmatic approaches for UIKit controls that support `sendActionsForControlEvents_` or `UITabBarController.setSelectedIndex_`.
