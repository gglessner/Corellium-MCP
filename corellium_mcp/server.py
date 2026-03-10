"""Corellium MCP Server — mobile penetration testing tools.

Exposes Corellium virtual device management, app security testing,
filesystem access, network capture, MATRIX security assessments,
hypervisor hooks, and CoreTrace via the Model Context Protocol.
"""

from __future__ import annotations

import base64
import json
import os
import plistlib
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import CorelliumClient

mcp = FastMCP(
    "corellium-mcp",
    instructions=(
        "Mobile penetration testing with Corellium virtual devices. "
        "Manage iOS/Android instances, install/analyze apps, access "
        "filesystems, capture network traffic, run MATRIX security "
        "assessments, and instrument at the hypervisor level."
    ),
)

# Global connection registry: connection_id -> CorelliumClient
_connections: dict[str, CorelliumClient] = {}


def _get_client(connection_id: str = "default") -> CorelliumClient:
    """Retrieve an active client or raise a helpful error."""
    if connection_id not in _connections:
        raise ValueError(
            f"No active connection '{connection_id}'. "
            "Call corellium_connect first."
        )
    return _connections[connection_id]


def _summarize(data: Any, max_items: int = 50) -> str:
    """Return a JSON string, truncating large lists for readability."""
    if isinstance(data, list) and len(data) > max_items:
        return json.dumps(data[:max_items], indent=2, default=str) + (
            f"\n... ({len(data) - max_items} more items)"
        )
    if isinstance(data, bytes):
        return f"<binary data, {len(data)} bytes>"
    return json.dumps(data, indent=2, default=str)


# =====================================================================
# Connection management
# =====================================================================


@mcp.tool()
async def corellium_connect(
    api_endpoint: str = "",
    api_token: str = "",
    connection_id: str = "default",
) -> str:
    """Connect to a Corellium instance.

    Reads CORELLIUM_API_ENDPOINT and CORELLIUM_API_TOKEN from environment
    variables if not provided. Supports multiple concurrent connections
    via connection_id.

    Args:
        api_endpoint: API URL (e.g. https://app.corellium.com/api).
                      Falls back to CORELLIUM_API_ENDPOINT env var.
        api_token: Bearer token. Falls back to CORELLIUM_API_TOKEN env var.
        connection_id: Label for this connection (default: "default").
    """
    endpoint = api_endpoint or os.environ.get("CORELLIUM_API_ENDPOINT", "")
    token = api_token or os.environ.get("CORELLIUM_API_TOKEN", "")

    if not endpoint:
        return "Error: api_endpoint not provided and CORELLIUM_API_ENDPOINT not set."
    if not token:
        return "Error: api_token not provided and CORELLIUM_API_TOKEN not set."

    client = CorelliumClient(endpoint, token)
    try:
        projects = await client.get_projects()
        _connections[connection_id] = client
        project_names = [p.get("name", p.get("id", "?")) for p in projects]
        return (
            f"Connected to {endpoint} as '{connection_id}'. "
            f"Projects visible: {project_names}"
        )
    except Exception as e:
        await client.close()
        return f"Connection failed: {e}"


@mcp.tool()
async def corellium_disconnect(connection_id: str = "default") -> str:
    """Disconnect from a Corellium instance and release resources.

    Args:
        connection_id: Which connection to close.
    """
    if connection_id in _connections:
        await _connections[connection_id].close()
        del _connections[connection_id]
        return f"Disconnected '{connection_id}'."
    return f"No connection '{connection_id}' found."


@mcp.tool()
async def corellium_connections() -> str:
    """List all active Corellium connections."""
    if not _connections:
        return "No active connections."
    lines = [
        f"  {cid}: {c.endpoint}" for cid, c in _connections.items()
    ]
    return "Active connections:\n" + "\n".join(lines)


# =====================================================================
# Projects
# =====================================================================


@mcp.tool()
async def corellium_list_projects(connection_id: str = "default") -> str:
    """List all projects visible to the authenticated user.

    Args:
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    projects = await client.get_projects()
    return _summarize(projects)


@mcp.tool()
async def corellium_get_project(
    project_id: str, connection_id: str = "default"
) -> str:
    """Get detailed info about a specific project.

    Args:
        project_id: The project UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_project(project_id))


# =====================================================================
# Models & firmware
# =====================================================================


@mcp.tool()
async def corellium_list_models(connection_id: str = "default") -> str:
    """List all supported device models (hardware flavors).

    Returns model names like iphone16pm, ipad9, pixel7, etc.

    Args:
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_models())


@mcp.tool()
async def corellium_get_model_software(
    model: str, connection_id: str = "default"
) -> str:
    """List available firmware/OS versions for a specific device model.

    Args:
        model: Device model (e.g. "iphone16pm", "pixel7").
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_model_software(model))


# =====================================================================
# Instance (virtual device) management
# =====================================================================


@mcp.tool()
async def corellium_list_instances(
    connection_id: str = "default",
) -> str:
    """List all virtual device instances.

    Args:
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    instances = await client.get_instances()
    summary = []
    for inst in instances:
        summary.append({
            "id": inst.get("id"),
            "name": inst.get("name"),
            "flavor": inst.get("flavor"),
            "type": inst.get("type"),
            "state": inst.get("state"),
        })
    return _summarize(summary)


@mcp.tool()
async def corellium_get_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Get detailed information about a virtual device instance.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_instance(instance_id))


@mcp.tool()
async def corellium_create_instance(
    project_id: str,
    flavor: str,
    os_version: str,
    name: str = "",
    connection_id: str = "default",
) -> str:
    """Create a new virtual device instance.

    The device starts booting immediately. Use corellium_get_instance or
    corellium_agent_ready to check when it's fully available.

    Args:
        project_id: Project UUID to create the instance in.
        flavor: Hardware model (e.g. "iphone16pm", "pixel7").
        os_version: Firmware/OS version (e.g. "18.0", "14.0.0").
        name: Optional display name for the instance.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    body: dict[str, Any] = {
        "project": project_id,
        "flavor": flavor,
        "os": os_version,
    }
    if name:
        body["name"] = name
    result = await client.create_instance(body)
    return _summarize(result)


@mcp.tool()
async def corellium_start_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Power on a virtual device instance.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.start_instance(instance_id)
    return f"Instance {instance_id} is powering on."


@mcp.tool()
async def corellium_stop_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Power off a virtual device instance.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.stop_instance(instance_id)
    return f"Instance {instance_id} is powering off."


@mcp.tool()
async def corellium_reboot_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Reboot a virtual device instance.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.reboot_instance(instance_id)
    return f"Instance {instance_id} is rebooting."


@mcp.tool()
async def corellium_pause_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Pause a virtual device instance (freeze execution).

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.pause_instance(instance_id)
    return f"Instance {instance_id} is paused."


@mcp.tool()
async def corellium_unpause_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Unpause / resume a paused virtual device instance.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.unpause_instance(instance_id)
    return f"Instance {instance_id} resumed."


@mcp.tool()
async def corellium_delete_instance(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Delete a virtual device instance permanently.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.delete_instance(instance_id)
    return f"Instance {instance_id} deleted."


@mcp.tool()
async def corellium_screenshot(
    instance_id: str,
    format: str = "png",
    connection_id: str = "default",
) -> str:
    """Take a screenshot of the virtual device screen.

    Returns the screenshot as base64-encoded image data.

    Args:
        instance_id: The instance UUID.
        format: Image format — "png" or "jpeg".
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = await client.get_instance_screenshot(instance_id, format)
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:image/{format};base64,{b64}"


@mcp.tool()
async def corellium_console_log(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Get the console (kernel) log for a virtual device.

    Useful for identifying kernel panics, system errors, and boot issues.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = await client.get_console_log(instance_id)
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


@mcp.tool()
async def corellium_set_device_peripherals(
    instance_id: str,
    peripherals_json: str,
    connection_id: str = "default",
) -> str:
    """Set virtual device peripherals (GPS, battery, sensors).

    Example peripherals_json:
      {"gpsSatellites": 6, "gpsLatitude": 37.7749, "gpsLongitude": -122.4194,
       "batteryLevel": 50, "batteryCharging": false}

    Args:
        instance_id: The instance UUID.
        peripherals_json: JSON object with peripheral values to set.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    peripherals = json.loads(peripherals_json)
    result = await client.set_instance_peripherals(instance_id, peripherals)
    return _summarize(result)


@mcp.tool()
async def corellium_get_device_peripherals(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Get current peripheral state for a virtual device (GPS, battery, etc.).

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_instance_peripherals(instance_id))


# =====================================================================
# Agent readiness
# =====================================================================


@mcp.tool()
async def corellium_agent_ready(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Check if the Corellium agent on the virtual device is ready.

    The agent must be ready before app, file, or system operations work.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    try:
        result = await client.agent_ready(instance_id)
        ready = result.get("ready", result.get("status") == "ok")
        return f"Agent ready: {ready}"
    except Exception as e:
        return f"Agent ready: False ({e})"


# =====================================================================
# App management
# =====================================================================


@mcp.tool()
async def corellium_list_apps(
    instance_id: str, connection_id: str = "default"
) -> str:
    """List all installed applications on the virtual device.

    Shows bundle IDs, names, and running status. Essential for
    identifying attack surface during penetration testing.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.list_apps(instance_id))


@mcp.tool()
async def corellium_install_app(
    instance_id: str,
    file_path: str,
    connection_id: str = "default",
) -> str:
    """Install an application on the virtual device.

    The file must already be uploaded to the VM filesystem.
    Upload an IPA (iOS) or APK (Android) first using corellium_upload_file,
    then provide the on-device path here.

    Args:
        instance_id: The instance UUID.
        file_path: Path to the app on the VM (e.g. /tmp/app.ipa).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.install_app(instance_id, file_path)
    return _summarize(result)


@mcp.tool()
async def corellium_uninstall_app(
    instance_id: str,
    bundle_id: str,
    connection_id: str = "default",
) -> str:
    """Uninstall an application from the virtual device.

    Args:
        instance_id: The instance UUID.
        bundle_id: App bundle ID (e.g. com.example.app).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.uninstall_app(instance_id, bundle_id)
    return _summarize(result)


@mcp.tool()
async def corellium_run_app(
    instance_id: str,
    bundle_id: str,
    connection_id: str = "default",
) -> str:
    """Launch an application on the virtual device.

    Args:
        instance_id: The instance UUID.
        bundle_id: App bundle ID (e.g. com.example.app).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.run_app(instance_id, bundle_id)
    return _summarize(result)


@mcp.tool()
async def corellium_kill_app(
    instance_id: str,
    bundle_id: str,
    connection_id: str = "default",
) -> str:
    """Kill a running application on the virtual device.

    Args:
        instance_id: The instance UUID.
        bundle_id: App bundle ID (e.g. com.example.app).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.kill_app(instance_id, bundle_id)
    return _summarize(result)


@mcp.tool()
async def corellium_disable_ssl_pinning(
    instance_id: str,
    connection_id: str = "default",
) -> str:
    """Disable SSL certificate pinning on the virtual device.

    This uses the Corellium agent's built-in SSL pinning bypass
    which operates at the OS level. Extremely useful for MITM
    proxy-based traffic interception during security testing.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.disable_ssl_pinning(instance_id)
    return _summarize(result)


@mcp.tool()
async def corellium_enable_ssl_pinning(
    instance_id: str,
    connection_id: str = "default",
) -> str:
    """Re-enable SSL certificate pinning on the virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.enable_ssl_pinning(instance_id)
    return _summarize(result)


@mcp.tool()
async def corellium_shell_exec(
    instance_id: str,
    command: str,
    connection_id: str = "default",
) -> str:
    """Execute a shell command on the virtual device.

    Runs a command on the device and returns its output.
    Requires the device to be jailbroken/rooted.

    Args:
        instance_id: The instance UUID.
        command: Shell command to execute (e.g. "ls -la /tmp").
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.shell_exec(instance_id, command)
    return _summarize(result)


@mcp.tool()
async def corellium_start_network_monitor(
    instance_id: str,
    connection_id: str = "default",
) -> str:
    """Start the network monitor (sslsplit) on the virtual device.

    Captures all network traffic including TLS-intercepted streams.
    Use corellium_download_pcap to retrieve the capture file.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.start_network_monitor(instance_id)
    return _summarize(result)


@mcp.tool()
async def corellium_stop_network_monitor(
    instance_id: str,
    connection_id: str = "default",
) -> str:
    """Stop the network monitor on the virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.stop_network_monitor(instance_id)
    return _summarize(result)


# =====================================================================
# File operations (jailbroken/rooted filesystem access)
# =====================================================================


@mcp.tool()
async def corellium_list_files(
    instance_id: str,
    path: str,
    connection_id: str = "default",
) -> str:
    """List files and directories at a path on the virtual device.

    The device must be jailbroken/rooted for full filesystem access.
    Use this to browse app bundles, data containers, and system
    directories when searching for configuration files, plists,
    databases, and other artifacts.

    Args:
        instance_id: The instance UUID.
        path: Directory path on the device (e.g. /private/var/containers/Bundle/Application/).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.list_files(instance_id, path)
    return _summarize(result)


@mcp.tool()
async def corellium_upload_file(
    instance_id: str,
    device_path: str,
    base64_content: str,
    connection_id: str = "default",
) -> str:
    """Upload a file to the virtual device filesystem.

    The device must be jailbroken/rooted for full filesystem access.
    Content is provided as base64. Useful for deploying test tools,
    payloads, IPA/APK files, or configuration modifications.

    Args:
        instance_id: The instance UUID.
        device_path: Destination path on the device (e.g. /tmp/payload.bin).
        base64_content: File content encoded as base64.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = base64.b64decode(base64_content)
    result = await client.upload_file(instance_id, device_path, data)
    return f"Uploaded {len(data)} bytes to {device_path}. {_summarize(result)}"


@mcp.tool()
async def corellium_download_file(
    instance_id: str,
    device_path: str,
    connection_id: str = "default",
) -> str:
    """Download a file from the virtual device filesystem.

    Returns file content as base64. Useful for extracting app data,
    databases, keychains, logs, and other artifacts.

    Args:
        instance_id: The instance UUID.
        device_path: Path on the device (e.g. /var/mobile/Library/...).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = await client.download_file(instance_id, device_path)
    b64 = base64.b64encode(data).decode("ascii")
    return f"Downloaded {len(data)} bytes from {device_path}.\nBase64: {b64}"


@mcp.tool()
async def corellium_delete_file(
    instance_id: str,
    device_path: str,
    connection_id: str = "default",
) -> str:
    """Delete a file from the virtual device filesystem.

    Args:
        instance_id: The instance UUID.
        device_path: Path on the device to delete.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.delete_file(instance_id, device_path)
    return f"Deleted {device_path}."


@mcp.tool()
async def corellium_find_app_data_container(
    instance_id: str,
    bundle_id: str,
    connection_id: str = "default",
) -> str:
    """Find the data container UUID and path for an iOS app by bundle ID.

    Scans /var/mobile/Containers/Data/Application/ and reads each
    container's metadata plist to find the one matching the given
    bundle identifier.  Returns the UUID, common sub-paths (Library,
    Documents, tmp), and the container metadata.

    Args:
        instance_id: The instance UUID.
        bundle_id: The app bundle identifier (e.g. com.example.app).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    base = "/var/mobile/Containers/Data/Application"
    listing = await client.list_files(instance_id, base)
    entries = listing.get("entries", []) if isinstance(listing, dict) else listing

    for entry in entries:
        name = entry.get("name", "")
        if len(name) != 36 or name.count("-") != 4:
            continue
        meta_path = f"{base}/{name}/.com.apple.mobile_container_manager.metadata.plist"
        try:
            raw = await client.download_file(instance_id, meta_path)
            plist = plistlib.loads(raw)
            identifier = plist.get("MCMMetadataIdentifier", "")
            if identifier == bundle_id:
                container = f"{base}/{name}"
                return json.dumps({
                    "found": True,
                    "bundle_id": bundle_id,
                    "uuid": name,
                    "data_container": container,
                    "paths": {
                        "preferences": f"{container}/Library/Preferences",
                        "caches": f"{container}/Library/Caches",
                        "documents": f"{container}/Documents",
                        "tmp": f"{container}/tmp",
                        "splash_board": f"{container}/Library/SplashBoard",
                    },
                }, indent=2)
        except Exception:
            continue

    return json.dumps({
        "found": False,
        "bundle_id": bundle_id,
        "containers_scanned": len([
            e for e in entries
            if len(e.get("name", "")) == 36 and e.get("name", "").count("-") == 4
        ]),
        "error": "No data container found for this bundle ID.",
    }, indent=2)


# =====================================================================
# Snapshots
# =====================================================================


@mcp.tool()
async def corellium_list_snapshots(
    instance_id: str, connection_id: str = "default"
) -> str:
    """List all snapshots for a virtual device instance.

    Snapshots capture the full device state for quick restore. Useful
    for testing different attack scenarios from a known-good state.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_snapshots(instance_id))


@mcp.tool()
async def corellium_create_snapshot(
    instance_id: str,
    name: str,
    connection_id: str = "default",
) -> str:
    """Create a snapshot of the current device state.

    Captures full memory, disk, and CPU state. Use before destructive
    testing so you can restore to a clean state.

    Args:
        instance_id: The instance UUID.
        name: Human-readable name for the snapshot.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.create_snapshot(instance_id, name)
    return _summarize(result)


@mcp.tool()
async def corellium_restore_snapshot(
    instance_id: str,
    snapshot_id: str,
    connection_id: str = "default",
) -> str:
    """Restore a virtual device to a previous snapshot.

    Reverts memory, disk, and CPU state. The instance will reboot.

    Args:
        instance_id: The instance UUID.
        snapshot_id: The snapshot UUID to restore.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.restore_snapshot(instance_id, snapshot_id)
    return f"Restoring snapshot {snapshot_id} on instance {instance_id}."


@mcp.tool()
async def corellium_delete_snapshot(
    instance_id: str,
    snapshot_id: str,
    connection_id: str = "default",
) -> str:
    """Delete a snapshot.

    Args:
        instance_id: The instance UUID.
        snapshot_id: The snapshot UUID to delete.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.delete_snapshot(instance_id, snapshot_id)
    return f"Deleted snapshot {snapshot_id}."


# =====================================================================
# Network capture
# =====================================================================


@mcp.tool()
async def corellium_download_network_capture(
    instance_id: str,
    capture_type: str = "netdump",
    connection_id: str = "default",
) -> str:
    """Download network traffic capture (PCAP) from the virtual device.

    Returns the pcap data as base64. Analyze with Wireshark or tshark
    to inspect API calls, cleartext credentials, certificate issues, etc.

    Args:
        instance_id: The instance UUID.
        capture_type: "netdump" or "networkMonitor".
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    if capture_type == "networkMonitor":
        data = await client.download_network_monitor_pcap(instance_id)
    else:
        data = await client.download_netdump_pcap(instance_id)
    b64 = base64.b64encode(data).decode("ascii")
    return (
        f"Captured {len(data)} bytes of network traffic ({capture_type}).\n"
        f"Base64 PCAP: {b64[:2000]}{'...' if len(b64) > 2000 else ''}"
    )


# =====================================================================
# System operations
# =====================================================================


@mcp.tool()
async def corellium_lock_device(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Lock the virtual device screen (iOS only).

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.lock_device(instance_id)
    return "Device locked."


@mcp.tool()
async def corellium_unlock_device(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Unlock the virtual device screen (iOS only).

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.unlock_device(instance_id)
    return "Device unlocked."


@mcp.tool()
async def corellium_get_network_info(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Get network interface info for the virtual device (AOSP only).

    Returns IP address of eth0 and other network details.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_network_info(instance_id))


@mcp.tool()
async def corellium_get_system_property(
    instance_id: str,
    property_name: str,
    connection_id: str = "default",
) -> str:
    """Get a system property from an Android device (AOSP only).

    Args:
        instance_id: The instance UUID.
        property_name: Property name (e.g. "ro.build.version.sdk").
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(
        await client.get_system_prop(instance_id, property_name)
    )


# =====================================================================
# Kernel panics
# =====================================================================


@mcp.tool()
async def corellium_get_kernel_panics(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Get recorded kernel panics for a virtual device.

    Useful for identifying kernel-level vulnerabilities and crashes
    triggered during fuzzing or exploit testing.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_instance_panics(instance_id))


@mcp.tool()
async def corellium_clear_kernel_panics(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Clear recorded kernel panics for a virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.clear_instance_panics(instance_id)
    return "Kernel panics cleared."


# =====================================================================
# CoreTrace (syscall tracing)
# =====================================================================


@mcp.tool()
async def corellium_start_core_trace(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Start CoreTrace (system call tracing) on the virtual device.

    CoreTrace monitors syscalls at the hypervisor level. Useful for
    observing app behavior, file access patterns, and network calls.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.start_core_trace(instance_id)
    return "CoreTrace started."


@mcp.tool()
async def corellium_stop_core_trace(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Stop CoreTrace (system call tracing) on the virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.stop_core_trace(instance_id)
    return "CoreTrace stopped."


@mcp.tool()
async def corellium_get_core_trace(
    instance_id: str,
    lines: int = 1000,
    pid_filter: str = "",
    connection_id: str = "default",
) -> str:
    """Retrieve CoreTrace (syscall trace) data from the virtual device.

    Downloads captured syscall trace lines. Use pid_filter to isolate
    a specific process. Pair with corellium_start_core_trace /
    corellium_stop_core_trace.

    Args:
        instance_id: The instance UUID.
        lines: Number of trace lines to retrieve (default: 1000).
        pid_filter: Optional PID to filter for (shows only matching lines).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = await client.get_core_trace(instance_id, lines=lines)

    if pid_filter:
        filtered = [
            line for line in data.splitlines()
            if f"[pid {pid_filter}]" in line or line.startswith(f"{pid_filter} ")
        ]
        return (
            f"CoreTrace ({len(filtered)} lines matching PID {pid_filter} "
            f"out of {len(data.splitlines())} total):\n"
            + "\n".join(filtered[:lines])
        )

    total = len(data.splitlines())
    return f"CoreTrace ({total} lines):\n{data}"


@mcp.tool()
async def corellium_clear_core_trace(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Clear CoreTrace logs on the virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.clear_core_trace(instance_id)
    return "CoreTrace logs cleared."


# =====================================================================
# Hypervisor hooks
# =====================================================================


@mcp.tool()
async def corellium_list_hooks(
    instance_id: str, connection_id: str = "default"
) -> str:
    """List all hypervisor hooks on a virtual device.

    Hooks intercept execution at the hypervisor level for instrumentation.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.get_hooks(instance_id))


@mcp.tool()
async def corellium_create_hook(
    instance_id: str,
    hook_json: str,
    connection_id: str = "default",
) -> str:
    """Create a hypervisor hook on a virtual device.

    Hooks allow intercepting and modifying execution at specific
    addresses. Powerful for bypassing security checks, patching
    functions, or logging calls.

    Example hook_json:
      {"address": "0x1000", "patch": "0xNOP...", "enabled": true}

    Args:
        instance_id: The instance UUID.
        hook_json: JSON object describing the hook.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    hook = json.loads(hook_json)
    result = await client.create_hook(instance_id, hook)
    return _summarize(result)


@mcp.tool()
async def corellium_delete_hook(
    hook_id: str, connection_id: str = "default"
) -> str:
    """Delete a hypervisor hook.

    Args:
        hook_id: The hook UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.delete_hook(hook_id)
    return f"Hook {hook_id} deleted."


@mcp.tool()
async def corellium_execute_hooks(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Execute all hypervisor hooks on a virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.execute_hooks(instance_id)
    return "Hooks executed."


@mcp.tool()
async def corellium_clear_hooks(
    instance_id: str, connection_id: str = "default"
) -> str:
    """Clear all hypervisor hooks on a virtual device.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.clear_hooks(instance_id)
    return "All hooks cleared."


# =====================================================================
# MATRIX security assessments
# =====================================================================


@mcp.tool()
async def corellium_create_assessment(
    instance_id: str,
    bundle_id: str = "",
    connection_id: str = "default",
) -> str:
    """Create a MATRIX security assessment for an app on the device.

    MATRIX performs automated security testing including static and
    dynamic analysis, certificate pinning checks, data storage
    analysis, and more.

    Args:
        instance_id: The instance UUID.
        bundle_id: App bundle ID to assess (optional, for app-specific assessment).
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    body: dict[str, Any] = {}
    if bundle_id:
        body["bundleId"] = bundle_id
    result = await client.create_assessment(instance_id, body)
    return _summarize(result)


@mcp.tool()
async def corellium_get_assessment(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Get the status and results of a MATRIX security assessment.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(
        await client.get_assessment(instance_id, assessment_id)
    )


@mcp.tool()
async def corellium_start_monitoring(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Start MATRIX device monitoring for a security assessment.

    Begins monitoring the device for the specified assessment.
    Run the app and interact with it while monitoring is active.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.start_monitoring(instance_id, assessment_id)
    return _summarize(result)


@mcp.tool()
async def corellium_stop_monitoring(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Stop MATRIX device monitoring for a security assessment.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.stop_monitoring(instance_id, assessment_id)
    return _summarize(result)


@mcp.tool()
async def corellium_run_security_tests(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Execute MATRIX security tests for an assessment.

    Runs the automated test suite after monitoring is complete.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.run_tests(instance_id, assessment_id)
    return _summarize(result)


@mcp.tool()
async def corellium_download_security_report(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Download the MATRIX security assessment report.

    Returns the report as base64. The report contains detailed
    findings, vulnerabilities, and remediation recommendations.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = await client.download_report(instance_id, assessment_id)
    b64 = base64.b64encode(data).decode("ascii")
    return (
        f"Security report: {len(data)} bytes.\n"
        f"Base64: {b64[:3000]}{'...' if len(b64) > 3000 else ''}"
    )


@mcp.tool()
async def corellium_delete_assessment(
    instance_id: str,
    assessment_id: str,
    connection_id: str = "default",
) -> str:
    """Delete a MATRIX security assessment.

    Args:
        instance_id: The instance UUID.
        assessment_id: The assessment UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    await client.delete_assessment(instance_id, assessment_id)
    return f"Assessment {assessment_id} deleted."


# =====================================================================
# Exposed ports (SSH, FRIDA, etc.)
# =====================================================================


@mcp.tool()
async def corellium_enable_port(
    instance_id: str,
    port_json: str,
    connection_id: str = "default",
) -> str:
    """Enable an exposed port on the virtual device.

    Use this to expose SSH (22), FRIDA (27042), or other services
    for remote access during penetration testing.

    Example port_json: {"port": 22, "protocol": "tcp"}

    Args:
        instance_id: The instance UUID.
        port_json: JSON object with port configuration.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    body = json.loads(port_json)
    result = await client.enable_expose_port(instance_id, body)
    return _summarize(result)


@mcp.tool()
async def corellium_disable_port(
    instance_id: str,
    port_json: str,
    connection_id: str = "default",
) -> str:
    """Disable an exposed port on the virtual device.

    Args:
        instance_id: The instance UUID.
        port_json: JSON object with port configuration.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    body = json.loads(port_json)
    result = await client.disable_expose_port(instance_id, body)
    return _summarize(result)


# =====================================================================
# Profiles (iOS configuration profiles)
# =====================================================================


@mcp.tool()
async def corellium_list_profiles(
    instance_id: str, connection_id: str = "default"
) -> str:
    """List installed configuration profiles on an iOS device.

    Profiles can include VPN configs, certificates, MDM settings,
    and other security-relevant configuration.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    return _summarize(await client.list_profiles(instance_id))


@mcp.tool()
async def corellium_install_profile(
    instance_id: str,
    base64_profile: str,
    connection_id: str = "default",
) -> str:
    """Install a configuration profile on an iOS device.

    Useful for installing custom CA certificates for MITM testing,
    VPN configurations, or other profile-based settings.

    Args:
        instance_id: The instance UUID.
        base64_profile: Profile data (.mobileconfig) as base64.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    data = base64.b64decode(base64_profile)
    result = await client.install_profile(instance_id, data)
    return _summarize(result)


@mcp.tool()
async def corellium_uninstall_profile(
    instance_id: str,
    profile_id: str,
    connection_id: str = "default",
) -> str:
    """Uninstall a configuration profile from an iOS device.

    Args:
        instance_id: The instance UUID.
        profile_id: The profile identifier to remove.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.uninstall_profile(instance_id, profile_id)
    return _summarize(result)


# =====================================================================
# SSH execution
# =====================================================================

@mcp.tool()
async def corellium_ssh_exec(
    instance_id: str,
    command: str,
    username: str = "root",
    password: str = "alpine",
    timeout: int = 30,
    connection_id: str = "default",
) -> str:
    """Execute a shell command on the device via SSH.

    Connects to the device over SSH and runs the command. This is the
    preferred method for shell execution on jailbroken/rooted devices
    since the REST shell_exec endpoint uses the WebSocket agent protocol.

    Automatically ensures port 22 is exposed before connecting.

    Common uses:
    - Run keychain-dumper to extract keychain items
    - Run FRIDA scripts (frida -U ...)
    - Launch/kill apps via command line
    - List processes, inspect filesystem, run any tool

    Args:
        instance_id: The instance UUID.
        command: Shell command to execute (e.g. "ls -la /tmp").
        username: SSH username (default: root).
        password: SSH password (default: alpine).
        timeout: Command timeout in seconds.
        connection_id: Which connection to use.
    """
    try:
        import paramiko
    except ImportError:
        return (
            "ERROR: paramiko is required for SSH access.\n"
            "Install with: pip install paramiko"
        )

    client = _get_client(connection_id)

    try:
        await client.enable_expose_port(
            instance_id, {"port": 22, "protocol": "tcp"}
        )
    except Exception:
        pass

    try:
        info = await client.get_instance(instance_id)
    except Exception as exc:
        return f"ERROR: Cannot get instance info: {exc}"

    domain_name = info.get("domainName")
    ssh_host = info.get("serviceIp")
    ssh_port = 22
    using_internal_ip = True

    services = info.get("services", {})
    vpn = services.get("vpn", {})
    for proxy in vpn.get("proxy", []):
        if proxy.get("devicePort") == 22:
            if proxy.get("exposedPort"):
                ssh_host = domain_name or ssh_host
                ssh_port = proxy["exposedPort"]
                using_internal_ip = False
            break

    if not ssh_host:
        ssh_host = vpn.get("ip") or info.get("ip")
    if not ssh_host:
        return "ERROR: Cannot determine device IP address from instance info"

    if using_internal_ip:
        try:
            test_sock = __import__("socket").create_connection(
                (ssh_host, ssh_port), timeout=5,
            )
            test_sock.close()
        except OSError:
            return (
                f"ERROR: SSH host {ssh_host}:{ssh_port} is unreachable.\n"
                f"The device serviceIp ({ssh_host}) is on the Corellium "
                f"internal network and requires VPN access.\n"
                f"No externally exposed port for SSH (22) was found.\n\n"
                f"Options:\n"
                f"  1. Connect via Corellium VPN first\n"
                f"  2. Use corellium_enable_port to expose port 22 "
                f"(may be restricted by enterprise policy)\n"
                f"  3. Use the Corellium web UI SSH console"
            )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            hostname=ssh_host,
            port=ssh_port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    except Exception as exc:
        return f"ERROR: SSH connection failed: {exc}"
    finally:
        ssh.close()

    result = f"Exit code: {exit_code}\n"
    if out:
        result += f"stdout:\n{out}\n"
    if err:
        result += f"stderr:\n{err}\n"
    return result


# =====================================================================
# Input injection / UI automation
# =====================================================================

@mcp.tool()
async def corellium_inject_input(
    instance_id: str,
    input_json: str,
    connection_id: str = "default",
) -> str:
    """Inject touch/keyboard input into the virtual device.

    Enables UI automation by sending tap, swipe, and key events.
    Useful for exercising app features during dynamic testing when
    programmatic app control is unavailable.

    Input format examples:
      Tap:   {"type": "touchDown", "x": 200, "y": 400}
             {"type": "touchUp", "x": 200, "y": 400}
      Key:   {"type": "keyDown", "keyCode": 4}  (Android back)
      Text:  {"type": "text", "text": "hello"}

    Args:
        instance_id: The instance UUID.
        input_json: JSON object describing the input event.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    body = json.loads(input_json)
    result = await client.inject_input(instance_id, body)
    return _summarize(result)


@mcp.tool()
async def corellium_set_hostname(
    instance_id: str,
    hostname: str,
    connection_id: str = "default",
) -> str:
    """Set the hostname of the virtual device.

    Useful for device fingerprinting tests — change the hostname
    and observe if the app behaves differently.

    Args:
        instance_id: The instance UUID.
        hostname: New hostname to set.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.set_hostname(instance_id, hostname)
    return _summarize(result)


@mcp.tool()
async def corellium_system_shutdown(
    instance_id: str,
    connection_id: str = "default",
) -> str:
    """Gracefully shut down the virtual device OS.

    Sends a shutdown command to the device agent. The instance
    remains allocated but the OS stops. Use corellium_start_instance
    to boot it again.

    Args:
        instance_id: The instance UUID.
        connection_id: Which connection to use.
    """
    client = _get_client(connection_id)
    result = await client.system_shutdown(instance_id)
    return _summarize(result)


# =====================================================================
# Entry point
# =====================================================================

def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
