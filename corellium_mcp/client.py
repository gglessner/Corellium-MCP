"""Corellium REST API client wrapper using httpx."""

from __future__ import annotations

import httpx
from typing import Any
from urllib.parse import quote as _url_quote


class CorelliumClient:
    """Lightweight async wrapper around the Corellium REST API (v1).

    All methods return parsed JSON (dict/list) or raw bytes for binary
    endpoints (screenshots, pcap downloads, reports).
    """

    def __init__(self, endpoint: str, api_token: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_token = api_token
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.endpoint,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(120.0, connect=30.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        data: bytes | None = None,
        params: dict[str, Any] | None = None,
        content_type: str | None = None,
        raw_response: bool = False,
    ) -> Any:
        client = await self._ensure_client()
        headers: dict[str, str] = {}
        if content_type:
            headers["Content-Type"] = content_type

        resp = await client.request(
            method,
            path,
            json=json,
            content=data,
            params=params,
            headers=headers,
        )
        resp.raise_for_status()

        if raw_response:
            return resp.content
        if resp.status_code == 204 or not resp.content:
            return {"status": "ok"}
        return resp.json()

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    async def get_projects(self) -> list[dict]:
        return await self._request("GET", "/v1/projects")

    async def get_project(self, project_id: str) -> dict:
        return await self._request("GET", f"/v1/projects/{project_id}")

    # ------------------------------------------------------------------
    # Models & firmware
    # ------------------------------------------------------------------

    async def get_models(self) -> list[dict]:
        return await self._request("GET", "/v1/models")

    async def get_model_software(self, model: str) -> list[dict]:
        return await self._request("GET", f"/v1/models/{model}/software")

    # ------------------------------------------------------------------
    # Instances (virtual devices)
    # ------------------------------------------------------------------

    async def get_instances(self) -> list[dict]:
        return await self._request("GET", "/v1/instances")

    async def get_instance(self, instance_id: str) -> dict:
        return await self._request("GET", f"/v1/instances/{instance_id}")

    async def create_instance(self, body: dict) -> dict:
        return await self._request("POST", "/v1/instances", json=body)

    async def delete_instance(self, instance_id: str) -> dict:
        return await self._request("DELETE", f"/v1/instances/{instance_id}")

    async def start_instance(self, instance_id: str) -> dict:
        return await self._request("POST", f"/v1/instances/{instance_id}/start")

    async def stop_instance(self, instance_id: str) -> dict:
        return await self._request("POST", f"/v1/instances/{instance_id}/stop")

    async def reboot_instance(self, instance_id: str) -> dict:
        return await self._request("POST", f"/v1/instances/{instance_id}/reboot")

    async def pause_instance(self, instance_id: str) -> dict:
        return await self._request("POST", f"/v1/instances/{instance_id}/pause")

    async def unpause_instance(self, instance_id: str) -> dict:
        return await self._request("POST", f"/v1/instances/{instance_id}/unpause")

    async def get_instance_screenshot(
        self, instance_id: str, fmt: str = "png"
    ) -> bytes:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/screenshot.{fmt}",
            raw_response=True,
        )

    async def get_console_log(self, instance_id: str) -> str:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/consoleLog",
            raw_response=True,
        )

    async def get_instance_panics(self, instance_id: str) -> list[dict]:
        return await self._request(
            "GET", f"/v1/instances/{instance_id}/panics"
        )

    async def clear_instance_panics(self, instance_id: str) -> dict:
        return await self._request(
            "DELETE", f"/v1/instances/{instance_id}/panics"
        )

    async def get_instance_peripherals(self, instance_id: str) -> dict:
        return await self._request(
            "GET", f"/v1/instances/{instance_id}/peripherals"
        )

    async def set_instance_peripherals(
        self, instance_id: str, peripherals: dict
    ) -> dict:
        return await self._request(
            "PUT", f"/v1/instances/{instance_id}/peripherals", json=peripherals
        )

    async def inject_input(self, instance_id: str, body: dict) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/input", json=body
        )

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    async def get_snapshots(self, instance_id: str) -> list[dict]:
        return await self._request(
            "GET", f"/v1/instances/{instance_id}/snapshots"
        )

    async def get_snapshot(
        self, instance_id: str, snapshot_id: str
    ) -> dict:
        return await self._request(
            "GET", f"/v1/instances/{instance_id}/snapshots/{snapshot_id}"
        )

    async def create_snapshot(self, instance_id: str, name: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/snapshots",
            json={"name": name},
        )

    async def restore_snapshot(
        self, instance_id: str, snapshot_id: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/snapshots/{snapshot_id}/restore",
        )

    async def delete_snapshot(
        self, instance_id: str, snapshot_id: str
    ) -> dict:
        return await self._request(
            "DELETE",
            f"/v1/instances/{instance_id}/snapshots/{snapshot_id}",
        )

    # ------------------------------------------------------------------
    # Agent – apps
    # ------------------------------------------------------------------

    async def agent_ready(self, instance_id: str) -> dict:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/app/ready",
        )

    async def list_apps(self, instance_id: str) -> dict:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/app/apps",
        )

    async def run_app(self, instance_id: str, bundle_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/app/apps/{bundle_id}/run",
        )

    async def kill_app(self, instance_id: str, bundle_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/app/apps/{bundle_id}/kill",
            json={},
        )

    async def disable_ssl_pinning(self, instance_id: str) -> dict:
        return await self._request(
            "PUT",
            f"/v1/instances/{instance_id}/agent/v1/system/ssl-pinning/disable",
            json={},
        )

    async def enable_ssl_pinning(self, instance_id: str) -> dict:
        return await self._request(
            "PUT",
            f"/v1/instances/{instance_id}/agent/v1/system/ssl-pinning/enable",
            json={},
        )

    async def shell_exec(self, instance_id: str, command: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/exec",
            json={"cmd": command},
        )

    async def install_app(self, instance_id: str, path: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/app/install",
            json={"path": path},
        )

    async def uninstall_app(
        self, instance_id: str, bundle_id: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/app/apps/{bundle_id}/uninstall",
        )

    # ------------------------------------------------------------------
    # Agent – files
    # ------------------------------------------------------------------

    async def list_files(self, instance_id: str, dir_path: str) -> list[dict]:
        dir_path = _url_quote(dir_path.lstrip("/"), safe="/")
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/file/device/{dir_path}",
        )

    async def download_file(self, instance_id: str, file_path: str) -> bytes:
        file_path = _url_quote(file_path.lstrip("/"), safe="/")
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/file/device/{file_path}",
            raw_response=True,
        )

    async def upload_file(
        self, instance_id: str, file_path: str, data: bytes
    ) -> dict:
        file_path = _url_quote(file_path.lstrip("/"), safe="/")
        return await self._request(
            "PUT",
            f"/v1/instances/{instance_id}/agent/v1/file/device/{file_path}",
            data=data,
            content_type="application/octet-stream",
        )

    async def delete_file(self, instance_id: str, file_path: str) -> dict:
        file_path = _url_quote(file_path.lstrip("/"), safe="/")
        return await self._request(
            "DELETE",
            f"/v1/instances/{instance_id}/agent/v1/file/device/{file_path}",
        )

    # ------------------------------------------------------------------
    # Agent – profiles (iOS provisioning / config profiles)
    # ------------------------------------------------------------------

    async def list_profiles(self, instance_id: str) -> list[dict]:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/profile/profiles",
        )

    async def install_profile(
        self, instance_id: str, profile_data: bytes
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/profile/install",
            data=profile_data,
            content_type="application/octet-stream",
        )

    async def uninstall_profile(
        self, instance_id: str, profile_id: str
    ) -> dict:
        return await self._request(
            "DELETE",
            f"/v1/instances/{instance_id}/agent/v1/profile/profiles/{profile_id}",
        )

    # ------------------------------------------------------------------
    # Agent – system
    # ------------------------------------------------------------------

    async def lock_device(self, instance_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/lock",
        )

    async def unlock_device(self, instance_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/unlock",
        )

    async def set_hostname(self, instance_id: str, hostname: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/setHostname",
            json={"hostname": hostname},
        )

    async def system_shutdown(self, instance_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/shutdown",
        )

    async def get_network_info(self, instance_id: str) -> dict:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/agent/v1/system/network",
        )

    async def get_system_prop(
        self, instance_id: str, prop: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/agent/v1/system/getprop",
            json={"property": prop},
        )

    # ------------------------------------------------------------------
    # Network capture
    # ------------------------------------------------------------------

    async def download_netdump_pcap(self, instance_id: str) -> bytes:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/netdump.pcap",
            raw_response=True,
        )

    async def start_network_monitor(self, instance_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/sslsplit/enable",
        )

    async def stop_network_monitor(self, instance_id: str) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/sslsplit/disable",
        )

    async def download_network_monitor_pcap(
        self, instance_id: str
    ) -> bytes:
        return await self._request(
            "GET",
            f"/v1/instances/{instance_id}/networkMonitor.pcap",
            raw_response=True,
        )

    # ------------------------------------------------------------------
    # CoreTrace (syscall tracing)
    # ------------------------------------------------------------------

    async def start_core_trace(self, instance_id: str) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/strace/enable"
        )

    async def stop_core_trace(self, instance_id: str) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/strace/disable"
        )

    async def clear_core_trace(self, instance_id: str) -> dict:
        return await self._request(
            "DELETE", f"/v1/instances/{instance_id}/strace"
        )

    async def get_core_trace(
        self, instance_id: str, lines: int = 1000
    ) -> str:
        data = await self._request(
            "GET",
            f"/v1/instances/{instance_id}/strace",
            params={"lines": lines},
            raw_response=True,
        )
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    # ------------------------------------------------------------------
    # Hypervisor hooks
    # ------------------------------------------------------------------

    async def get_hooks(self, instance_id: str) -> list[dict]:
        return await self._request(
            "GET", f"/v1/instances/{instance_id}/hooks"
        )

    async def create_hook(self, instance_id: str, hook: dict) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/hooks", json=hook
        )

    async def delete_hook(self, hook_id: str) -> dict:
        return await self._request("DELETE", f"/v1/hooks/{hook_id}")

    async def execute_hooks(self, instance_id: str) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/hooks/execute"
        )

    async def clear_hooks(self, instance_id: str) -> dict:
        return await self._request(
            "POST", f"/v1/instances/{instance_id}/hooks/clear"
        )

    # ------------------------------------------------------------------
    # MATRIX security assessments
    # ------------------------------------------------------------------

    async def create_assessment(
        self, instance_id: str, body: dict
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/services/matrix/{instance_id}/assessments",
            json=body,
        )

    async def get_assessment(
        self, instance_id: str, assessment_id: str
    ) -> dict:
        return await self._request(
            "GET",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}",
        )

    async def delete_assessment(
        self, instance_id: str, assessment_id: str
    ) -> dict:
        return await self._request(
            "DELETE",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}",
        )

    async def start_monitoring(
        self, instance_id: str, assessment_id: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}/start",
        )

    async def stop_monitoring(
        self, instance_id: str, assessment_id: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}/stop",
        )

    async def run_tests(
        self, instance_id: str, assessment_id: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}/test",
        )

    async def download_report(
        self, instance_id: str, assessment_id: str
    ) -> bytes:
        return await self._request(
            "GET",
            f"/v1/services/matrix/{instance_id}/assessments/{assessment_id}/download",
            raw_response=True,
        )

    # ------------------------------------------------------------------
    # Images (custom firmware / kernels)
    # ------------------------------------------------------------------

    async def get_images(self) -> list[dict]:
        return await self._request("GET", "/v1/images")

    async def get_image(self, image_id: str) -> dict:
        return await self._request("GET", f"/v1/images/{image_id}")

    async def create_image(self, body: dict) -> dict:
        return await self._request("POST", "/v1/images", json=body)

    async def delete_image(self, image_id: str) -> dict:
        return await self._request("DELETE", f"/v2/images/{image_id}")

    # ------------------------------------------------------------------
    # Exposed ports
    # ------------------------------------------------------------------

    async def enable_expose_port(
        self, instance_id: str, body: dict
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/exposeport/enable",
            json=body,
        )

    async def disable_expose_port(
        self, instance_id: str, body: dict
    ) -> dict:
        return await self._request(
            "POST",
            f"/v1/instances/{instance_id}/exposeport/disable",
            json=body,
        )
