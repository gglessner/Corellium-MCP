"""Analysis MCP Server — mobile forensics toolkit.

Provides decoding, parsing, and analysis tools for common mobile
application data formats encountered during penetration testing:
binary plists, cookies, JWTs, provisioning profiles, HSTS lists,
and general binary/base64 data extraction.

Copyright (C) 2025 Garland Glessner (gglessner@gmail.com)
License: GNU GPLv3
"""

from __future__ import annotations

import base64
import datetime
import json
import plistlib
import re
import struct
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "analysis-mcp",
    instructions=(
        "Mobile forensics analysis toolkit. Decode binary plists, "
        "iOS cookies, JWTs, provisioning profiles, Adobe AEP data, "
        "HSTS domain lists, and extract strings from binary blobs. "
        "All inputs accept base64-encoded data as returned by "
        "corellium_download_file."
    ),
)


def _safe_serialize(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable types."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, (list, tuple)):
        return [_safe_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# Tool: decode_plist
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_plist(
    data_base64: str,
    keys_of_interest: str = "",
) -> str:
    """Decode a binary or XML property list from base64.

    Args:
        data_base64: Base64-encoded plist data (as returned by corellium_download_file).
        keys_of_interest: Optional comma-separated key names to highlight in the output.
            If provided, matching keys are extracted into a separate 'highlighted' section.

    Returns:
        JSON representation of the plist contents.
    """
    raw = base64.b64decode(data_base64)
    try:
        parsed = plistlib.loads(raw)
    except plistlib.InvalidFileException:
        return json.dumps({
            "error": "Invalid plist format",
            "raw_strings": _extract_strings(raw, min_length=6),
        }, indent=2)

    result = _safe_serialize(parsed)

    if keys_of_interest:
        target_keys = {k.strip().lower() for k in keys_of_interest.split(",")}
        highlighted = _find_keys(result, target_keys)
        return json.dumps({"highlighted": highlighted, "full": result}, indent=2)

    return json.dumps(result, indent=2)


def _find_keys(obj: Any, target_keys: set[str], path: str = "") -> dict:
    """Recursively find keys matching the target set."""
    found = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            current = f"{path}.{k}" if path else k
            if k.lower() in target_keys:
                found[current] = v
            found.update(_find_keys(v, target_keys, current))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.update(_find_keys(v, target_keys, f"{path}[{i}]"))
    return found


# ---------------------------------------------------------------------------
# Tool: encode_plist
# ---------------------------------------------------------------------------
@mcp.tool()
async def encode_plist(
    json_data: str,
    output_format: str = "binary",
) -> str:
    """Encode a JSON object into a property list and return as base64.

    Enables the full download -> decode_plist -> modify -> encode_plist ->
    corellium_upload_file workflow for modifying app configuration on-device.

    Args:
        json_data: JSON string representing the plist contents.
        output_format: "binary" (default, Apple binary plist) or "xml" (XML plist).

    Returns:
        Base64-encoded plist data ready for corellium_upload_file.
    """
    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    converted = _json_to_plist_types(parsed)

    fmt = plistlib.FMT_BINARY if output_format == "binary" else plistlib.FMT_XML
    try:
        encoded = plistlib.dumps(converted, fmt=fmt)
    except Exception as e:
        return json.dumps({"error": f"Plist encoding failed: {e}"})

    b64 = base64.b64encode(encoded).decode("ascii")
    return json.dumps({
        "format": output_format,
        "size_bytes": len(encoded),
        "base64": b64,
    }, indent=2)


def _json_to_plist_types(obj: Any) -> Any:
    """Convert JSON-native types back to plist-compatible types."""
    if isinstance(obj, dict):
        return {str(k): _json_to_plist_types(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_to_plist_types(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Tool: decode_base64_json
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_base64_json(
    data_base64: str,
    nested_json_keys: str = "",
) -> str:
    """Decode base64 data containing JSON, with optional nested JSON expansion.

    Args:
        data_base64: Base64-encoded JSON data.
        nested_json_keys: Optional comma-separated key names whose string values
            are themselves JSON and should be parsed recursively.

    Returns:
        Pretty-printed JSON with nested values expanded.
    """
    raw = base64.b64decode(data_base64)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        text = raw.decode("utf-8", errors="replace")
        return json.dumps({
            "error": f"JSON decode error: {e}",
            "raw_text": text[:4000],
        }, indent=2)

    if nested_json_keys:
        expand_keys = {k.strip() for k in nested_json_keys.split(",")}
        parsed = _expand_nested_json(parsed, expand_keys)

    return json.dumps(_safe_serialize(parsed), indent=2)


def _expand_nested_json(obj: Any, keys: set[str]) -> Any:
    """Parse string values of specified keys as JSON."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                try:
                    result[k] = _expand_nested_json(json.loads(v), keys)
                except json.JSONDecodeError:
                    result[k] = v
            else:
                result[k] = _expand_nested_json(v, keys)
        return result
    if isinstance(obj, list):
        return [_expand_nested_json(v, keys) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Tool: decode_binarycookies
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_binarycookies(data_base64: str) -> str:
    """Parse an iOS Cookies.binarycookies file from base64.

    Args:
        data_base64: Base64-encoded contents of a Cookies.binarycookies file.

    Returns:
        JSON array of cookie objects with domain, name, path, value, flags,
        and expiry information.
    """
    raw = base64.b64decode(data_base64)
    cookies = _parse_binarycookies(raw)
    return json.dumps(cookies, indent=2, default=str)


def _parse_binarycookies(data: bytes) -> list[dict]:
    """Parse the Apple binarycookies format."""
    if data[:4] != b"cook":
        return [{"error": "Not a valid binarycookies file (missing 'cook' magic)"}]

    try:
        num_pages = struct.unpack(">I", data[4:8])[0]
        page_sizes = []
        offset = 8
        for _ in range(num_pages):
            page_sizes.append(struct.unpack(">I", data[offset:offset + 4])[0])
            offset += 4

        cookies = []
        for page_size in page_sizes:
            page_data = data[offset:offset + page_size]
            cookies.extend(_parse_cookie_page(page_data))
            offset += page_size

        return cookies
    except Exception as e:
        strings = _extract_strings(data, min_length=4)
        domains = [s for s in strings if "." in s and not s.startswith("bplist")]
        return [{
            "parse_note": f"Partial parse (format error: {e})",
            "extracted_domains_and_values": domains,
        }]


def _parse_cookie_page(page: bytes) -> list[dict]:
    """Parse a single page of cookies."""
    cookies = []
    if page[:4] != b"\x00\x00\x01\x00":
        return cookies

    try:
        num_cookies = struct.unpack("<I", page[4:8])[0]
        cookie_offsets = []
        pos = 8
        for _ in range(num_cookies):
            cookie_offsets.append(struct.unpack("<I", page[pos:pos + 4])[0])
            pos += 4

        for co in cookie_offsets:
            cookie = _parse_single_cookie(page, co)
            if cookie:
                cookies.append(cookie)
    except Exception:
        pass

    return cookies


def _parse_single_cookie(page: bytes, offset: int) -> dict | None:
    """Parse a single cookie record from a page."""
    try:
        size = struct.unpack("<I", page[offset:offset + 4])[0]
        flags = struct.unpack("<I", page[offset + 4:offset + 8])[0]

        url_offset = struct.unpack("<I", page[offset + 16:offset + 20])[0]
        name_offset = struct.unpack("<I", page[offset + 20:offset + 24])[0]
        path_offset = struct.unpack("<I", page[offset + 24:offset + 28])[0]
        value_offset = struct.unpack("<I", page[offset + 28:offset + 32])[0]

        expiry_raw = struct.unpack("<d", page[offset + 40:offset + 48])[0]
        creation_raw = struct.unpack("<d", page[offset + 48:offset + 56])[0]

        # Apple epoch is 2001-01-01
        apple_epoch = datetime.datetime(2001, 1, 1)
        expiry = (apple_epoch + datetime.timedelta(seconds=expiry_raw)).isoformat() if expiry_raw > 0 else "session"
        created = (apple_epoch + datetime.timedelta(seconds=creation_raw)).isoformat() if creation_raw > 0 else "unknown"

        def _read_cstring(data: bytes, pos: int) -> str:
            end = data.find(b"\x00", pos)
            if end == -1:
                return data[pos:pos + 256].decode("utf-8", errors="replace")
            return data[pos:end].decode("utf-8", errors="replace")

        domain = _read_cstring(page, offset + url_offset)
        name = _read_cstring(page, offset + name_offset)
        path = _read_cstring(page, offset + path_offset)
        value = _read_cstring(page, offset + value_offset)

        flag_list = []
        if flags & 0x1:
            flag_list.append("Secure")
        if flags & 0x4:
            flag_list.append("HttpOnly")

        # Truncate very long values for readability
        display_value = value if len(value) <= 200 else value[:200] + f"... ({len(value)} chars)"

        return {
            "domain": domain,
            "name": name,
            "path": path,
            "value": display_value,
            "flags": flag_list,
            "expires": expiry,
            "created": created,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool: decode_jwt
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_jwt(token: str) -> str:
    """Decode a JSON Web Token (JWT) without verification.

    Args:
        token: The JWT string (header.payload.signature).

    Returns:
        JSON with decoded header, payload (claims), and signature info.
    """
    parts = token.strip().split(".")
    if len(parts) < 2:
        return json.dumps({"error": "Not a valid JWT (expected at least 2 dot-separated parts)"})

    def _decode_part(part: str) -> dict:
        padded = part + "=" * (4 - len(part) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            return json.loads(raw)
        except Exception as e:
            return {"decode_error": str(e)}

    header = _decode_part(parts[0])
    payload = _decode_part(parts[1])

    # Convert epoch timestamps to human-readable
    for key in ("exp", "iat", "nbf", "auth_time"):
        if key in payload and isinstance(payload[key], (int, float)):
            try:
                dt = datetime.datetime.fromtimestamp(payload[key], tz=datetime.timezone.utc)
                payload[f"{key}_human"] = dt.isoformat()
            except (ValueError, OSError):
                pass

    # Calculate expiry info
    if "exp" in payload and "iat" in payload:
        try:
            lifetime = payload["exp"] - payload["iat"]
            payload["token_lifetime_hours"] = round(lifetime / 3600, 1)
            now = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
            if payload["exp"] < now:
                payload["status"] = "EXPIRED"
            else:
                remaining = payload["exp"] - now
                payload["status"] = f"VALID (expires in {round(remaining / 3600, 1)}h)"
        except (TypeError, ValueError):
            pass

    result = {
        "header": header,
        "payload": payload,
        "signature_present": len(parts) >= 3 and len(parts[2]) > 0,
    }
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool: decode_mobileprovision
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_mobileprovision(data_base64: str) -> str:
    """Decode an iOS embedded.mobileprovision file from base64.

    Extracts the embedded plist containing entitlements, team info,
    app ID, provisioning profile details, and allowed capabilities.

    Args:
        data_base64: Base64-encoded contents of an embedded.mobileprovision file.

    Returns:
        JSON with parsed provisioning profile data and entitlements.
    """
    raw = base64.b64decode(data_base64)

    # The plist is embedded within a CMS/PKCS#7 wrapper.
    # Find it by looking for the XML plist markers.
    plist_start = raw.find(b"<?xml")
    plist_end = raw.find(b"</plist>")

    if plist_start == -1 or plist_end == -1:
        return json.dumps({"error": "Could not find embedded plist in mobileprovision"})

    plist_data = raw[plist_start:plist_end + len(b"</plist>")]
    try:
        parsed = plistlib.loads(plist_data)
    except plistlib.InvalidFileException as e:
        return json.dumps({"error": f"Failed to parse plist: {e}"})

    result = _safe_serialize(parsed)

    # Highlight security-relevant fields
    summary = {
        "AppIDName": result.get("AppIDName"),
        "TeamName": result.get("TeamName"),
        "TeamIdentifier": result.get("TeamIdentifier"),
        "CreationDate": result.get("CreationDate"),
        "ExpirationDate": result.get("ExpirationDate"),
        "ProvisionsAllDevices": result.get("ProvisionsAllDevices"),
        "Entitlements": result.get("Entitlements"),
        "ProvisionedDevices_count": len(result.get("ProvisionedDevices", [])),
    }

    return json.dumps({"summary": summary, "full": result}, indent=2)


# ---------------------------------------------------------------------------
# Tool: extract_strings
# ---------------------------------------------------------------------------
@mcp.tool()
async def extract_strings(
    data_base64: str,
    min_length: int = 6,
    keywords: str = "",
) -> str:
    """Extract readable ASCII/UTF-8 strings from base64-encoded binary data.

    Args:
        data_base64: Base64-encoded binary data.
        min_length: Minimum string length to extract (default 6).
        keywords: Optional comma-separated keywords to filter results.
            Only strings containing at least one keyword (case-insensitive) are returned.

    Returns:
        JSON with extracted strings, optionally filtered by keywords.
    """
    raw = base64.b64decode(data_base64)
    strings = _extract_strings(raw, min_length=min_length)

    if keywords:
        kw_list = [k.strip().lower() for k in keywords.split(",") if k.strip()]
        filtered = [s for s in strings if any(kw in s.lower() for kw in kw_list)]
        return json.dumps({
            "total_strings": len(strings),
            "keyword_matches": len(filtered),
            "keywords": kw_list,
            "matches": filtered,
        }, indent=2)

    return json.dumps({
        "total_strings": len(strings),
        "strings": strings[:500],  # cap for readability
        "truncated": len(strings) > 500,
    }, indent=2)


def _extract_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [m.decode("ascii") for m in re.findall(pattern, data)]


# ---------------------------------------------------------------------------
# Tool: analyze_hsts
# ---------------------------------------------------------------------------
@mcp.tool()
async def analyze_hsts(data_base64: str) -> str:
    """Parse a WebKit HSTS.plist to extract the list of HSTS-enforced domains.

    The HSTS plist reveals every domain the app has contacted that sets
    Strict-Transport-Security headers — effectively a network contact map.

    Args:
        data_base64: Base64-encoded HSTS.plist file.

    Returns:
        JSON with list of HSTS domains and their properties.
    """
    raw = base64.b64decode(data_base64)
    try:
        parsed = plistlib.loads(raw)
    except plistlib.InvalidFileException:
        domains = re.findall(rb"[a-z0-9][-a-z0-9.]*\.[a-z]{2,}", raw)
        unique = list(dict.fromkeys(d.decode() for d in domains))
        return json.dumps({
            "note": "Binary plist parse fallback — extracted domain strings",
            "domains": unique,
        }, indent=2)

    result = _safe_serialize(parsed)

    # Walk the structure to find domains and their HSTS properties
    domains = []
    storage = None
    for key, val in result.items():
        if isinstance(val, dict):
            storage = val
            break

    if storage:
        for domain, props in storage.items():
            entry = {"domain": domain}
            if isinstance(props, dict):
                entry["include_subdomains"] = props.get("Include Subdomains", False)
                entry["hsts_host"] = props.get("HSTS Host", "")
            domains.append(entry)

    return json.dumps({
        "total_domains": len(domains),
        "domains": domains,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: decode_aep_config
# ---------------------------------------------------------------------------
@mcp.tool()
async def decode_aep_config(data_base64: str) -> str:
    """Decode Adobe Experience Platform (AEP) configuration or identity files.

    Parses the JSON structure and expands nested JSON string values that
    Adobe AEP stores as escaped strings within the outer JSON.

    Args:
        data_base64: Base64-encoded Adobe AEP JSON file
            (e.g., com.adobe.module.identity.json or com.adobe.module.configuration.json).

    Returns:
        JSON with all nested values expanded and security-relevant fields highlighted.
    """
    raw = base64.b64decode(data_base64)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"JSON decode error: {e}"})

    # Expand all string values that are themselves JSON
    expanded = {}
    for key, value in parsed.items():
        if isinstance(value, str):
            try:
                inner = json.loads(value)
                if isinstance(inner, dict):
                    # Recurse one more level for doubly-nested JSON
                    for ik, iv in inner.items():
                        if isinstance(iv, str):
                            try:
                                inner[ik] = json.loads(iv)
                            except (json.JSONDecodeError, TypeError):
                                pass
                expanded[key] = inner
            except (json.JSONDecodeError, TypeError):
                expanded[key] = value
        else:
            expanded[key] = value

    # Extract security-relevant highlights
    highlights = {}
    _walk_for_highlights(expanded, highlights)

    return json.dumps({
        "security_highlights": highlights,
        "full": expanded,
    }, indent=2)


def _walk_for_highlights(obj: Any, out: dict, path: str = "") -> None:
    """Walk a nested structure looking for security-relevant AEP fields."""
    interesting_keys = {
        "edge.configId", "edge.domain", "experienceCloud.org",
        "build.environment", "rules.url", "property.id",
        "__stage__edge.configId", "__dev__edge.configId",
        "ecidString", "privacyStatus", "blob", "locationHint",
        "config.appID",
    }
    if isinstance(obj, dict):
        for k, v in obj.items():
            current = f"{path}.{k}" if path else k
            if k in interesting_keys:
                out[current] = v
            _walk_for_highlights(v, out, current)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_for_highlights(v, out, f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Tool: binary_search
# ---------------------------------------------------------------------------
@mcp.tool()
async def binary_search(
    data_base64: str,
    keywords: str,
    context_bytes: int = 50,
) -> str:
    """Search base64-encoded binary data for keywords and return surrounding context.

    Useful for finding URLs, tokens, keys, or identifiers in binary
    files, SQLite databases, or other opaque data blobs.

    Args:
        data_base64: Base64-encoded binary data to search.
        keywords: Comma-separated keywords to search for (case-insensitive).
        context_bytes: Number of bytes of context to show around each match (default 50).

    Returns:
        JSON with matches, their byte offsets, and surrounding context.
    """
    raw = base64.b64decode(data_base64)
    kw_list = [k.strip() for k in keywords.split(",") if k.strip()]

    matches = []
    for kw in kw_list:
        kw_bytes = kw.encode("utf-8")
        raw_lower = raw.lower()
        kw_lower = kw_bytes.lower()

        pos = 0
        while True:
            idx = raw_lower.find(kw_lower, pos)
            if idx == -1:
                break

            start = max(0, idx - context_bytes)
            end = min(len(raw), idx + len(kw_bytes) + context_bytes)
            context = raw[start:end]
            # Extract printable context
            context_str = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in context
            )

            matches.append({
                "keyword": kw,
                "offset": idx,
                "context": context_str,
            })
            pos = idx + 1

            if len(matches) > 100:
                break

    return json.dumps({
        "total_matches": len(matches),
        "keywords_searched": kw_list,
        "matches": matches,
    }, indent=2)


# ---------------------------------------------------------------------------
# Tool: summarize_sqlite_strings
# ---------------------------------------------------------------------------
@mcp.tool()
async def summarize_sqlite_strings(
    data_base64: str,
    keywords: str = "",
) -> str:
    """Extract table names, schema, and interesting strings from a SQLite database.

    Works on raw base64-encoded SQLite files. Extracts the schema by
    parsing the sqlite_master table entries from the binary format,
    then extracts all readable strings for keyword analysis.

    Args:
        data_base64: Base64-encoded SQLite database file.
        keywords: Optional comma-separated keywords to filter extracted strings.

    Returns:
        JSON with schema information and extracted strings.
    """
    raw = base64.b64decode(data_base64)

    if raw[:16] != b"SQLite format 3\x00":
        return json.dumps({"error": "Not a valid SQLite database"})

    # Extract schema: look for CREATE TABLE/INDEX statements
    schema_pattern = rb"(CREATE\s+(?:TABLE|INDEX|VIEW|TRIGGER)\s+[^\x00]+)"
    schema_matches = re.findall(schema_pattern, raw, re.IGNORECASE)
    schemas = []
    for m in schema_matches:
        try:
            schemas.append(m.decode("utf-8", errors="replace").strip())
        except Exception:
            pass

    # Extract all strings
    strings = _extract_strings(raw, min_length=8)

    if keywords:
        kw_list = [k.strip().lower() for k in keywords.split(",") if k.strip()]
        filtered = [s for s in strings if any(kw in s.lower() for kw in kw_list)]
        return json.dumps({
            "schemas": schemas,
            "total_strings": len(strings),
            "keyword_matches": len(filtered),
            "matches": filtered,
        }, indent=2)

    # Deduplicate and limit
    unique_strings = list(dict.fromkeys(strings))
    return json.dumps({
        "schemas": schemas,
        "total_unique_strings": len(unique_strings),
        "strings": unique_strings[:300],
        "truncated": len(unique_strings) > 300,
    }, indent=2)


# ---------------------------------------------------------------------------
# Keychain dump parser
# ---------------------------------------------------------------------------

@mcp.tool()
def decode_keychain_dump(data_base64: str = "", raw_text: str = "") -> str:
    """Parse iOS keychain-dumper output into structured JSON.

    Accepts either base64-encoded data (from corellium_download_file)
    or raw text output (from corellium_ssh_exec running keychain-dumper).

    Keychain-dumper produces XML plist output with kSecClass entries.
    This tool extracts service names, accounts, access groups, data
    values, and accessibility flags.

    Args:
        data_base64: Base64-encoded keychain dump output.
        raw_text: Raw text keychain dump output (alternative to base64).
    """
    if data_base64:
        try:
            raw = base64.b64decode(data_base64)
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            return json.dumps({"error": f"Base64 decode failed: {exc}"})
    elif raw_text:
        text = raw_text
    else:
        return json.dumps({"error": "Provide data_base64 or raw_text"})

    items: list[dict] = []
    current: dict[str, Any] = {}

    sensitive_keys = {
        "v_data", "svce", "acct", "agrp", "labl", "pdmn", "type",
        "kcls", "gena", "desc", "srvr", "ptcl", "port", "path",
    }

    try:
        plist_start = text.find("<?xml")
        if plist_start >= 0:
            plist_end = text.rfind("</plist>")
            if plist_end > plist_start:
                plist_data = text[plist_start:plist_end + len("</plist>")]
                parsed = plistlib.loads(plist_data.encode("utf-8"))
                if isinstance(parsed, list):
                    for entry in parsed:
                        if isinstance(entry, dict):
                            item: dict[str, Any] = {}
                            for k, v in entry.items():
                                if isinstance(v, bytes):
                                    try:
                                        item[k] = v.decode("utf-8")
                                    except UnicodeDecodeError:
                                        item[k] = v.hex()
                                elif isinstance(v, (datetime.datetime, datetime.date)):
                                    item[k] = str(v)
                                else:
                                    item[k] = v
                            items.append(item)
                    return json.dumps({
                        "format": "plist_array",
                        "total_items": len(items),
                        "items": items,
                    }, indent=2, default=str)
    except Exception:
        pass

    kc_class_pattern = re.compile(
        r"(kSecClass(?:GenericPassword|InternetPassword|Certificate|Key|Identity))"
    )
    kv_pattern = re.compile(r'^\s*(\w+)\s*[:=]\s*(.+)$')

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            if current:
                items.append(current)
                current = {}
            continue

        cls_match = kc_class_pattern.search(line)
        if cls_match:
            if current:
                items.append(current)
            current = {"kSecClass": cls_match.group(1)}
            continue

        kv_match = kv_pattern.match(line)
        if kv_match:
            key, val = kv_match.group(1), kv_match.group(2).strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            current[key] = val

    if current:
        items.append(current)

    security_summary = {
        "total_items": len(items),
        "passwords": 0,
        "internet_passwords": 0,
        "certificates": 0,
        "keys": 0,
        "always_accessible": 0,
        "after_first_unlock": 0,
    }

    for item in items:
        kclass = item.get("kSecClass", item.get("kcls", ""))
        if "GenericPassword" in kclass:
            security_summary["passwords"] += 1
        elif "InternetPassword" in kclass:
            security_summary["internet_passwords"] += 1
        elif "Certificate" in kclass:
            security_summary["certificates"] += 1
        elif "Key" in kclass:
            security_summary["keys"] += 1

        pdmn = item.get("pdmn", item.get("kSecAttrAccessible", ""))
        if "Always" in str(pdmn) or pdmn in ("dk", "dku"):
            security_summary["always_accessible"] += 1
        elif "AfterFirstUnlock" in str(pdmn) or pdmn in ("ck", "cku"):
            security_summary["after_first_unlock"] += 1

    return json.dumps({
        "format": "text_parsed",
        "security_summary": security_summary,
        "items": items,
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Akamai sensor data decoder
# ---------------------------------------------------------------------------

@mcp.tool()
def decode_akamai_sensor(sensor_data: str) -> str:
    """Decode Akamai Bot Manager (BMP) sensor payload into structured fields.

    Akamai sensor data is stored in app preferences as
    com.akamai.botman.defaults.sensor_data. This tool parses the
    semicolon-delimited payload and extracts identifiable fields.

    Useful for understanding what device fingerprint data is collected
    and for preparing sensor replay attacks.

    Args:
        sensor_data: The raw sensor data string (from plist extraction).
    """
    if not sensor_data:
        return json.dumps({"error": "Empty sensor_data"})

    if sensor_data.startswith("{") or sensor_data.startswith("["):
        try:
            parsed = json.loads(sensor_data)
            fields: dict[str, Any] = {}
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(v, str) and len(v) > 200:
                        fields[k] = {
                            "type": "long_string",
                            "length": len(v),
                            "preview": v[:100] + "...",
                        }
                    else:
                        fields[k] = v
            return json.dumps({
                "format": "json",
                "total_keys": len(fields),
                "fields": fields,
                "security_notes": [
                    "Contains device fingerprint data",
                    "Can be extracted and replayed to bypass bot detection",
                    "Should NOT be stored in plaintext NSUserDefaults",
                ],
            }, indent=2, default=str)
        except json.JSONDecodeError:
            pass

    delimiter = ";"
    for candidate in [";", "$", ","]:
        count = sensor_data.count(candidate)
        if count > sensor_data.count(delimiter):
            delimiter = candidate
    segments = sensor_data.split(delimiter)

    known_field_map = {
        0: "version",
        1: "timestamp_ms",
        2: "session_id",
    }

    decoded_fields: dict[str, Any] = {}
    raw_segments: list[dict[str, Any]] = []
    timestamps: list[str] = []
    urls: list[str] = []
    long_encoded: list[int] = []

    for i, seg in enumerate(segments):
        seg = seg.strip()
        if not seg:
            continue

        field_name = known_field_map.get(i, f"field_{i}")
        entry: dict[str, Any] = {"index": i, "name": field_name}

        if seg.isdigit() and len(seg) >= 13:
            ts_sec = int(seg) / 1000.0
            try:
                dt = datetime.datetime.fromtimestamp(ts_sec, tz=datetime.timezone.utc)
                entry["value"] = seg
                entry["decoded_timestamp"] = str(dt)
                timestamps.append(str(dt))
            except (ValueError, OSError):
                entry["value"] = seg
        elif seg.startswith("http://") or seg.startswith("https://"):
            entry["value"] = seg
            urls.append(seg)
        elif len(seg) > 200:
            entry["value_preview"] = seg[:80] + "..."
            entry["length"] = len(seg)
            entry["type"] = "encoded_block"
            long_encoded.append(i)
        else:
            entry["value"] = seg

        raw_segments.append(entry)
        decoded_fields[field_name] = seg if len(seg) <= 200 else f"[{len(seg)} chars]"

    delim_names = {";": "semicolon", "$": "dollar", ",": "comma"}
    return json.dumps({
        "format": f"{delim_names.get(delimiter, repr(delimiter))}_delimited",
        "delimiter": delimiter,
        "total_segments": len(segments),
        "non_empty_segments": len(raw_segments),
        "timestamps_found": timestamps,
        "urls_found": urls,
        "long_encoded_field_indices": long_encoded,
        "segments": raw_segments[:50],
        "truncated": len(raw_segments) > 50,
        "security_notes": [
            "Akamai BMP sensor data contains device fingerprint",
            "Includes timing data, screen metrics, touch patterns",
            "Replay of this data can bypass bot detection",
            "Storage in plaintext NSUserDefaults is a High finding",
            f"Total payload size: {len(sensor_data)} bytes",
        ],
    }, indent=2, default=str)


# ---------------------------------------------------------------------------
# Screenshot / image metadata analyzer
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_screenshot(data_base64: str) -> str:
    """Analyze a PNG/JPEG screenshot for metadata and sensitive content indicators.

    Extracts image dimensions, format info, and embedded metadata from
    SplashBoard snapshots or device screenshots. Checks for text chunks
    in PNGs that may contain app state information.

    Args:
        data_base64: Base64-encoded image data.
    """
    try:
        raw = base64.b64decode(data_base64)
    except Exception as exc:
        return json.dumps({"error": f"Base64 decode failed: {exc}"})

    result: dict[str, Any] = {
        "size_bytes": len(raw),
        "format": "unknown",
    }

    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        result["format"] = "PNG"

        if len(raw) >= 24:
            width = struct.unpack(">I", raw[16:20])[0]
            height = struct.unpack(">I", raw[20:24])[0]
            result["width"] = width
            result["height"] = height
            result["aspect_ratio"] = round(width / height, 3) if height else 0

        chunks: list[dict[str, Any]] = []
        text_chunks: list[dict[str, str]] = []
        pos = 8
        while pos + 8 <= len(raw):
            chunk_len = struct.unpack(">I", raw[pos:pos+4])[0]
            chunk_type = raw[pos+4:pos+8].decode("ascii", errors="replace")

            chunk_info: dict[str, Any] = {
                "type": chunk_type,
                "size": chunk_len,
            }

            if chunk_type in ("tEXt", "iTXt", "zTXt") and chunk_len > 0:
                data_start = pos + 8
                data_end = data_start + min(chunk_len, 1000)
                chunk_data = raw[data_start:data_end]
                if b'\x00' in chunk_data:
                    key_end = chunk_data.index(b'\x00')
                    key = chunk_data[:key_end].decode("ascii", errors="replace")
                    val = chunk_data[key_end+1:].decode("utf-8", errors="replace")
                    text_chunks.append({"key": key, "value": val[:200]})
                    chunk_info["text_key"] = key

            chunks.append(chunk_info)
            pos += 12 + chunk_len
            if chunk_type == "IEND":
                break

        result["chunks"] = chunks
        if text_chunks:
            result["text_metadata"] = text_chunks

    elif raw[:2] == b'\xff\xd8':
        result["format"] = "JPEG"

        pos = 2
        while pos < len(raw) - 2:
            if raw[pos] != 0xFF:
                break
            marker = raw[pos+1]
            if marker == 0xD9:
                break
            if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0x01):
                pos += 2
                continue
            if pos + 4 > len(raw):
                break
            seg_len = struct.unpack(">H", raw[pos+2:pos+4])[0]

            if marker == 0xC0 or marker == 0xC2:
                if pos + 9 <= len(raw):
                    height = struct.unpack(">H", raw[pos+5:pos+7])[0]
                    width = struct.unpack(">H", raw[pos+7:pos+9])[0]
                    result["width"] = width
                    result["height"] = height
                    result["aspect_ratio"] = round(width / height, 3) if height else 0

            if marker == 0xE1 and seg_len > 6:
                seg_data = raw[pos+4:pos+2+min(seg_len, 200)]
                if seg_data[:4] == b'Exif':
                    result["has_exif"] = True

            pos += 2 + seg_len

    sensitive_strings: list[str] = []
    text = raw.decode("utf-8", errors="ignore")
    sensitive_patterns = [
        r'password', r'token', r'api[_-]?key', r'secret',
        r'session[_-]?id', r'auth', r'credential',
    ]
    for pat in sensitive_patterns:
        if re.search(pat, text, re.IGNORECASE):
            sensitive_strings.append(pat)

    if sensitive_strings:
        result["sensitive_content_detected"] = sensitive_strings

    is_blank = False
    if result.get("format") == "PNG" and result.get("width") and result.get("height"):
        idat_sizes = [c["size"] for c in chunks if c["type"] == "IDAT"]
        total_idat = sum(idat_sizes)
        pixel_count = result["width"] * result["height"]
        if pixel_count > 0:
            compression_ratio = total_idat / pixel_count
            if compression_ratio < 0.01:
                is_blank = True
                result["likely_blank_screen"] = True

    result["security_notes"] = []
    if sensitive_strings:
        result["security_notes"].append(
            "Embedded text contains potentially sensitive keywords"
        )
    if is_blank:
        result["security_notes"].append(
            "Image appears to be a blank/solid screen (very high compression)"
        )
    else:
        result["security_notes"].append(
            "SplashBoard snapshots may capture sensitive screens (login, account data)"
        )
    if result.get("has_exif"):
        result["security_notes"].append(
            "EXIF metadata present — may contain location, device info"
        )

    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# File save utility
# ---------------------------------------------------------------------------
@mcp.tool()
def save_base64_to_file(data_base64: str, file_path: str) -> str:
    """Save base64-encoded data to a local file.

    Decodes base64 data (as returned by corellium_download_file,
    corellium_screenshot, etc.) and writes the raw bytes to a local
    file path. Handles padding correction automatically.

    Common uses:
    - Save Corellium screenshots as PNG files for viewing
    - Save downloaded binaries, plists, databases, or PCAPs locally
    - Extract any base64-encoded content to disk for external tools

    Args:
        data_base64: Base64-encoded data string.
        file_path: Local filesystem path to write the decoded file to.
    """
    import os

    clean = data_base64.strip()
    padding = 4 - len(clean) % 4
    if padding != 4:
        clean += "=" * padding

    try:
        raw = base64.b64decode(clean)
    except Exception as e:
        return json.dumps({"error": f"Base64 decode failed: {e}"})

    parent = os.path.dirname(file_path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

    try:
        with open(file_path, "wb") as f:
            f.write(raw)
    except Exception as e:
        return json.dumps({"error": f"File write failed: {e}"})

    return json.dumps({
        "status": "saved",
        "path": os.path.abspath(file_path),
        "size_bytes": len(raw),
        "size_human": (
            f"{len(raw):,} bytes"
            if len(raw) < 1024
            else f"{len(raw)/1024:.1f} KB"
            if len(raw) < 1048576
            else f"{len(raw)/1048576:.1f} MB"
        ),
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
