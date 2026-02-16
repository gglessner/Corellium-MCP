# JWT (JSON Web Token) Parser
# Decodes and displays JWT token contents from Bearer authorization

import base64
import json
import re
from datetime import datetime, timezone

def base64url_decode(data):
    """Decode base64url (URL-safe base64 without padding)."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)


def extract_bearer_tokens(data):
    """
    Extract Bearer tokens from HTTP request/response data.
    Returns a list of tokens found.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode('utf-8', errors='replace')
        except:
            data = data.decode('latin-1', errors='replace')
    
    tokens = []
    
    # Pattern for Authorization: Bearer <token>
    bearer_pattern = r'[Aa]uthorization:\s*[Bb]earer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)'
    matches = re.findall(bearer_pattern, data)
    tokens.extend(matches)
    
    # Pattern for tokens in JSON bodies (access_token, id_token, token fields)
    json_token_pattern = r'"(?:access_token|id_token|token|jwt|idToken|accessToken)":\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)"'
    matches = re.findall(json_token_pattern, data)
    tokens.extend(matches)
    
    # Pattern for tokens in query strings or form data
    query_pattern = r'(?:access_token|id_token|token|jwt)=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)'
    matches = re.findall(query_pattern, data)
    tokens.extend(matches)
    
    return tokens


def decode_jwt(token):
    """
    Decode a JWT token and return its components.
    Returns (header_dict, payload_dict, signature_b64, error_message)
    """
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None, "Invalid JWT format (expected 3 parts)"
    
    header_b64, payload_b64, signature_b64 = parts
    
    try:
        header_json = base64url_decode(header_b64)
        header = json.loads(header_json)
    except Exception as e:
        return None, None, None, f"Failed to decode header: {e}"
    
    try:
        payload_json = base64url_decode(payload_b64)
        payload = json.loads(payload_json)
    except Exception as e:
        return None, None, None, f"Failed to decode payload: {e}"
    
    return header, payload, signature_b64, None


def format_timestamp(ts):
    """Format a Unix timestamp to human-readable datetime."""
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return str(ts)


def check_expiration(payload):
    """Check if token is expired and return status string."""
    exp = payload.get('exp')
    if exp is None:
        return "No expiration (exp) claim"
    
    try:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        if now > exp_dt:
            delta = now - exp_dt
            return f"EXPIRED ({delta.days}d {delta.seconds//3600}h {(delta.seconds%3600)//60}m ago)"
        else:
            delta = exp_dt - now
            return f"Valid (expires in {delta.days}d {delta.seconds//3600}h {(delta.seconds%3600)//60}m)"
    except:
        return "Could not parse expiration"


# Common JWT claim names
CLAIM_DESCRIPTIONS = {
    'iss': 'Issuer',
    'sub': 'Subject',
    'aud': 'Audience',
    'exp': 'Expiration Time',
    'nbf': 'Not Before',
    'iat': 'Issued At',
    'jti': 'JWT ID',
    'name': 'Full Name',
    'given_name': 'Given Name',
    'family_name': 'Family Name',
    'email': 'Email',
    'email_verified': 'Email Verified',
    'phone_number': 'Phone Number',
    'preferred_username': 'Preferred Username',
    'groups': 'Groups',
    'roles': 'Roles',
    'scope': 'Scope',
    'azp': 'Authorized Party',
    'nonce': 'Nonce',
    'auth_time': 'Authentication Time',
    'acr': 'Authentication Context Class',
    'amr': 'Authentication Methods',
    'at_hash': 'Access Token Hash',
    'c_hash': 'Code Hash',
    'sid': 'Session ID',
    'org_id': 'Organization ID',
    'tenant': 'Tenant',
    'client_id': 'Client ID',
    'typ': 'Type',
    'alg': 'Algorithm',
    'kid': 'Key ID',
}


def format_jwt(token):
    """
    Format a JWT token for display.
    Returns a formatted string with all decoded information.
    """
    header, payload, signature, error = decode_jwt(token)
    
    if error:
        return f"JWT Decode Error: {error}\nRaw token: {token[:100]}..."
    
    output = []
    output.append("=" * 60)
    output.append("JWT TOKEN DECODED")
    output.append("=" * 60)
    
    # Header
    output.append("\n[HEADER]")
    for key, value in header.items():
        desc = CLAIM_DESCRIPTIONS.get(key, key)
        output.append(f"  {desc}: {value}")
    
    # Payload
    output.append("\n[PAYLOAD]")
    
    # Check expiration status first
    exp_status = check_expiration(payload)
    output.append(f"  ** Status: {exp_status} **")
    output.append("")
    
    for key, value in payload.items():
        desc = CLAIM_DESCRIPTIONS.get(key, key)
        
        # Format timestamps
        if key in ('exp', 'iat', 'nbf', 'auth_time'):
            if isinstance(value, (int, float)):
                formatted_time = format_timestamp(value)
                output.append(f"  {desc}: {formatted_time} ({value})")
            else:
                output.append(f"  {desc}: {value}")
        # Format lists/arrays nicely
        elif isinstance(value, list):
            output.append(f"  {desc}: {', '.join(str(v) for v in value)}")
        # Format nested objects
        elif isinstance(value, dict):
            output.append(f"  {desc}:")
            for k, v in value.items():
                output.append(f"    {k}: {v}")
        else:
            output.append(f"  {desc}: {value}")
    
    # Signature (just show it's present, truncated)
    output.append("\n[SIGNATURE]")
    if signature:
        output.append(f"  {signature[:32]}... ({len(signature)} chars)")
    else:
        output.append("  (no signature)")
    
    output.append("=" * 60)
    
    return '\n'.join(output)


def find_and_format_jwts(data):
    """
    Find all JWT tokens in data and format them for display.
    Returns formatted string or None if no tokens found.
    """
    tokens = extract_bearer_tokens(data)
    
    if not tokens:
        return None
    
    output = []
    for i, token in enumerate(tokens, 1):
        if len(tokens) > 1:
            output.append(f"\n>>> JWT Token #{i} <<<")
        output.append(format_jwt(token))
    
    return '\n'.join(output)
