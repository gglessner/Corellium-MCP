# HTTP Basic Authentication Decoder
# Extracts and decodes Basic auth credentials from HTTP headers

import base64
import re


def extract_basic_auth(data):
    """
    Extract Basic auth credentials from HTTP request data.
    Returns list of (username, password) tuples found.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode('utf-8', errors='replace')
        except:
            data = data.decode('latin-1', errors='replace')
    
    credentials = []
    
    # Pattern for Authorization: Basic <base64> or Proxy-Authorization: Basic <base64>
    patterns = [
        r'[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)',
        r'[Pp]roxy-[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, data)
        for b64_creds in matches:
            try:
                decoded = base64.b64decode(b64_creds).decode('utf-8', errors='replace')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    credentials.append((username, password, 'Authorization' if 'roxy' not in pattern else 'Proxy-Authorization'))
            except:
                pass
    
    return credentials


def format_basic_auth(data):
    """
    Find and format HTTP Basic auth credentials for display.
    Returns formatted string or None if no credentials found.
    """
    creds = extract_basic_auth(data)
    
    if not creds:
        return None
    
    output = []
    output.append("=" * 50)
    output.append("HTTP BASIC AUTH CREDENTIALS CAPTURED")
    output.append("=" * 50)
    
    for username, password, auth_type in creds:
        output.append(f"  Header: {auth_type}")
        output.append(f"  Username: {username}")
        output.append(f"  Password: {password}")
        output.append("-" * 50)
    
    return '\n'.join(output)
