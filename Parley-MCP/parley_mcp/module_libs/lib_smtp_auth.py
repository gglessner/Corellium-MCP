# SMTP/IMAP Authentication Decoder
# Extracts credentials from AUTH LOGIN and AUTH PLAIN mechanisms

import base64
import re


def decode_auth_plain(b64_data):
    """
    Decode SASL PLAIN authentication (used by SMTP, IMAP, etc.)
    Format: \x00username\x00password or authzid\x00authcid\x00password
    """
    try:
        decoded = base64.b64decode(b64_data)
        # Split on null bytes
        parts = decoded.split(b'\x00')
        
        if len(parts) == 3:
            # authzid, authcid (username), password
            authzid = parts[0].decode('utf-8', errors='replace')
            username = parts[1].decode('utf-8', errors='replace')
            password = parts[2].decode('utf-8', errors='replace')
            return username, password, authzid if authzid else None
        elif len(parts) == 2:
            # Just username and password
            username = parts[0].decode('utf-8', errors='replace')
            password = parts[1].decode('utf-8', errors='replace')
            return username, password, None
    except:
        pass
    
    return None, None, None


def extract_smtp_auth(data):
    """
    Extract SMTP AUTH credentials from data.
    Handles AUTH PLAIN and AUTH LOGIN mechanisms.
    Returns list of credential dicts.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            data = data.decode('utf-8', errors='replace')
        except:
            data = data.decode('latin-1', errors='replace')
    
    credentials = []
    
    # AUTH PLAIN - single base64 blob
    # Format: AUTH PLAIN <base64> or AUTH PLAIN\r\n<base64>
    plain_pattern = r'AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)'
    matches = re.findall(plain_pattern, data, re.IGNORECASE)
    for b64_data in matches:
        username, password, authzid = decode_auth_plain(b64_data)
        if username and password:
            credentials.append({
                'mechanism': 'PLAIN',
                'username': username,
                'password': password,
                'authzid': authzid,
            })
    
    # AUTH PLAIN with response on next line
    plain_pattern2 = r'AUTH\s+PLAIN\s*\r?\n([A-Za-z0-9+/=]+)'
    matches = re.findall(plain_pattern2, data, re.IGNORECASE)
    for b64_data in matches:
        username, password, authzid = decode_auth_plain(b64_data)
        if username and password:
            credentials.append({
                'mechanism': 'PLAIN',
                'username': username,
                'password': password,
                'authzid': authzid,
            })
    
    # AUTH LOGIN - separate base64 for username and password
    # Server sends: 334 VXNlcm5hbWU6 (Username:)
    # Client sends: <base64 username>
    # Server sends: 334 UGFzc3dvcmQ6 (Password:)
    # Client sends: <base64 password>
    
    # Look for AUTH LOGIN followed by base64 responses
    login_pattern = r'AUTH\s+LOGIN\s*\r?\n([A-Za-z0-9+/=]+)\r?\n(?:334[^\r\n]*\r?\n)?([A-Za-z0-9+/=]+)'
    matches = re.findall(login_pattern, data, re.IGNORECASE)
    for b64_user, b64_pass in matches:
        try:
            username = base64.b64decode(b64_user).decode('utf-8', errors='replace')
            password = base64.b64decode(b64_pass).decode('utf-8', errors='replace')
            credentials.append({
                'mechanism': 'LOGIN',
                'username': username,
                'password': password,
                'authzid': None,
            })
        except:
            pass
    
    # Also look for standalone base64 that decodes to something credential-like
    # after a 334 challenge (Username: or Password:)
    
    # AUTHENTICATE PLAIN (IMAP style)
    imap_plain = r'AUTHENTICATE\s+PLAIN\s*\r?\n([A-Za-z0-9+/=]+)'
    matches = re.findall(imap_plain, data, re.IGNORECASE)
    for b64_data in matches:
        username, password, authzid = decode_auth_plain(b64_data)
        if username and password:
            credentials.append({
                'mechanism': 'PLAIN (IMAP)',
                'username': username,
                'password': password,
                'authzid': authzid,
            })
    
    return credentials


def format_smtp_auth(data):
    """
    Find and format SMTP/IMAP auth credentials for display.
    Returns formatted string or None if no credentials found.
    """
    creds = extract_smtp_auth(data)
    
    if not creds:
        return None
    
    output = []
    output.append("=" * 50)
    output.append("SMTP/IMAP AUTH CREDENTIALS CAPTURED")
    output.append("=" * 50)
    
    for cred in creds:
        output.append(f"  Mechanism: {cred['mechanism']}")
        if cred.get('authzid'):
            output.append(f"  Auth ID: {cred['authzid']}")
        output.append(f"  Username: {cred['username']}")
        output.append(f"  Password: {cred['password']}")
        output.append("-" * 50)
    
    return '\n'.join(output)
