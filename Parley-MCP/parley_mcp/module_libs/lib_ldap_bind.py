# LDAP Simple Bind Decoder
# Extracts credentials from LDAP BindRequest messages
# LDAP uses ASN.1 BER encoding

def decode_ber_length(data, offset):
    """Decode BER length field, return (length, bytes_consumed)."""
    if offset >= len(data):
        return 0, 0
    
    first_byte = data[offset]
    
    if first_byte < 0x80:
        # Short form: length is just this byte
        return first_byte, 1
    elif first_byte == 0x80:
        # Indefinite form (not handling)
        return 0, 1
    else:
        # Long form: first byte tells how many bytes encode the length
        num_bytes = first_byte & 0x7F
        if offset + 1 + num_bytes > len(data):
            return 0, 1
        
        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[offset + 1 + i]
        
        return length, 1 + num_bytes


def decode_ber_string(data, offset):
    """Decode a BER-encoded string (OCTET STRING or similar)."""
    if offset >= len(data):
        return None, 0
    
    tag = data[offset]
    length, len_bytes = decode_ber_length(data, offset + 1)
    
    start = offset + 1 + len_bytes
    end = start + length
    
    if end > len(data):
        return None, 0
    
    try:
        value = data[start:end].decode('utf-8', errors='replace')
    except:
        value = data[start:end].hex()
    
    return value, 1 + len_bytes + length


def extract_ldap_simple_bind(data):
    """
    Extract LDAP Simple Bind credentials from raw data.
    
    LDAP BindRequest structure:
    SEQUENCE {
        messageID INTEGER,
        protocolOp BindRequest ::= [APPLICATION 0] SEQUENCE {
            version INTEGER,
            name OCTET STRING (DN),
            authentication CHOICE {
                simple [0] OCTET STRING (password),
                ...
            }
        }
    }
    
    Returns list of (dn, password) tuples.
    """
    if isinstance(data, bytearray):
        data = bytes(data)
    
    credentials = []
    
    # Look for LDAP BindRequest pattern
    # Tag 0x30 = SEQUENCE (message envelope)
    # Inside, look for APPLICATION 0 (0x60) = BindRequest
    
    i = 0
    while i < len(data) - 10:
        # Look for SEQUENCE tag
        if data[i] != 0x30:
            i += 1
            continue
        
        # Get sequence length
        seq_len, len_bytes = decode_ber_length(data, i + 1)
        if seq_len == 0:
            i += 1
            continue
        
        # Look inside for BindRequest (APPLICATION 0 = 0x60)
        inner_offset = i + 1 + len_bytes
        
        # Skip message ID (INTEGER, tag 0x02)
        if inner_offset < len(data) and data[inner_offset] == 0x02:
            int_len, int_len_bytes = decode_ber_length(data, inner_offset + 1)
            inner_offset += 1 + int_len_bytes + int_len
        
        # Check for BindRequest (APPLICATION 0 = 0x60)
        if inner_offset < len(data) and data[inner_offset] == 0x60:
            bind_len, bind_len_bytes = decode_ber_length(data, inner_offset + 1)
            bind_offset = inner_offset + 1 + bind_len_bytes
            
            # Skip version (INTEGER, tag 0x02)
            if bind_offset < len(data) and data[bind_offset] == 0x02:
                ver_len, ver_len_bytes = decode_ber_length(data, bind_offset + 1)
                bind_offset += 1 + ver_len_bytes + ver_len
            
            # Get DN (OCTET STRING, tag 0x04)
            if bind_offset < len(data) and data[bind_offset] == 0x04:
                dn, dn_consumed = decode_ber_string(data, bind_offset)
                bind_offset += dn_consumed
                
                # Check for simple authentication (CONTEXT 0 = 0x80)
                if bind_offset < len(data) and data[bind_offset] == 0x80:
                    pwd_len, pwd_len_bytes = decode_ber_length(data, bind_offset + 1)
                    pwd_start = bind_offset + 1 + pwd_len_bytes
                    pwd_end = pwd_start + pwd_len
                    
                    if pwd_end <= len(data):
                        try:
                            password = data[pwd_start:pwd_end].decode('utf-8', errors='replace')
                        except:
                            password = data[pwd_start:pwd_end].hex()
                        
                        if dn and password:
                            credentials.append((dn, password))
        
        i += 1
    
    return credentials


def format_ldap_bind(data):
    """
    Find and format LDAP Simple Bind credentials for display.
    Returns formatted string or None if no credentials found.
    """
    creds = extract_ldap_simple_bind(data)
    
    if not creds:
        return None
    
    output = []
    output.append("=" * 50)
    output.append("LDAP SIMPLE BIND CREDENTIALS CAPTURED")
    output.append("=" * 50)
    
    for dn, password in creds:
        output.append(f"  Bind DN: {dn}")
        output.append(f"  Password: {password}")
        
        # Try to extract username from DN
        if 'cn=' in dn.lower() or 'uid=' in dn.lower():
            parts = dn.split(',')
            for part in parts:
                if part.lower().startswith('cn=') or part.lower().startswith('uid='):
                    output.append(f"  (Username: {part.split('=', 1)[1]})")
                    break
        
        output.append("-" * 50)
    
    return '\n'.join(output)
