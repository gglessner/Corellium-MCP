# ISO 8583 Payment Message Decoder
# Requires: pip install iso8583

try:
    import iso8583
    from iso8583.specs import default_ascii as spec
    _HAS_ISO8583 = True
except ImportError:
    _HAS_ISO8583 = False


def decode_iso8583(raw_data):
    """Decode an ISO 8583 payment message.

    Requires the 'iso8583' package: pip install iso8583

    Returns a dict with 'MTI' and field numbers as keys.
    Raises ImportError if the iso8583 package is not installed.
    """
    if not _HAS_ISO8583:
        raise ImportError(
            "The 'iso8583' package is required for ISO 8583 decoding. "
            "Install it with: pip install iso8583"
        )

    try:
        decoded, _ = iso8583.decode(raw_data, spec=spec)
    except iso8583.DecodeError as e:
        if "Extra data after last field" in str(e):
            # Re-decode tolerating trailing data
            decoded, _ = iso8583.decode(raw_data[:len(raw_data)], spec=spec)
        else:
            raise

    readable_output = {}
    readable_output['MTI'] = decoded.get('t', '')

    for field, value in decoded.items():
        if field != 't' and value is not None:
            readable_output[field] = value

    return readable_output
