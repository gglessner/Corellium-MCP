import base64

def decode_base64_credentials(data):
    # Convert bytes to string for easier manipulation
    data_str = data.decode('latin1')

    # Find the start of the username (first base64 string)
    start_username = data_str.find('\x06')
    if start_username == -1:
        return "Error: Could not find username marker."

    # The base64 string for the username starts after \x06 and the next character
    start_username += 2
    end_username = data_str.find('\x07', start_username)
    if end_username == -1:
        return "Error: Could not find end of username."

    # Extract the username base64 string
    base64_string1 = data_str[start_username:end_username]

    # Find the start of the password (second base64 string)
    # It starts after \x07 and the next character
    start_password = end_username + 2
    end_password = data_str.find('\x81', start_password)
    if end_password == -1:
        return "Error: Could not find end of password."

    # Extract the password base64 string
    base64_string2 = data_str[start_password:end_password]

    # Decode base64 strings
    try:
        username = base64.b64decode(base64_string1).decode('utf-8')
        password = base64.b64decode(base64_string2).decode('utf-8')
        return f"Solace username: {username} - Solace password: {password}"
    except (base64.binascii.Error, UnicodeDecodeError):
        return "Error: Base64 decoding or UTF-8 decoding failed."
