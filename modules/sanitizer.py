def sanitize_data_for_safe_mode(data, output_format):
    if output_format != 'safe':
        return data

    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if key in ['password', 'retrieved_password', 'hash', 'ntlm', 'lm', 'description']:
                sanitized[key] = None
            elif key == 'sharedWith':
                sanitized[key] = []
            else:
                sanitized[key] = sanitize_data_for_safe_mode(value, output_format)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_data_for_safe_mode(item, output_format) for item in data]
    else:
        return data
