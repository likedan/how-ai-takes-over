"""Simple web server that processes user data."""

import json

def process_request(data):
    """Process incoming request data and return response."""
    parsed = json.loads(data)
    username = parsed["user"]["name"]
    # BUG: no null check — crashes if "email" key is missing
    email = parsed["user"]["email"]
    return {"status": "ok", "user": username, "email": email}

def validate_input(data):
    """Validate that input is proper JSON."""
    try:
        json.loads(data)
        return True
    except json.JSONDecodeError:
        return False

def main():
    sample = '{"user": {"name": "Alice"}}'
    if validate_input(sample):
        result = process_request(sample)  # This will crash
        print(result)

if __name__ == "__main__":
    main()
