"""Utility functions for the web server."""

def sanitize_string(s):
    """Remove potentially dangerous characters."""
    return s.replace("<", "&lt;").replace(">", "&gt;")

def format_response(status, data):
    """Format a JSON response."""
    return {"status": status, "data": data, "version": "1.0"}
