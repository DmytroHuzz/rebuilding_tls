# utils.py
#
# SHARED UTILITIES FOR PART 3
#
# Small helpers used across versions.  Nothing cryptographic lives here —
# just formatting and convenience functions.


def hex_preview(data: bytes, max_bytes: int = 16) -> str:
    """Return a short hex preview of raw bytes, for debug printing."""
    preview = data[:max_bytes].hex()
    if len(data) > max_bytes:
        preview += "..."
    return preview
