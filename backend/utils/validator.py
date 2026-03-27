"""
validator.py
Input validation for scan targets.
Accepts: valid IPv4 addresses and 'localhost'.
Rejects: everything else.
"""

import re

IPV4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)$"
)


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate a scan target.

    Returns:
        (True, "")            — valid
        (False, "reason")     — invalid with explanation
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string."

    target = target.strip().lower()

    if target == "localhost":
        return True, ""

    if IPV4_PATTERN.match(target):
        return True, ""

    return False, f"Invalid target '{target}'. Must be a valid IPv4 address or 'localhost'."
