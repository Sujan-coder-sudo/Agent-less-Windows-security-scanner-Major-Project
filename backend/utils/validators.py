"""
Validation utilities for secure input handling.
"""

import re
import ipaddress
from typing import Optional
from .exceptions import ValidationError


# Regex patterns for security validation
IP_ADDRESS_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

CIDR_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
)

# Dangerous characters that could be used for injection
DANGEROUS_CHARS = re.compile(r'[;|&$`\n\r\\]')


def validate_ip_address(target: str) -> bool:
    """
    Validate IP address or CIDR range.
    
    Args:
        target: IP address or CIDR range (e.g., '192.168.1.1' or '192.168.1.0/24')
    
    Returns:
        True if valid
    
    Raises:
        ValidationError: If the input is invalid or contains dangerous characters
    """
    if not target:
        raise ValidationError("Target cannot be empty")
    
    # Check for dangerous characters that could be used for command injection
    if DANGEROUS_CHARS.search(target):
        raise ValidationError("Target contains invalid characters")
    
    # Try to validate as IP address
    if IP_ADDRESS_PATTERN.match(target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            raise ValidationError(f"Invalid IP address: {target}")
    
    # Try to validate as CIDR range
    if CIDR_PATTERN.match(target):
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            raise ValidationError(f"Invalid CIDR range: {target}")
    
    # Try ipaddress module as fallback (handles edge cases)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    raise ValidationError(f"Invalid IP address or CIDR range: {target}")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to sanitize
    
    Returns:
        Sanitized filename
    
    Raises:
        ValidationError: If the filename is invalid
    """
    if not filename:
        raise ValidationError("Filename cannot be empty")
    
    # Remove path components
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Check for remaining dangerous patterns
    if DANGEROUS_CHARS.search(filename):
        raise ValidationError("Filename contains invalid characters")
    
    return filename


def validate_script_path(base_dir: str, script_path: str) -> str:
    """
    Validate that a script path is within the allowed base directory.
    
    Args:
        base_dir: The allowed base directory
        script_path: The script path to validate
    
    Returns:
        Absolute path if valid
    
    Raises:
        ValidationError: If the path is outside the allowed directory
    """
    import os
    
    # Convert to absolute paths
    base_dir = os.path.abspath(base_dir)
    full_path = os.path.abspath(os.path.join(base_dir, script_path))
    
    # Ensure the path is within the base directory
    if not full_path.startswith(base_dir):
        raise ValidationError(f"Script path is outside allowed directory: {script_path}")
    
    # Check that the file exists and is a .py file
    if not os.path.isfile(full_path):
        raise ValidationError(f"Script not found: {script_path}")
    
    if not full_path.endswith('.py'):
        raise ValidationError(f"Only Python scripts are allowed: {script_path}")
    
    return full_path


def validate_port_number(port: int) -> bool:
    """
    Validate a port number.
    
    Args:
        port: Port number to validate
    
    Returns:
        True if valid (1-65535)
    
    Raises:
        ValidationError: If the port is invalid
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"Port must be a number: {port}")
    
    if port < 1 or port > 65535:
        raise ValidationError(f"Port must be between 1 and 65535: {port}")
    
    return True
