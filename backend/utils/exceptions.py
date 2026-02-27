"""
Custom exceptions for the Agentless Scanner API.
"""


class ScannerAPIError(Exception):
    """Base exception for scanner API errors."""
    pass


class ValidationError(ScannerAPIError):
    """Raised when input validation fails."""
    pass


class ExecutionError(ScannerAPIError):
    """Raised when subprocess execution fails."""
    pass


class FileReadError(ScannerAPIError):
    """Raised when file reading fails."""
    pass


class JSONParseError(ScannerAPIError):
    """Raised when JSON parsing fails."""
    pass


class TimeoutError(ScannerAPIError):
    """Raised when execution times out."""
    pass
