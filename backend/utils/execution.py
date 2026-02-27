"""
Execution utility for secure subprocess execution.
Handles timeout, logging, and error handling.
"""

import subprocess
import logging
import os
import threading
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime

from utils.exceptions import ExecutionError, TimeoutError as ScannerTimeoutError

logger = logging.getLogger(__name__)


class ExecutionResult:
    """Container for execution results."""
    
    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        execution_time: float,
        command: List[str]
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.execution_time = execution_time
        self.command = command
        self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "returncode": self.returncode,
            "stdout": self.stdout[:5000] if self.stdout else "",  # Limit output size
            "stderr": self.stderr[:2000] if self.stderr else "",
            "execution_time_seconds": round(self.execution_time, 2),
            "command": " ".join(self.command),
            "timestamp": self.timestamp,
            "success": self.returncode == 0
        }
    
    def is_success(self) -> bool:
        """Check if execution was successful."""
        return self.returncode == 0


class ExecutionManager:
    """
    Secure subprocess execution manager.
    
    Features:
    - Timeout handling
    - No shell execution (prevents injection)
    - Logging of all executions
    - Resource limits
    """
    
    DEFAULT_TIMEOUT = 300  # 5 minutes
    MAX_OUTPUT_SIZE = 50 * 1024 * 1024  # 50MB
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def execute(
        self,
        command: List[str],
        working_dir: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Execute a command securely without shell.
        
        Args:
            command: List of command arguments (e.g., ['python', 'script.py'])
            working_dir: Working directory for execution
            env_vars: Additional environment variables
            timeout: Override default timeout (seconds)
        
        Returns:
            ExecutionResult with output and metadata
        
        Raises:
            ExecutionError: If execution fails
            ScannerTimeoutError: If execution times out
        """
        if not command:
            raise ExecutionError("Command cannot be empty")
        
        if not isinstance(command, list):
            raise ExecutionError("Command must be a list of arguments")
        
        # Ensure first argument exists
        if not os.path.isfile(command[0]) and not self._is_system_command(command[0]):
            raise ExecutionError(f"Command not found: {command[0]}")
        
        use_timeout = timeout or self.timeout
        
        self.logger.info(f"Executing: {' '.join(command)}")
        self.logger.debug(f"Working dir: {working_dir}, Timeout: {use_timeout}s")
        
        start_time = datetime.utcnow()
        
        try:
            # Prepare environment
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)
            
            # Execute without shell (secure)
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=working_dir,
                env=env,
                shell=False,  # Security: Never use shell
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            # Wait with timeout
            try:
                stdout, stderr = process.communicate(timeout=use_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise ScannerTimeoutError(f"Execution timed out after {use_timeout} seconds")
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            # Log results
            if process.returncode == 0:
                self.logger.info(f"Execution completed successfully in {execution_time:.2f}s")
            else:
                self.logger.warning(
                    f"Execution failed with code {process.returncode} in {execution_time:.2f}s"
                )
            
            # Limit output size
            stdout = stdout[:self.MAX_OUTPUT_SIZE] if stdout else ""
            stderr = stderr[:self.MAX_OUTPUT_SIZE] if stderr else ""
            
            return ExecutionResult(
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                command=command
            )
            
        except ScannerTimeoutError:
            raise
        except Exception as e:
            self.logger.exception(f"Execution failed: {str(e)}")
            raise ExecutionError(f"Failed to execute command: {str(e)}")
    
    def execute_python_script(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        working_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> ExecutionResult:
        """
        Execute a Python script securely.
        
        Args:
            script_path: Path to Python script
            args: Additional arguments for the script
            working_dir: Working directory
            timeout: Execution timeout
        
        Returns:
            ExecutionResult
        """
        # Find Python executable
        python_exe = self._get_python_executable()
        
        # Build command
        command = [python_exe, script_path]
        if args:
            command.extend(args)
        
        return self.execute(command, working_dir, timeout=timeout)
    
    def _is_system_command(self, cmd: str) -> bool:
        """Check if command is a system command (like 'python')."""
        system_cmds = ['python', 'python3', 'python.exe', 'py']
        return cmd.lower() in system_cmds
    
    def _get_python_executable(self) -> str:
        """Get the Python executable path."""
        import sys
        return sys.executable


# Global execution manager instance
execution_manager = ExecutionManager()
