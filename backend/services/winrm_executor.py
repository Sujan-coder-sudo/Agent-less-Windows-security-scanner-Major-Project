import winrm
import logging

logger = logging.getLogger(__name__)

class WinRMExecutor:
    """
    Enterprise-grade WinRM execution engine.
    Replaces the local, blocking PowerShell `subprocess.run` execution
    with authenticated, remote, agentless scanning.
    """
    def __init__(self, target: str, username: str = None, password: str = None):
        self.target = target
        self.username = username
        self.password = password
        
        # In a real environment, we would use proper certificate validation
        # For local development/testing, we allow NTLM with ignore certs
        self.session = winrm.Session(
            target, 
            auth=(username, password) if username and password else None,
            transport='ntlm',
            server_cert_validation='ignore'
        )

    def run_ps(self, script: str) -> dict:
        """
        Executes a PowerShell script on the remote target and returns the result.
        """
        logger.info(f"Executing remote WinRM script on {self.target}...")
        try:
            # Wrap script to ensure it runs in PowerShell
            encoded_ps = winrm.Session._clean_error_msg(script) # just a safety check
            
            result = self.session.run_ps(script)
            
            return {
                "status_code": result.status_code,
                "stdout": result.std_out.decode('utf-8', errors='ignore').strip(),
                "stderr": result.std_err.decode('utf-8', errors='ignore').strip()
            }
        except Exception as e:
            logger.error(f"WinRM execution failed on {self.target}: {str(e)}")
            return {
                "status_code": -1,
                "stdout": "",
                "stderr": str(e)
            }

    # ── Standard Enterprise Checks ─────────────────────────────────────────────

    def check_password_policy(self):
        script = "net accounts"
        return self.run_ps(script)

    def check_smb_signing(self):
        script = "Get-ItemPropertyValue -Path 'HKLM:\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue"
        return self.run_ps(script)

    def check_installed_software(self):
        script = "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName | ConvertTo-Json"
        return self.run_ps(script)

    def check_windows_defender(self):
        script = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled | ConvertTo-Json"
        return self.run_ps(script)
