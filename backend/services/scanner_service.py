"""
Scanner service layer - orchestrates scan execution and result processing.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

from utils.execution import execution_manager, ExecutionResult
from utils.json_parser import JSONParser, Phase2Normalizer, Phase3Normalizer
from utils.validators import validate_script_path
from utils.exceptions import ExecutionError, FileReadError, ValidationError

logger = logging.getLogger(__name__)


class ScannerService:
    """
    Service layer for scanner operations.
    Handles execution, result parsing, and data normalization.
    """
    
    # Base directory for scanner scripts
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    
    # Script paths (relative to base dir)
    PHASE2_SCRIPT = 'agentless-scanner/phase2/test.py'
    PHASE3_SCRIPT = 'agentless-scanner/phase3/core1.py'
    
    # Output file paths
    PHASE2_OUTPUT = 'agentless-scanner/phase2/output/phase2_exposure.json'
    PHASE3_OUTPUT = 'agentless-scanner/phase3/output/scan_report.json'
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._validate_paths()
    
    def _validate_paths(self):
        """Validate that required paths exist."""
        scanner_dir = os.path.join(self.BASE_DIR, 'agentless-scanner')
        if not os.path.exists(scanner_dir):
            self.logger.warning(f"Scanner directory not found: {scanner_dir}")
    
    def _get_absolute_path(self, relative_path: str) -> str:
        """Convert relative path to absolute path."""
        return os.path.join(self.BASE_DIR, relative_path)
    
    def run_phase2_scan(self, target: str) -> Dict[str, Any]:
        """
        Execute Phase 2 network exposure scan.
        
        Args:
            target: IP address or CIDR range to scan
        
        Returns:
            Normalized scan results
        
        Raises:
            ExecutionError: If scan execution fails
            FileReadError: If output file cannot be read
        """
        self.logger.info(f"Starting Phase 2 scan for target: {target}")

        # Resolve absolute paths up-front (needed both inside and after try)
        script_path = self._get_absolute_path(self.PHASE2_SCRIPT)
        output_path = self._get_absolute_path(self.PHASE2_OUTPUT)
        working_dir = os.path.dirname(script_path)

        # Ensure output directory exists before running
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        try:
            # Execute using the runner module
            runner_script = os.path.join(working_dir, 'runner.py')

            if os.path.exists(runner_script):
                result = self._execute_runner(target, working_dir)
            else:
                self.logger.warning("Runner not found, using direct execution")
                result = execution_manager.execute_python_script(
                    script_path=script_path,
                    working_dir=working_dir,
                    timeout=300
                )

            if not result.is_success():
                self.logger.warning(
                    f"Phase 2 scan returned non-zero code {result.returncode}. "
                    f"STDERR: {result.stderr[:500]}"
                )
                # Continue anyway — partial results may have been written

            # Check output file exists
            if not os.path.exists(output_path):
                raise FileReadError(
                    f"Phase 2 output file not found: {output_path}. "
                    f"Script STDERR: {result.stderr[:300] if result.stderr else 'none'}"
                )

            # Guard against empty file (script may have crashed silently)
            if os.path.getsize(output_path) == 0:
                raise FileReadError(
                    f"Phase 2 output file is empty — the scan script likely failed. "
                    f"Test manually: python \"{script_path}\". "
                    f"Script STDERR: {result.stderr[:300] if result.stderr else 'none'}"
                )

            raw_data = JSONParser.parse_file(output_path, default={})

            # Get the latest scan entry
            latest_scan = self._extract_latest_phase2_scan(raw_data)

            # Normalize data for UI
            normalized = Phase2Normalizer.normalize(latest_scan)

            # Add execution metadata
            normalized['execution'] = result.to_dict()

            self.logger.info(
                f"Phase 2 scan complete: {normalized['summary']['total_hosts']} hosts, "
                f"{normalized['summary']['total_open_ports']} ports, "
                f"risk: {normalized['summary']['risk_level']}"
            )

            return normalized

            
        except Exception as e:
            self.logger.exception(f"Phase 2 scan failed: {e}")
            raise ExecutionError(f"Phase 2 scan failed: {str(e)}")
    
    def _execute_runner(self, target: str, working_dir: str) -> ExecutionResult:
        """
        Execute the Phase 2 runner with the given target.
        Creates a temporary wrapper script to pass the target IP.
        """
        import tempfile
        
        # Create a temporary script that calls runner.py functions
        temp_script_content = f'''
import sys
sys.path.insert(0, r"{working_dir}")
from runner import phase2_execute, append_scan_result

result = phase2_execute("{target}")
append_scan_result(result)
print("[Phase2] Scan completed and appended successfully")
'''
        
        # Write temporary script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(temp_script_content)
            temp_script = f.name
        
        try:
            result = execution_manager.execute_python_script(
                script_path=temp_script,
                working_dir=working_dir,
                timeout=300
            )
            return result
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_script)
            except:
                pass
    
    def _extract_latest_phase2_scan(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract the latest scan from Phase 2 output."""
        # Check if data has 'history' key (new format)
        history = JSONParser.safe_get(raw_data, 'history', [])
        
        if isinstance(history, list) and len(history) > 0:
            # Return the last entry (most recent)
            return history[-1]
        
        # If no history, assume the whole data is a single scan
        return raw_data
    
    def run_phase3_scan(self) -> Dict[str, Any]:
        """
        Execute Phase 3 system vulnerability scan.
        
        Returns:
            Normalized scan results
        
        Raises:
            ExecutionError: If scan execution fails
            FileReadError: If output file cannot be read
        """
        self.logger.info("Starting Phase 3 scan")
        
        # Validate script path
        script_path = self._get_absolute_path(self.PHASE3_SCRIPT)
        working_dir = os.path.dirname(script_path)
        
        # Ensure output directory exists
        output_dir = os.path.dirname(self._get_absolute_path(self.PHASE3_OUTPUT))
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Execute the script
            self.logger.info(f"Executing Phase 3 script: {script_path}")
            self.logger.info(f"Working directory: {working_dir}")
            
            result = execution_manager.execute_python_script(
                script_path=script_path,
                working_dir=working_dir,
                timeout=600  # Phase 3 can take longer due to NVD queries
            )
            
            self.logger.info(f"Phase 3 execution complete: returncode={result.returncode}")
            if result.stdout:
                self.logger.debug(f"Phase 3 stdout: {result.stdout[:500]}")
            if result.stderr:
                self.logger.warning(f"Phase 3 stderr: {result.stderr[:500]}")
            
            if not result.is_success():
                self.logger.warning(f"Phase 3 scan returned non-zero code: {result.returncode}")
                # Continue anyway as results may have been written
            
            # Read and parse output
            output_path = self._get_absolute_path(self.PHASE3_OUTPUT)
            
            if not os.path.exists(output_path):
                raise FileReadError(f"Phase 3 output file not found: {output_path}")
            
            raw_data = JSONParser.parse_file(output_path, default=[])
            
            # Normalize data for UI
            normalized = Phase3Normalizer.normalize(raw_data)
            
            # Add execution metadata
            normalized['execution'] = result.to_dict()
            
            self.logger.info(
                f"Phase 3 scan complete: {normalized['summary']['total_vulnerabilities']} vulns, "
                f"score: {normalized['summary']['risk_score']}"
            )
            
            return normalized
            
        except Exception as e:
            self.logger.exception(f"Phase 3 scan failed: {e}")
            raise ExecutionError(f"Phase 3 scan failed: {str(e)}")
    
    def get_overview_metrics(self) -> Dict[str, Any]:
        """
        Get overview metrics from latest scan results.
        
        Returns:
            Aggregated metrics
        """
        metrics = {
            "totalHosts": 0,
            "openPorts": 0,
            "highRiskServices": 0,
            "missingHotfixes": 0,
            "lastScan": None,
            "vulnData": [],
            "recentHosts": []
        }
        
        try:
            # Try to read Phase 2 output
            phase2_path = self._get_absolute_path(self.PHASE2_OUTPUT)
            if os.path.exists(phase2_path):
                raw_data = JSONParser.parse_file(phase2_path, default={})
                normalized = Phase2Normalizer.normalize(
                    self._extract_latest_phase2_scan(raw_data)
                )
                
                metrics["totalHosts"] = normalized["summary"]["total_hosts"]
                metrics["openPorts"] = normalized["summary"]["total_open_ports"]
                metrics["lastScan"] = normalized["scan_info"]["timestamp"]
                
                # Extract recent hosts
                for host in normalized["hosts"][:5]:  # Top 5
                    metrics["recentHosts"].append({
                        "ip": host["ip"],
                        "hostname": host["hostname"],
                        "risk": host.get("risk_level", "LOW"),
                        "lastSeen": normalized["scan_info"]["timestamp"]
                    })
                
                # Generate vulnerability distribution
                risk_dist = normalized["summary"]["risk_distribution"]
                metrics["vulnData"] = [
                    {"label": "Critical", "value": risk_dist.get("CRITICAL", 0), "color": "var(--accent-red)"},
                    {"label": "High", "value": risk_dist.get("HIGH", 0), "color": "var(--accent-red)"},
                    {"label": "Medium", "value": risk_dist.get("MEDIUM", 0), "color": "var(--accent-yellow)"},
                    {"label": "Low", "value": risk_dist.get("LOW", 0), "color": "var(--accent-cyan)"}
                ]
        except Exception as e:
            self.logger.warning(f"Could not load Phase 2 data for overview: {e}")
        
        try:
            # Try to read Phase 3 output
            phase3_path = self._get_absolute_path(self.PHASE3_OUTPUT)
            if os.path.exists(phase3_path):
                raw_data = JSONParser.parse_file(phase3_path, default=[])
                normalized = Phase3Normalizer.normalize(raw_data)
                
                summary = normalized["summary"]
                metrics["highRiskServices"] = (
                    summary.get("critical_count", 0) + summary.get("high_count", 0)
                )
                metrics["missingHotfixes"] = summary.get("high_count", 0)
                
                # Use Phase 3 timestamp if Phase 2 not available
                if not metrics["lastScan"]:
                    metrics["lastScan"] = normalized["scan_info"]["timestamp"]
        except Exception as e:
            self.logger.warning(f"Could not load Phase 3 data for overview: {e}")
        
        return metrics
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """
        Get scan history from Phase 2 output file.
        
        Returns:
            List of scan history entries
        """
        history = []
        
        try:
            phase2_path = self._get_absolute_path(self.PHASE2_OUTPUT)
            if not os.path.exists(phase2_path):
                return history
            
            raw_data = JSONParser.parse_file(phase2_path, default={})
            scan_history = JSONParser.safe_get(raw_data, 'history', [])
            
            if not isinstance(scan_history, list):
                return history
            
            for i, scan in enumerate(scan_history):
                if not isinstance(scan, dict):
                    continue
                
                history.append({
                    "id": 1000 + i,
                    "target": JSONParser.safe_get(scan, 'target', 'Unknown'),
                    "phase": "Phase 2",
                    "timestamp": JSONParser.safe_get(scan, 'scan_id'),
                    "status": "Success" if JSONParser.safe_get(scan, 'network_exposure') else "Failed",
                    "hosts": len(JSONParser.safe_get(scan, 'network_exposure', []))
                })
            
            # Sort by ID descending (newest first)
            history.reverse()
            
        except Exception as e:
            self.logger.warning(f"Could not load scan history: {e}")
        
        return history
