"""
JSON parser utility for safe JSON handling.
Handles missing keys, malformed data, and provides normalization.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

from utils.exceptions import JSONParseError, FileReadError

logger = logging.getLogger(__name__)


class JSONParser:
    """Safe JSON parsing utility with validation and normalization."""
    
    @staticmethod
    def parse_file(filepath: str, default: Optional[Any] = None) -> Any:
        """
        Safely parse a JSON file.
        
        Args:
            filepath: Path to JSON file
            default: Default value if parsing fails
        
        Returns:
            Parsed JSON data or default value
        
        Raises:
            FileReadError: If file cannot be read
            JSONParseError: If JSON is malformed
        """
        path = Path(filepath)
        
        if not path.exists():
            logger.warning(f"JSON file not found: {filepath}")
            if default is not None:
                return default
            raise FileReadError(f"File not found: {filepath}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if not content.strip():
                logger.warning(f"JSON file is empty: {filepath}")
                if default is not None:
                    return default
                raise JSONParseError(f"File is empty: {filepath}")
            
            data = json.loads(content)
            logger.debug(f"Successfully parsed JSON from {filepath}")
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {filepath}: {e}")
            if default is not None:
                return default
            raise JSONParseError(f"Invalid JSON in {filepath}: {e}")
            
        except UnicodeDecodeError as e:
            logger.error(f"Encoding error in {filepath}: {e}")
            if default is not None:
                return default
            raise FileReadError(f"File encoding error: {filepath}")
            
        except Exception as e:
            logger.exception(f"Unexpected error reading {filepath}: {e}")
            if default is not None:
                return default
            raise FileReadError(f"Failed to read file: {filepath}")
    
    @staticmethod
    def parse_string(json_str: str, default: Optional[Any] = None) -> Any:
        """
        Safely parse a JSON string.
        
        Args:
            json_str: JSON string to parse
            default: Default value if parsing fails
        
        Returns:
            Parsed JSON data or default value
        """
        if not json_str or not json_str.strip():
            if default is not None:
                return default
            raise JSONParseError("Empty JSON string")
        
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            if default is not None:
                return default
            raise JSONParseError(f"Invalid JSON: {e}")
    
    @staticmethod
    def get_nested(data: Dict[str, Any], *keys, default: Any = None) -> Any:
        """
        Safely get a nested value from a dictionary.
        
        Args:
            data: Dictionary to search
            keys: Sequence of keys to traverse
            default: Default value if key not found
        
        Returns:
            Value at the nested path or default
        """
        current = data
        for key in keys:
            if not isinstance(current, dict):
                return default
            current = current.get(key, default)
            if current is None:
                return default
        return current
    
    @staticmethod
    def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
        """
        Safely get a value from a dictionary.
        
        Args:
            data: Dictionary to search
            key: Key to retrieve
            default: Default value if key not found
        
        Returns:
            Value or default
        """
        if not isinstance(data, dict):
            return default
        return data.get(key, default)


class Phase2Normalizer:
    """Normalizer for Phase 2 scan results."""
    
    @staticmethod
    def normalize(raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Phase 2 scan data into UI-friendly format.
        
        Args:
            raw_data: Raw Phase 2 JSON data
        
        Returns:
            Normalized data structure
        """
        result = {
            "scan_info": {
                "scan_id": JSONParser.safe_get(raw_data, 'scan_id'),
                "target": JSONParser.safe_get(raw_data, 'target'),
                "phase": JSONParser.safe_get(raw_data, 'phase'),
                "timestamp": JSONParser.safe_get(raw_data, 'scan_id')
            },
            "summary": {
                "total_hosts": 0,
                "total_open_ports": 0,
                "risk_level": "LOW",
                "risk_distribution": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            },
            "hosts": [],
            "local_context": JSONParser.safe_get(raw_data, 'local_context', {})
        }
        
        # Process network exposure data
        network_exposure = JSONParser.safe_get(raw_data, 'network_exposure', [])
        
        if isinstance(network_exposure, list):
            for host_data in network_exposure:
                if isinstance(host_data, dict):
                    host_entry = Phase2Normalizer._normalize_host(host_data)
                    result["hosts"].append(host_entry)
                    
                    # Update summary counts
                    result["summary"]["total_hosts"] += 1
                    open_ports = len(JSONParser.safe_get(host_data, 'ports', []))
                    result["summary"]["total_open_ports"] += open_ports
                    
                    # Determine risk level based on open ports
                    risk_level = Phase2Normalizer._calculate_host_risk(host_data)
                    result["summary"]["risk_distribution"][risk_level] += 1
        
        # Calculate overall risk level
        result["summary"]["risk_level"] = Phase2Normalizer._calculate_overall_risk(
            result["summary"]["risk_distribution"]
        )
        
        # Add exposure summary text
        result["summary"]["exposure_summary"] = Phase2Normalizer._generate_summary_text(
            result["summary"]
        )
        
        return result
    
    @staticmethod
    def _normalize_host(host_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single host entry."""
        host = JSONParser.safe_get(host_data, 'host', 'Unknown')
        ports = JSONParser.safe_get(host_data, 'ports', [])
        
        # Ensure ports is a list
        if not isinstance(ports, list):
            ports = []
        
        normalized_ports = []
        services = []
        
        for port in ports:
            if isinstance(port, dict):
                port_num = JSONParser.safe_get(port, 'port', 0)
                state = JSONParser.safe_get(port, 'state', 'unknown')
                service = JSONParser.safe_get(port, 'service', '')
                version = JSONParser.safe_get(port, 'version', '')
                
                normalized_port = {
                    "port": port_num,
                    "state": state,
                    "service": service or "Unknown",
                    "version": version,
                    "risk_level": Phase2Normalizer._get_port_risk(port_num, service)
                }
                normalized_ports.append(normalized_port)
                
                if service and service not in services:
                    services.append(service)
        
        return {
            "ip": host,
            "hostname": JSONParser.safe_get(host_data, 'hostname', host),
            "status": JSONParser.safe_get(host_data, 'status', 'unknown'),
            "open_ports": len(normalized_ports),
            "ports": normalized_ports,
            "services": services,
            "os": JSONParser.safe_get(host_data, 'os', 'Unknown'),
            "error": JSONParser.safe_get(host_data, 'error')
        }
    
    @staticmethod
    def _get_port_risk(port: int, service: str) -> str:
        """Determine risk level for a port."""
        high_risk_ports = [21, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                          993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        critical_ports = [22, 445, 3389, 5985, 5986]  # SMB, RDP, WinRM
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_risk_ports:
            return "HIGH"
        elif port < 1024:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def _calculate_host_risk(host_data: Dict[str, Any]) -> str:
        """Calculate risk level for a host."""
        ports = JSONParser.safe_get(host_data, 'ports', [])
        
        critical_count = 0
        high_count = 0
        
        for port in ports:
            if isinstance(port, dict):
                port_num = JSONParser.safe_get(port, 'port', 0)
                risk = Phase2Normalizer._get_port_risk(port_num, '')
                if risk == "CRITICAL":
                    critical_count += 1
                elif risk == "HIGH":
                    high_count += 1
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count >= 3:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def _calculate_overall_risk(risk_distribution: Dict[str, int]) -> str:
        """Calculate overall risk level."""
        if risk_distribution.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif risk_distribution.get("HIGH", 0) > 0:
            return "HIGH"
        elif risk_distribution.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def _generate_summary_text(summary: Dict[str, Any]) -> str:
        """Generate human-readable exposure summary."""
        hosts = summary.get("total_hosts", 0)
        ports = summary.get("total_open_ports", 0)
        risk = summary.get("risk_level", "LOW")
        
        return f"Discovered {hosts} host(s) with {ports} open port(s). Overall risk: {risk}."


class Phase3Normalizer:
    """Normalizer for Phase 3 scan results."""
    
    @staticmethod
    def normalize(raw_data: Union[Dict, List]) -> Dict[str, Any]:
        """
        Normalize Phase 3 scan data into UI-friendly format.
        
        Args:
            raw_data: Raw Phase 3 JSON data (dict or list)
        
        Returns:
            Normalized data structure
        """
        result = {
            "scan_info": {
                "timestamp": None,
                "scanner": "Agentless Windows Vulnerability Scanner",
                "total_categories": 0
            },
            "summary": {
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "risk_score": 0,
                "os_info": {}
            },
            "os_profiling": {},
            "categories": [],
            "all_vulnerabilities": [],
            "all_cve_findings": [],
            "software_analysis": []
        }
        
        # Handle list format (multiple scans)
        if isinstance(raw_data, list) and len(raw_data) > 0:
            # Use the latest scan
            latest_scan = raw_data[-1]
            if isinstance(latest_scan, dict):
                raw_data = latest_scan
            else:
                return result
        
        if not isinstance(raw_data, dict):
            return result
        
        # Extract scan info
        result["scan_info"]["timestamp"] = JSONParser.safe_get(raw_data, 'run_timestamp')
        result["scan_info"]["scanner"] = JSONParser.safe_get(
            raw_data, 'scanner', result["scan_info"]["scanner"]
        )
        
        # Process results
        results = JSONParser.safe_get(raw_data, 'results', [])
        if not isinstance(results, list):
            return result
        
        result["scan_info"]["total_categories"] = len(results)
        
        for category_data in results:
            if not isinstance(category_data, dict):
                continue
            
            normalized_category = Phase3Normalizer._normalize_category(category_data)
            result["categories"].append(normalized_category)
            
            # Collect all vulnerabilities
            vulns = JSONParser.safe_get(category_data, 'detected_vulnerabilities', [])
            for vuln in vulns:
                if isinstance(vuln, dict):
                    vuln_copy = vuln.copy()
                    vuln_copy['category'] = normalized_category['name']
                    result["all_vulnerabilities"].append(vuln_copy)
                    
                    severity = vuln.get('severity', 'LOW')
                    if severity == 'CRITICAL':
                        result["summary"]["critical_count"] += 1
                    elif severity == 'HIGH':
                        result["summary"]["high_count"] += 1
                    elif severity == 'MEDIUM':
                        result["summary"]["medium_count"] += 1
                    else:
                        result["summary"]["low_count"] += 1
            
            # Collect CVE findings
            cve_findings = JSONParser.safe_get(category_data, 'cve_findings', [])
            for cve in cve_findings:
                if isinstance(cve, dict):
                    cve_copy = cve.copy()
                    cve_copy['category'] = normalized_category['name']
                    result["all_cve_findings"].append(cve_copy)
                    
                    severity = cve.get('severity', 'LOW')
                    if severity == 'CRITICAL':
                        result["summary"]["critical_count"] += 1
                    elif severity == 'HIGH':
                        result["summary"]["high_count"] += 1
                    elif severity == 'MEDIUM':
                        result["summary"]["medium_count"] += 1
                    else:
                        result["summary"]["low_count"] += 1
            
            # Collect software analysis
            sw_analysis = JSONParser.safe_get(category_data, 'software_analysis', [])
            if isinstance(sw_analysis, list):
                for sw in sw_analysis:
                    if isinstance(sw, dict) and sw not in result["software_analysis"]:
                        result["software_analysis"].append(sw)
            
            # Extract OS info from OS Profiling category
            if normalized_category['name'] == 'OS Profiling':
                result["os_profiling"] = normalized_category
                result["summary"]["risk_score"] = JSONParser.safe_get(
                    category_data, 'risk_score', 0
                )
        
        # Calculate total vulnerabilities
        result["summary"]["total_vulnerabilities"] = (
            result["summary"]["critical_count"] +
            result["summary"]["high_count"] +
            result["summary"]["medium_count"] +
            result["summary"]["low_count"]
        )
        
        return result
    
    @staticmethod
    def _normalize_category(category_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single category entry."""
        category_name = JSONParser.safe_get(category_data, 'category', 'Unknown')
        
        return {
            "name": category_name,
            "command": JSONParser.safe_get(category_data, 'command', ''),
            "summary": JSONParser.safe_get(category_data, 'summary', ''),
            "logic": JSONParser.safe_get(category_data, 'logic_reasoning', ''),
            "risk_score": JSONParser.safe_get(category_data, 'risk_score', 0),
            "vulnerabilities": JSONParser.safe_get(category_data, 'detected_vulnerabilities', []),
            "cve_findings": JSONParser.safe_get(category_data, 'cve_findings', []),
            "software_analysis": JSONParser.safe_get(category_data, 'software_analysis', []),
            "command_output": JSONParser.safe_get(category_data, 'command_output', '')[:500]
        }


# Convenience functions
def safe_json_load(filepath: str, default: Optional[Any] = None) -> Any:
    """Convenience function to safely load JSON from file."""
    return JSONParser.parse_file(filepath, default)


def get_nested_value(data: Dict[str, Any], *keys, default: Any = None) -> Any:
    """Convenience function to safely get nested values."""
    return JSONParser.get_nested(data, *keys, default=default)
