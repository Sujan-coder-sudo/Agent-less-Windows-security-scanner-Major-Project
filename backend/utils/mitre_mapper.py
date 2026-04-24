import json
import os

class MitreMapper:
    """
    Enriches vulnerability findings with MITRE ATT&CK tactics, techniques, and IDs.
    """
    
    # Standard mapping knowledge base for common enterprise Windows vulnerabilities
    KNOWLEDGE_BASE = {
        "SMB": {
            "tactic": "Lateral Movement",
            "technique": "Exploitation of Remote Services",
            "technique_id": "T1210",
            "description": "Adversaries may exploit remote services such as SMB to gain unauthorized access to internal systems."
        },
        "RDP": {
            "tactic": "Lateral Movement",
            "technique": "Remote Services: Remote Desktop Protocol",
            "technique_id": "T1021.001",
            "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP)."
        },
        "WinRM": {
            "tactic": "Execution",
            "technique": "Windows Management Instrumentation",
            "technique_id": "T1047",
            "description": "Adversaries may abuse WMI to execute malicious commands and payloads."
        },
        "Password Policy": {
            "tactic": "Credential Access",
            "technique": "Brute Force: Password Guessing",
            "technique_id": "T1110.001",
            "description": "Adversaries may guess passwords to attempt access to accounts when passwords are not sufficiently complex."
        },
        "Missing Patches": {
            "tactic": "Privilege Escalation",
            "technique": "Exploitation for Privilege Escalation",
            "technique_id": "T1068",
            "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges."
        },
        "FTP": {
            "tactic": "Exfiltration",
            "technique": "Exfiltration Over Alternative Protocol",
            "technique_id": "T1048",
            "description": "Adversaries may steal data by exfiltrating it over an unencrypted FTP connection."
        },
        "Default": {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program."
        }
    }

    @classmethod
    def get_mapping(cls, service_or_category: str) -> dict:
        """
        Return the corresponding MITRE ATT&CK mapping for a given service or category.
        Performs a fuzzy match on the key.
        """
        if not service_or_category:
            return cls.KNOWLEDGE_BASE["Default"]
            
        service_upper = service_or_category.upper()
        
        for key, mapping in cls.KNOWLEDGE_BASE.items():
            if key.upper() in service_upper or service_upper in key.upper():
                return mapping
                
        # Default fallback if no match is found
        return cls.KNOWLEDGE_BASE["Default"]

    @classmethod
    def enrich_finding(cls, finding_dict: dict) -> dict:
        """
        Takes a raw finding dictionary and adds a 'mitre_attack' block.
        """
        # Determine the key to map against (service for port scans, category for OS inspection)
        mapping_key = finding_dict.get("service") or finding_dict.get("category") or ""
        
        mitre_data = cls.get_mapping(mapping_key)
        finding_dict["mitre_attack"] = mitre_data
        
        return finding_dict
