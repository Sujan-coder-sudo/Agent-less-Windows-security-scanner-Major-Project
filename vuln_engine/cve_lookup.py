import requests
from typing import List


def search_cve(query: str) -> List[str]:
    """
    Search NVD (National Vulnerability Database) for CVEs matching the query.
    
    Args:
        query: Search keyword (e.g., "SMB EternalBlue", "Redis unauthenticated")
    
    Returns:
        List of CVE IDs (e.g., ["CVE-2017-0144", "CVE-2020-0796"])
        Empty list if no results or on any error
    """
    # Input validation
    if not query or not isinstance(query, str):
        return []
    
    query = query.strip()
    if len(query) < 2:
        return []
    
    # Reject error strings or object references
    invalid_patterns = [
        "NoneType", "object has no attribute", "ERROR:",
        "<class", "Traceback", "Exception", "null", "undefined",
        "[object", "function()"
    ]
    if any(pattern in query for pattern in invalid_patterns):
        return []
    
    try:
        res = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": query,
                "resultsPerPage": 3
            },
            timeout=10
        )
        res.raise_for_status()
        data = res.json()
        
        return [
            item["cve"]["id"]
            for item in data.get("vulnerabilities", [])
            if "cve" in item and "id" in item["cve"]
        ]
        
    except requests.exceptions.RequestException:
        return []
    except Exception:
        return []

