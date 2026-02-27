# Agentless Windows Vulnerability Scanner (Core Engine)
# Fully operational logic for:
# - Running local inspection commands (agentless)
# - Rule-driven vulnerability evaluation (VULNERABILITY_RULES baseline)
# - Modular NVD 2.0 CVE correlation (NVDClient + VulnerabilityCorrelator)
# - Exporting results to JSON and PDF
#
# Two finding types are produced:
#   1) CONFIGURATION / BASELINE findings  → from evaluate_rules()
#   2) CVE findings                        → from VulnerabilityCorrelator

import os
import json
import re
import subprocess
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

import requests
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from datetime import datetime

# Module-level logger — callers can adjust level via logging.basicConfig()
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Severity weights for risk score calculation
SEVERITY_WEIGHTS: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 7,
    "CRITICAL": 10,
}

# Globally detected OS CPE (populated by scan_os_profiling)
DETECTED_CPE: str = "cpe:2.3:o:microsoft:windows_10"


# ─────────────────────────────────────────────
# VULNERABILITY RULES
# ─────────────────────────────────────────────
VULNERABILITY_RULES: List[Dict[str, Any]] = [

    # ----------------------------------------
    # BOOT & PLATFORM SECURITY
    # ----------------------------------------

    {
        "id": "CIS-001",
        "title": "Secure Boot Disabled",
        "severity": "HIGH",
        "description": "Secure Boot is disabled, allowing unsigned bootloaders or bootkits.",
        "recommendation": "Enable Secure Boot in UEFI firmware.",
        "data_key": "edr_health",
        "condition": lambda v: "securebootenabled" in v.lower() and "false" in v.lower(),
    },

    {
        "id": "CIS-002",
        "title": "BitLocker Not Enabled",
        "severity": "HIGH",
        "description": "System drive is not encrypted using BitLocker.",
        "recommendation": "Enable BitLocker on OS and fixed drives.",
        "data_key": "infrastructure_link",
        "condition": lambda v: "protectionstatus" in v.lower() and "off" in v.lower(),
    },

    # ----------------------------------------
    # NETWORK HARDENING
    # ----------------------------------------

    {
        "id": "CIS-003",
        "title": "SMBv1 Enabled",
        "severity": "CRITICAL",
        "description": "SMBv1 protocol is enabled, exposing system to legacy exploits.",
        "recommendation": "Disable SMBv1 immediately.",
        "data_key": "service_status",
        "condition": lambda v: "enablesmb1protocol" in v.lower() and "true" in v.lower(),
    },

    {
        "id": "CIS-004",
        "title": "SMB Signing Not Required",
        "severity": "HIGH",
        "description": "SMB signing is not enforced, allowing relay attacks.",
        "recommendation": "Enable SMB signing via Group Policy.",
        "data_key": "service_status",
        "condition": lambda v: "requiressecuritysignature" in v.lower() and "false" in v.lower(),
    },

    {
        "id": "CIS-005",
        "title": "Windows Firewall Disabled",
        "severity": "CRITICAL",
        "description": "Windows Firewall profile is disabled.",
        "recommendation": "Enable firewall for Domain, Private, and Public profiles.",
        "data_key": "firewall",
        "condition": lambda v: "enabled" in v.lower() and "false" in v.lower(),
    },

    {
        "id": "CIS-006",
        "title": "LLMNR Enabled",
        "severity": "HIGH",
        "description": "LLMNR is enabled, allowing credential capture via spoofing.",
        "recommendation": "Disable LLMNR via Group Policy.",
        "data_key": "interface_stats",
        "condition": lambda v: "llmnr" in v.lower() and "enabled" in v.lower(),
    },

    # ----------------------------------------
    # REMOTE ACCESS CONTROLS
    # ----------------------------------------

    {
        "id": "CIS-007",
        "title": "RDP Enabled",
        "severity": "HIGH",
        "description": "Remote Desktop service is running.",
        "recommendation": "Disable RDP if not required or restrict via firewall.",
        "data_key": "service_status",
        "condition": lambda v: "termservice" in v.lower() and "running" in v.lower(),
    },

    {
        "id": "CIS-008",
        "title": "RDP Without Network Level Authentication",
        "severity": "CRITICAL",
        "description": "RDP does not enforce Network Level Authentication (NLA).",
        "recommendation": "Enable NLA in RDP settings.",
        "data_key": "edr_health",
        "condition": lambda v: "userauthentication" in v.lower() and "0" in v.lower(),
    },

    # ----------------------------------------
    # CREDENTIAL PROTECTION
    # ----------------------------------------

    {
        "id": "CIS-009",
        "title": "LSASS Not Protected (RunAsPPL Disabled)",
        "severity": "CRITICAL",
        "description": "LSASS protection is disabled, allowing credential dumping.",
        "recommendation": "Enable RunAsPPL protection via registry or GPO.",
        "data_key": "edr_health",
        "condition": lambda v: "runasppl" in v.lower() and ("0x0" in v.lower() or "false" in v.lower()),
    },

    {
        "id": "CIS-010",
        "title": "Multiple Local Administrators",
        "severity": "MEDIUM",
        "description": "Excessive members in the local Administrators group.",
        "recommendation": "Reduce administrator group membership.",
        "data_key": "users",
        "condition": lambda v: v.lower().count("administrator") > 1,
    },

    # ----------------------------------------
    # LOGGING & AUDITING
    # ----------------------------------------

    {
        "id": "CIS-011",
        "title": "Audit Policy Not Fully Enabled",
        "severity": "MEDIUM",
        "description": "Audit policy is not comprehensively configured.",
        "recommendation": "Enable success and failure auditing for key categories.",
        "data_key": "audit_policy",
        "condition": lambda v: "no auditing" in v.lower(),
    },

    {
        "id": "CIS-012",
        "title": "PowerShell Unrestricted Execution Policy",
        "severity": "HIGH",
        "description": "PowerShell execution policy allows unsigned scripts.",
        "recommendation": "Set execution policy to RemoteSigned or AllSigned.",
        "data_key": "audit_policy",
        "condition": lambda v: "executionpolicy" in v.lower() and "unrestricted" in v.lower(),
    },

    # ----------------------------------------
    # PATCH MANAGEMENT
    # ----------------------------------------

    {
        "id": "CIS-013",
        "title": "Missing Critical Windows Updates",
        "severity": "HIGH",
        "description": "System has pending or missing Windows updates.",
        "recommendation": "Install all critical and security updates.",
        "data_key": "hotfix_audit",
        "condition": lambda v: "isinstalled=0" in v.lower() or "kb" in v.lower(),
    },

    # ----------------------------------------
    # PERSISTENCE & MALWARE RESILIENCE
    # ----------------------------------------

    {
        "id": "CIS-014",
        "title": "WMI Event Consumer Detected",
        "severity": "HIGH",
        "description": "WMI subscription detected. This may indicate persistence mechanism.",
        "recommendation": "Review and remove unauthorized WMI consumers.",
        "data_key": "service_status",
        "condition": lambda v: "__eventconsumer" in v.lower(),
    },

    {
        "id": "CIS-015",
        "title": "Scheduled Task Running from Temp Path",
        "severity": "MEDIUM",
        "description": "Scheduled task referencing temporary directory detected.",
        "recommendation": "Investigate and remove suspicious scheduled tasks.",
        "data_key": "persistence",
        "condition": lambda v: any(p in v.lower() for p in ["temp\\", "appdata\\local\\temp"]),
    },
]
# ─────────────────────────────────────────────
# MINIMUM SECURE VERSION RULES FOR SOFTWARE
# ─────────────────────────────────────────────
SOFTWARE_VERSION_RULES: Dict[str, Dict[str, Any]] = {
    "7-zip": {
        "min_version": (23, 1, 0),
        "cpe_template": "cpe:2.3:a:7-zip:7-zip:{version}",
        "reason_insecure": "Versions below 23.01 are affected by CVE-2023-31102 (heap overflow).",
    },
    "google chrome": {
        "min_version": (120, 0, 0),
        "cpe_template": "cpe:2.3:a:google:chrome:{version}",
        "reason_insecure": "Older Chrome versions have known RCE and sandbox escape vulnerabilities.",
    },
    "mozilla firefox": {
        "min_version": (121, 0, 0),
        "cpe_template": "cpe:2.3:a:mozilla:firefox:{version}",
        "reason_insecure": "Older Firefox versions expose users to heap-use-after-free and RCE bugs.",
    },
    "vlc media player": {
        "min_version": (3, 0, 20),
        "cpe_template": "cpe:2.3:a:videolan:vlc_media_player:{version}",
        "reason_insecure": "Older VLC versions are vulnerable to buffer overflows (CVE-2023-47359).",
    },
    "python": {
        "min_version": (3, 11, 0),
        "cpe_template": "cpe:2.3:a:python:python:{version}",
        "reason_insecure": "Python versions below 3.11 have known security fixes missing.",
    },
    "openssl": {
        "min_version": (3, 0, 0),
        "cpe_template": "cpe:2.3:a:openssl:openssl:{version}",
        "reason_insecure": "OpenSSL versions below 3.0 are end-of-life with known critical CVEs.",
    },
    "git": {
        "min_version": (2, 43, 0),
        "cpe_template": "cpe:2.3:a:git:git:{version}",
        "reason_insecure": "Older Git versions are affected by credential leakage vulnerabilities.",
    },
}


# ─────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def get_run_timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def run_powershell(command: str) -> str:
    """Executes a PowerShell command in read-only inspection mode."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return completed.stdout.strip() or completed.stderr.strip()
    except Exception as e:
        return f"ERROR: {str(e)}"


def build_windows_cpe(product_name: str, version: str) -> str:
    """Builds a CPE 2.3 string from the detected Windows product name and build number."""
    name_lower = product_name.lower() if product_name else ""
    if "windows 11" in name_lower:
        base = "cpe:2.3:o:microsoft:windows_11"
    else:
        base = "cpe:2.3:o:microsoft:windows_10"
    return f"{base}:{version}" if version else base


# ─────────────────────────────────────────────
# NVD API CLIENT
# ─────────────────────────────────────────────

class NVDClient:
    """
    Thin, reusable wrapper around the NVD REST API 2.0.

    Features:
    - Optional API key (graceful fallback when absent)
    - Per-keyword in-memory cache to eliminate duplicate queries
    - Basic rate-limit sleep (NIST recommends 0.6 s without key, 0.1 s with key)
    - Pagination support via startIndex
    - Structured error handling — always returns a list, never raises
    """

    # Rate-limit sleep constants (seconds)
    _SLEEP_NO_KEY: float = 0.6
    _SLEEP_WITH_KEY: float = 0.1

    # Legacy / irrelevant OS keywords — CVEs mentioning these are excluded
    _LEGACY_OS_MARKERS: Tuple[str, ...] = (
        "windows xp",
        "windows vista",
        "windows 7",
        "windows 8",
        "windows server",
        "windows rt",
    )

    def __init__(self, api_key: Optional[str] = None) -> None:
        # Store optional API key
        self._api_key: Optional[str] = api_key
        # In-memory query cache: keyword → raw CVE list
        # Cache is per keywordSearch term (product). Version-specific filtering
        # is handled by VulnerabilityCorrelator.
        self._cache: Dict[str, List[Dict[str, Any]]] = {}

    # ── Internal helpers ────────────────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        """Build HTTP request headers, injecting API key when available."""
        h: Dict[str, str] = {"User-Agent": "Agentless-Vuln-Scanner/2.0"}
        if self._api_key:
            h["apiKey"] = self._api_key
        return h

    def _sleep(self) -> None:
        """Respect NVD rate-limit: 0.6 s without key, 0.1 s with key."""
        delay = self._SLEEP_WITH_KEY if self._api_key else self._SLEEP_NO_KEY
        time.sleep(delay)

    # ── Public API ──────────────────────────────────────────────────────────

    def query(self, keyword: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """
        Query NVD 2.0 by keyword (product name).

        Results are cached per keyword — duplicate calls are free.
        Paginates automatically until max_results are collected or NVD
        returns no more entries.

        Args:
            keyword:     Product name to search (e.g. "7-Zip").
            max_results: Upper bound on CVEs returned per product.

        Returns:
            List of raw CVE dicts from NVD response, or [] on error.
        """
        # Normalise cache key
        # Cache only by keyword. This ensures we don't duplicate NVD API calls
        # for the same product, while allowing multiple installed versions to be
        # filtered independently downstream.
        cache_key = keyword.strip().lower()
        if cache_key in self._cache:
            logger.debug("NVDClient cache hit for '%s'", keyword)
            return self._cache[cache_key]

        collected: List[Dict[str, Any]] = []
        start_index = 0
        page_size = min(max_results, 20)  # NVD recommends ≤ 20 per page without key

        try:
            while len(collected) < max_results:
                params: Dict[str, Any] = {
                    "keywordSearch": keyword,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                }
                self._sleep()  # rate-limit before every request
                response = requests.get(
                    NVD_URL,
                    headers=self._headers(),
                    params=params,
                    timeout=30,
                )
                response.raise_for_status()
                payload = response.json()

                batch = payload.get("vulnerabilities", [])
                if not batch:
                    break  # NVD returned no more results

                collected.extend(batch)
                total_results = payload.get("totalResults", 0)
                start_index += len(batch)

                # Stop if we have fetched everything NVD has
                if start_index >= total_results:
                    break

            logger.info("NVDClient: fetched %d CVEs for '%s'", len(collected), keyword)
        except requests.RequestException as exc:
            # Network/HTTP error — log and return empty list (graceful fallback)
            logger.warning("NVDClient query failed for '%s': %s", keyword, exc)
            collected = []
        except Exception as exc:
            logger.error("NVDClient unexpected error for '%s': %s", keyword, exc)
            collected = []

        # Persist in cache even on error so we don't retry repeatedly
        self._cache[cache_key] = collected
        return collected

    def clear_cache(self) -> None:
        """Flush the in-memory query cache."""
        self._cache.clear()
        logger.debug("NVDClient cache cleared")


# ─────────────────────────────────────────────
# VULNERABILITY CORRELATOR
# ─────────────────────────────────────────────

class VulnerabilityCorrelator:
    """
    Correlates installed Windows 10/11 software against NVD CVE data.

    Responsibilities:
    - Parse raw software inventory text into (product, version) pairs
    - Query NVDClient per product (cached, no duplicates)
    - Filter CVEs by CVSS score, version range, and OS relevance
    - Return structured CVE findings in a defined output schema
    """

    # Minimum CVSS v3 base score to include a CVE (HIGH and above)
    MIN_CVSS: float = 7.0

    # CVE description substrings that indicate the CVE applies only to
    # legacy or server Windows editions — these are filtered out.
    _LEGACY_OS_MARKERS: Tuple[str, ...] = (
        "windows xp",
        "windows vista",
        "windows 7",
        "windows 8",
        "windows server",
        "windows rt",
    )

    # Regex: match lines like "7-Zip 16.04 (x64)" or "Mozilla Firefox 121.0" etc.
    # Group 1 → product name, Group 2 → version string
    _LINE_RE = re.compile(
        r"^(?P<product>[A-Za-z][A-Za-z0-9 \-_+.()]+?)\s+"
        r"(?P<version>\d+[\d.]+(?:\s*\([^)]*\))?)",
        re.MULTILINE,
    )

    # Version number extractor (used to compare version strings numerically)
    _VERSION_RE = re.compile(r"(\d+)")

    def __init__(self, client: NVDClient) -> None:
        # Inject the NVDClient dependency
        self._client: NVDClient = client
        # Cache filtered findings per (product, version). This prevents repeated
        # filtering work when software inventory has duplicated lines.
        self._finding_cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    # ── Internal helpers ────────────────────────────────────────────────────

    def _parse_version(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """
        Convert a version string to a comparable integer tuple.
        e.g. "16.04" → (16, 4), "121.0.6167.85" → (121, 0, 6167, 85)
        Returns None if no digits found.
        """
        parts = self._VERSION_RE.findall(version_str)
        return tuple(int(p) for p in parts) if parts else None

    def _normalize_product(self, product: str) -> str:
        """Normalise product names for matching/deduplication."""
        # Keep common punctuation (e.g. 7-Zip), remove bracketed arch markers.
        cleaned = re.sub(r"\s*\([^)]*\)\s*", " ", product).strip().lower()
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned

    def _should_skip_product(self, product: str) -> bool:
        """
        Skip inventory entries that are not meaningful software correlation targets.

        This prevents obvious OS lines (e.g. 'Windows 7 ...') from being sent to NVD
        and reduces false-positive CVE matches.
        """
        p = self._normalize_product(product)
        # Explicit legacy Windows products should never be correlated.
        if any(marker in p for marker in ("windows xp", "windows vista", "windows 7", "windows 8")):
            return True
        # If the entry is literally the OS, correlation is handled elsewhere.
        if p in {"windows", "microsoft windows", "windows 10", "windows 11"}:
            return True
        return False

    def _parse_version_str(self, version_str: str) -> Optional[Tuple[int, ...]]:
        """Alias kept for internal callers."""
        return self._parse_version(version_str)

    def _severity_from_score(self, score: float) -> str:
        """Map a CVSS v3 numeric base score to a severity label."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _is_legacy_os_cve(self, description: str) -> bool:
        """
        Return True if the CVE description exclusively targets legacy or
        server Windows editions (Windows XP, 7, Vista, Server, RT).

        Strategy: the description is considered 'legacy-only' when it
        mentions at least one legacy marker AND does NOT mention Windows 10
        or Windows 11.
        """
        desc_lower = description.lower()
        # Check for any legacy keyword
        has_legacy = any(marker in desc_lower for marker in self._LEGACY_OS_MARKERS)
        if not has_legacy:
            return False  # No legacy marker → not filtered
        # If it ALSO mentions Win10/Win11, keep it (might affect both)
        if "windows 10" in desc_lower or "windows 11" in desc_lower:
            return False
        return True  # Legacy-only → filter out

    def _is_windows_server_only_cve(self, description: str) -> bool:
        """
        Return True when a CVE appears to apply only to Windows Server.

        Note: This is intentionally conservative: if the description mentions
        Windows Server but also mentions Windows 10/11, we keep it.
        """
        desc_lower = description.lower()
        if "windows server" not in desc_lower:
            return False
        if "windows 10" in desc_lower or "windows 11" in desc_lower:
            return False
        return True

    def _is_relevant_to_product(self, cve_obj: Dict[str, Any], product: str, description: str) -> bool:
        """
        Best-effort relevance filter to avoid pulling unrelated CVEs returned by keywordSearch.

        NVD keywordSearch can match many unrelated entries. We prefer:
        - configuration CPE criteria referencing the product, OR
        - description mentioning the product name.
        """
        product_norm = self._normalize_product(product)
        # Build tokens that often appear in CPE strings (spaces become underscores).
        cpe_token = product_norm.replace(" ", "_")

        configurations = cve_obj.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = str(cpe_match.get("criteria", "")).lower()
                    if not criteria:
                        continue
                    # If CPE criteria includes the product token, treat it as relevant.
                    if cpe_token and cpe_token in criteria:
                        return True

        # Fallback: description text match (less reliable but better than nothing).
        return product_norm in description.lower()

    def _version_in_range(
        self,
        version: str,
        start_incl: Optional[str],
        end_excl: Optional[str],
    ) -> bool:
        """
        Check whether `version` falls in [start_incl, end_excl).
        If either bound is missing, that side is considered open.

        Returns True (vulnerable) when version is within the range,
        or when NVD provides no range information at all.
        """
        parsed = self._parse_version(version)
        if parsed is None:
            return True  # Cannot evaluate — assume vulnerable (safe default)

        if start_incl:
            start = self._parse_version(start_incl)
            if start and parsed < start:
                return False  # Version is below the affected range

        if end_excl:
            end = self._parse_version(end_excl)
            if end and parsed >= end:
                return False  # Version is at or above the fixed version

        return True  # Within range (or range unknown)

    def _extract_cve_details(
        self,
        raw_item: Dict[str, Any],
        product: str,
        version: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single NVD vulnerability item and return a structured CVE
        finding dict, or None if the CVE should be filtered out.

        Filters applied:
        1. CVSS v3 base score must be >= MIN_CVSS
        2. Description must not be legacy-OS-only
        3. Version range (if provided by NVD) must match installed version
        """
        cve = raw_item.get("cve", {})
        cve_id: str = cve.get("id", "UNKNOWN")

        # ── Description ─────────────────────────────────────────────
        descriptions = cve.get("descriptions", [])
        description: str = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            (descriptions[0]["value"] if descriptions else ""),
        )

        # Filter 0: reject CVEs that don't appear to match the product we queried.
        # This is required because keywordSearch can yield unrelated CVEs.
        if not self._is_relevant_to_product(cve, product, description):
            logger.debug("Skipping %s — not relevant to product '%s'", cve_id, product)
            return None

        # Filter 1: reject legacy-OS-only CVEs
        if self._is_legacy_os_cve(description):
            logger.debug("Skipping %s — legacy OS only", cve_id)
            return None

        # Filter 1b: reject Windows Server-only CVEs (do not report as Win10/11 findings)
        if self._is_windows_server_only_cve(description):
            logger.debug("Skipping %s — Windows Server only", cve_id)
            return None

        # ── CVSS v3 score ────────────────────────────────────────────
        metrics = cve.get("metrics", {})
        # Prefer v3.1, fall back to v3.0
        cvss_entries: List[Dict[str, Any]] = (
            metrics.get("cvssMetricV31") or
            metrics.get("cvssMetricV30") or
            []
        )
        if not cvss_entries:
            return None  # No CVSS v3 score — skip

        cvss_data = cvss_entries[0].get("cvssData", {})
        base_score: float = cvss_data.get("baseScore", 0.0)

        # Filter 2: reject LOW/MEDIUM CVEs (< 7.0)
        if base_score < self.MIN_CVSS:
            return None

        # ── Version range check ──────────────────────────────────────
        # NVD CPE match data may contain version bounds per configuration
        start_incl: Optional[str] = None
        end_excl: Optional[str] = None
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    # Take the first relevant version bounds found
                    start_incl = start_incl or cpe_match.get("versionStartIncluding")
                    end_excl = end_excl or cpe_match.get("versionEndExcluding")

        # Filter 3: version range mismatch → skip
        if not self._version_in_range(version, start_incl, end_excl):
            logger.debug(
                "Skipping %s — version %s not in range [%s, %s)",
                cve_id, version, start_incl, end_excl,
            )
            return None

        severity = self._severity_from_score(base_score)
        published: str = cve.get("published", "")

        # Build a short title from the first sentence of the description
        title = description.split(".")[0][:120] if description else cve_id

        return {
            "id": cve_id,
            "title": title,
            "severity": severity,
            "description": description,
            "cvss_score": base_score,
            "published": published,
            "source": "NVD",
            "affected_product": product,
            "affected_version": version,
        }

    # ── Public API ──────────────────────────────────────────────────────────

    def parse_software_entry(self, raw_name: str) -> Tuple[str, str]:
        """
        Split a raw software inventory line into (product, version).

        Examples:
            "7-Zip 16.04 (x64)"       → ("7-Zip", "16.04")
            "Mozilla Firefox 121.0"   → ("Mozilla Firefox", "121.0")
            "Python 3.11.5 (64-bit)" → ("Python", "3.11.5")
        """
        m = self._LINE_RE.match(raw_name.strip())
        if not m:
            return raw_name.strip(), ""
        product = m.group("product").strip()
        # Extract just the numeric version from the raw version token
        ver_token = m.group("version").strip()
        ver_nums = re.findall(r"\d+[\d.]*", ver_token)
        version = ver_nums[0] if ver_nums else ver_token
        return product, version

    def filter_cves(
        self,
        raw_cves: List[Dict[str, Any]],
        product: str,
        version: str,
    ) -> List[Dict[str, Any]]:
        """
        Apply all CVE filters to a raw NVD response list.

        Args:
            raw_cves: List of vulnerability dicts from NVDClient.query()
            product:  Parsed product name (e.g. "7-Zip")
            version:  Parsed version string (e.g. "16.04")

        Returns:
            Filtered list of structured CVE finding dicts.
        """
        findings: List[Dict[str, Any]] = []
        for item in raw_cves:
            finding = self._extract_cve_details(item, product, version)
            if finding:
                findings.append(finding)
        return findings

    def correlate_software(self, software_output: str) -> List[Dict[str, Any]]:
        """
        Main entry point: parse installed software list and correlate with NVD.

        Parses each line of the software inventory, queries NVD by product
        keyword (cached), filters CVEs, and returns all HIGH/CRITICAL CVE
        findings across all installed applications.

        Args:
            software_output: Raw text from PowerShell Get-Package / Win32_Product

        Returns:
            List of CVE finding dicts (may be empty if NVD is unreachable).
        """
        all_cve_findings: List[Dict[str, Any]] = []
        # Prevent duplicate filtering work per (product, version) pair.
        # NVDClient already prevents duplicate API queries per product keyword.
        seen_pairs: set = set()

        # Parse each line from the software inventory output
        for line in software_output.splitlines():
            line = line.strip()
            if not line:
                continue

            product, version = self.parse_software_entry(line)

            # Skip lines where we couldn't extract a meaningful product name
            if not product or not version:
                continue

            # Skip OS/legacy noise entries (only correlate real installed software).
            if self._should_skip_product(product):
                continue

            product_key = self._normalize_product(product)
            pair_key = (product_key, version)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # If we have cached filtered findings for this exact product+version,
            # re-use them to keep correlation fast and deterministic.
            if pair_key in self._finding_cache:
                all_cve_findings.extend(self._finding_cache[pair_key])
                continue

            logger.info("Correlating: %s %s", product, version)

            # Query NVD (cached internally in NVDClient)
            raw_cves = self._client.query(keyword=product)

            # Apply filters and collect findings
            findings = self.filter_cves(raw_cves, product, version)
            self._finding_cache[pair_key] = findings
            if findings:
                logger.info(
                    "Found %d qualifying CVE(s) for %s %s",
                    len(findings), product, version,
                )
            all_cve_findings.extend(findings)

        return all_cve_findings


# Backward-compatible shim: preserved so any external code using
# query_nvd_cpe() does not break. New code should use NVDClient directly.
def query_nvd_cpe(
    cpe: str,
    limit: int = 10,
    min_year: int = 2018,
    min_cvss: float = 7.0,
) -> Tuple[Dict[str, Any], ...]:
    """
    Legacy CPE-based NVD query helper (preserved for backward compatibility).
    New callers should use NVDClient.query() instead.
    """
    params: Dict[str, Any] = {"cpeName": cpe, "resultsPerPage": limit}
    headers: Dict[str, str] = {"User-Agent": "Agentless-Vuln-Scanner/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        r = requests.get(NVD_URL, headers=headers, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        results: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            published = cve.get("published", "")
            try:
                if int(published.split("-")[0]) < min_year:
                    continue
            except (ValueError, IndexError):
                pass
            cvss_list = cve.get("metrics", {}).get("cvssMetricV31", [])
            if not cvss_list:
                continue
            base_score: float = cvss_list[0].get("cvssData", {}).get("baseScore", 0.0)
            if base_score < min_cvss:
                continue
            results.append({
                "cve_id": cve.get("id"),
                "description": (cve.get("descriptions") or [{}])[0].get("value", ""),
                "cvss_score": base_score,
                "published": published,
            })
            if len(results) >= limit:
                break
        return tuple(results)
    except Exception as exc:
        return ({"error": str(exc)},)


# ─────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────

def evaluate_rules(context: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Evaluates VULNERABILITY_RULES against the collected scan context.
    Returns a list of triggered vulnerability findings.
    """
    findings: List[Dict[str, Any]] = []
    for rule in VULNERABILITY_RULES:
        data_value = context.get(rule["data_key"], "")
        try:
            triggered = rule["condition"](data_value)
        except Exception:
            triggered = False

        if triggered:
            findings.append({
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "description": rule["description"],
                "recommendation": rule["recommendation"],
            })
    return findings


# ─────────────────────────────────────────────
# SOFTWARE SECURITY CLASSIFICATION ENGINE
# ─────────────────────────────────────────────

def _parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parses a version string into a comparable integer tuple."""
    parts = re.findall(r"\d+", version_str)
    if not parts:
        return None
    return tuple(int(p) for p in parts[:3])


def _match_software_rule(name_lower: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Returns the matching software rule key and config, or None."""
    for key, rule in SOFTWARE_VERSION_RULES.items():
        if key in name_lower:
            return key, rule
    return None


def analyze_software_security(software_output: str) -> List[Dict[str, Any]]:
    """
    Parses software_output (from Get-Package or Win32_Product) and classifies
    each application as SECURE, INSECURE, UNASSESSED, or UNKNOWN.
    NVD is only queried for INSECURE applications.
    """
    results: List[Dict[str, Any]] = []
    seen: set = set()

    # Match lines like: "Name        7-Zip 23.01 (x64)" or "7-Zip 16.04    16.04"
    line_pattern = re.compile(
        r"^(?P<name>[A-Za-z0-9][A-Za-z0-9 \-_.()]+?)\s{2,}(?P<version>\d[\d.]*)",
        re.MULTILINE,
    )

    for match in line_pattern.finditer(software_output):
        raw_name = match.group("name").strip()
        raw_version = match.group("version").strip()

        # Deduplicate by normalised name
        dedup_key = raw_name.lower()
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        parsed_ver = _parse_version(raw_version)
        if parsed_ver is None:
            results.append({
                "application": raw_name,
                "version": raw_version or "UNKNOWN",
                "status": "UNKNOWN",
                "reason": "Version string could not be parsed.",
                "cves": [],
            })
            continue

        rule_match = _match_software_rule(raw_name.lower())
        if rule_match is None:
            results.append({
                "application": raw_name,
                "version": raw_version,
                "status": "UNASSESSED",
                "reason": "No security rule defined for this application.",
                "cves": [],
            })
            continue

        _, rule_cfg = rule_match
        min_ver: Tuple[int, ...] = rule_cfg["min_version"]

        if parsed_ver >= min_ver:
            results.append({
                "application": raw_name,
                "version": raw_version,
                "status": "SECURE",
                "reason": f"Version {raw_version} meets minimum secure version requirement.",
                "cves": [],
            })
        else:
            # Build CPE and query NVD only for insecure software
            ver_str = ".".join(str(x) for x in parsed_ver)
            cpe = rule_cfg["cpe_template"].format(version=ver_str)
            cve_tuples = query_nvd_cpe(cpe)
            cves: List[Dict[str, Any]] = [dict(c) for c in cve_tuples if "error" not in c]

            results.append({
                "application": raw_name,
                "version": raw_version,
                "status": "INSECURE",
                "reason": rule_cfg["reason_insecure"],
                "cves": cves,
            })

    return results


# ─────────────────────────────────────────────
# RISK SCORE CALCULATOR
# ─────────────────────────────────────────────

def calculate_risk_score(
    vulnerabilities: List[Dict[str, Any]],
    software_analysis: List[Dict[str, Any]],
) -> int:
    """
    Computes a cumulative risk score from rule findings and insecure software.
    Each severity level has a pre-defined weight.
    """
    score = 0
    for vuln in vulnerabilities:
        score += SEVERITY_WEIGHTS.get(vuln.get("severity", "LOW"), 1)
    # Each insecure application adds a MEDIUM weight by default
    insecure_count = sum(1 for s in software_analysis if s.get("status") == "INSECURE")
    score += insecure_count * SEVERITY_WEIGHTS["MEDIUM"]
    return score


# ─────────────────────────────────────────────
# RESULT WRAPPER
# ─────────────────────────────────────────────

def _wrap_result(
    category: str,
    cmd: str,
    output: str,
    logic: str,
    detected_vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    risk_score: int = 0,
    software_analysis: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "category": category,
        "command": cmd,
        "command_output": str(output)[:2000] if output else "",
        "summary": f"{category} inspection completed.",
        "logic_reasoning": logic,
        "detected_vulnerabilities": detected_vulnerabilities or [],
        "risk_score": risk_score,
        "software_analysis": software_analysis or [],
    }


# ─────────────────────────────────────────────
# SCAN MODULES  (data collection only)
# ─────────────────────────────────────────────

def scan_os_profiling() -> Dict[str, Any]:
    global DETECTED_CPE
    cmd = (
        "(Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber)"
        " | ConvertTo-Json"
    )
    output = run_powershell(cmd)
    try:
        parsed: Dict[str, Any] = json.loads(output)
        product_name = str(parsed.get("WindowsProductName", ""))
        version = str(parsed.get("OsBuildNumber", parsed.get("WindowsVersion", "")))
        DETECTED_CPE = build_windows_cpe(product_name, version)
    except Exception:
        DETECTED_CPE = "cpe:2.3:o:microsoft:windows_10"

    return _wrap_result(
        "OS Profiling",
        cmd,
        output,
        "OS version/build determines kernel exploit exposure.",
    )


def scan_hotfix_audit() -> Dict[str, Any]:
    cmd = (
        'Get-HotFix; '
        '(New-Object -ComObject Microsoft.Update.Session)'
        '.CreateUpdateSearcher().Search("IsInstalled=0").Updates'
    )
    return _wrap_result(
        "Hotfix Audit",
        cmd,
        run_powershell(cmd),
        "Missing KBs correlate with Patch Tuesday RCE/LPE vulnerabilities.",
    )


def scan_software_inventory() -> Dict[str, Any]:
    cmd = (
        'Get-Package; '
        'Get-WmiObject -Class Win32_Product; '
        'Get-Service | Where-Object {$_.Name -like "Sysmon"}'
    )
    return _wrap_result(
        "Software Inventory",
        cmd,
        run_powershell(cmd),
        "Outdated or unmanaged software expands exploit surface.",
    )


def scan_service_status() -> Dict[str, Any]:
    cmd = (
        'Get-Service | Where-Object {$_.Status -eq "Running"}; '
        'Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer'
    )
    return _wrap_result(
        "Service Status",
        cmd,
        run_powershell(cmd),
        "Running services and WMI consumers are common persistence vectors.",
    )


def scan_edr_health() -> Dict[str, Any]:
    cmd = "Get-MpComputerStatus; Confirm-SecureBootUEFI"
    return _wrap_result(
        "EDR / AV Health",
        cmd,
        run_powershell(cmd),
        "Weak EDR or Secure Boot off enables BYOVD and bootkits.",
    )


def scan_audit_policy() -> Dict[str, Any]:
    cmd = "auditpol /get /category:*; Get-EventLog -List"
    return _wrap_result(
        "Audit Policy",
        cmd,
        run_powershell(cmd),
        "Low logging creates detection gaps.",
    )


def scan_firewall() -> Dict[str, Any]:
    cmd = "Get-NetFirewallRule -Enabled True | Select DisplayName,Direction,Action"
    return _wrap_result(
        "Firewall Rules",
        cmd,
        run_powershell(cmd),
        "Inbound allow rules increase attack surface.",
    )


def scan_neighbor_discovery() -> Dict[str, Any]:
    cmd = "Get-NetNeighbor; Get-NetRoute"
    return _wrap_result(
        "Neighbor Discovery",
        cmd,
        run_powershell(cmd),
        "ARP/IPv6 exposure enables MitM attacks.",
    )


def scan_interface_stats() -> Dict[str, Any]:
    cmd = "Get-NetAdapterStatistics; Get-DnsClientServerAddress"
    return _wrap_result(
        "Interface Statistics",
        cmd,
        run_powershell(cmd),
        "DNS hijacking can redirect traffic to malicious resolvers.",
    )


def scan_infrastructure_link() -> Dict[str, Any]:
    cmd = (
        "Get-ADComputer -Identity $env:COMPUTERNAME -Properties *; "
        "(Get-CimInstance Win32_BIOS).Version"
    )
    return _wrap_result(
        "Infrastructure Link",
        cmd,
        run_powershell(cmd),
        "Outdated BIOS/UEFI firmware enables bootkits.",
    )


def scan_persistence() -> Dict[str, Any]:
    cmd = (
        "Get-ScheduledTask; "
        "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    return _wrap_result(
        "Persistence Mechanisms",
        cmd,
        run_powershell(cmd),
        "Startup tasks and run keys allow malware persistence.",
    )


def scan_users() -> Dict[str, Any]:
    cmd = 'Get-LocalGroupMember -Group "Administrators"'
    return _wrap_result(
        "User / Group Audit",
        cmd,
        run_powershell(cmd),
        "Admin sprawl enables privilege escalation chaining.",
    )


def scan_connections() -> Dict[str, Any]:
    cmd = "Get-NetTCPConnection -State Listen"
    return _wrap_result(
        "Active Connections",
        cmd,
        run_powershell(cmd),
        "Unexpected listeners may indicate backdoors.",
    )


# ─────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────

def export_json(report: List[Dict[str, Any]], run_ts: str) -> str:
    path = os.path.join(OUTPUT_DIR, "scan_report.json")
    scan_entry = {
        "run_timestamp": run_ts,
        "scanner": "Agentless Windows Vulnerability Scanner",
        "results": report,
    }
    existing: List[Dict[str, Any]] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                raw = json.load(f)
                existing = raw if isinstance(raw, list) else [raw]
            except json.JSONDecodeError:
                existing = []
    existing.append(scan_entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    return path


def export_pdf(report: List[Dict[str, Any]], run_ts: str) -> str:
    """
    Renders the full scan report to PDF.

    Sections per category block:
    - Category metadata (command, summary, logic, risk score)
    - Detected Vulnerabilities  (rule-based, CONFIGURATION findings)
    - Software Analysis         (SECURE / INSECURE / UNASSESSED table)
    - NVD CVE Findings          (CVE findings from VulnerabilityCorrelator)
    """
    filename = f"scan_report_{run_ts.replace(':', '').replace('-', '')}.pdf"
    path = os.path.join(OUTPUT_DIR, filename)
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Agentless Windows Vulnerability Assessment", styles["Title"]))
    story.append(Paragraph(f"Scan Time (UTC): {run_ts}", styles["Normal"]))
    story.append(Spacer(1, 12))

    for item in report:
        # ── Category header ──────────────────────────────────────────────
        story.append(Paragraph(f"<b>Category:</b> {item['category']}", styles["Heading2"]))
        story.append(Paragraph(f"<b>Command:</b> {item['command']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Summary:</b> {item['summary']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Logic:</b> {item['logic_reasoning']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Risk Score:</b> {item['risk_score']}", styles["Normal"]))

        # ── Rule-based (CONFIGURATION) findings ──────────────────────────
        vulns = item.get("detected_vulnerabilities", [])
        if vulns:
            story.append(Paragraph("<b>Detected Vulnerabilities (Configuration):</b>", styles["Normal"]))
            for v in vulns:
                story.append(Paragraph(
                    f"&nbsp;&nbsp;[{v['severity']}] {v['title']}: {v['description']}",
                    styles["Normal"],
                ))

        # ── Software classification table ────────────────────────────────
        sw = item.get("software_analysis", [])
        if sw:
            story.append(Paragraph("<b>Software Analysis:</b>", styles["Normal"]))
            for s in sw:
                # Legacy per-app CVEs from analyze_software_security()
                cve_ids = ", ".join(c.get("cve_id", "") for c in s.get("cves", []))
                cve_line = f" | CVEs: {cve_ids}" if cve_ids else ""
                story.append(Paragraph(
                    f"&nbsp;&nbsp;{s['application']} {s['version']} → {s['status']}{cve_line}",
                    styles["Normal"],
                ))

        # ── NVD CVE findings (new, from VulnerabilityCorrelator) ─────────
        cve_findings = item.get("cve_findings", [])
        if cve_findings:
            story.append(Paragraph("<b>NVD CVE Findings:</b>", styles["Normal"]))
            for cve in cve_findings:
                score_str = f"CVSS {cve.get('cvss_score', 'N/A')}"
                product_str = (
                    f"{cve.get('affected_product', '')} {cve.get('affected_version', '')}"
                ).strip()
                story.append(Paragraph(
                    f"&nbsp;&nbsp;[{cve['severity']}] {cve['id']} ({score_str}) "
                    f"| {product_str} | {cve.get('title', '')}",
                    styles["Normal"],
                ))
                # Description on next indented line for readability
                desc = cve.get("description", "")[:300]
                if desc:
                    story.append(Paragraph(
                        f"&nbsp;&nbsp;&nbsp;&nbsp;{desc}",
                        styles["Normal"],
                    ))

        story.append(Spacer(1, 10))

    doc.build(story)
    return path


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    """
    Main scan orchestration.

    Flow:
        1. Collect raw scan data via PowerShell inspection modules
        2. Build evaluation context (keyed string outputs)
        3. Run baseline VULNERABILITY_RULES engine  → CONFIGURATION findings
        4. Run software classification engine        → SECURE/INSECURE analysis
        5. Run NVD VulnerabilityCorrelator           → CVE findings
        6. Merge all findings into report blocks
        7. Export JSON + PDF
    """
    run_ts = get_run_timestamp()

    # ── 1. Collect raw scan data (agentless PowerShell) ────────────────────
    # scan_os_profiling MUST run first to populate DETECTED_CPE global
    report: List[Dict[str, Any]] = [
        scan_os_profiling(),
        scan_hotfix_audit(),
        scan_software_inventory(),
        scan_service_status(),
        scan_edr_health(),
        scan_audit_policy(),
        scan_firewall(),
        scan_neighbor_discovery(),
        scan_interface_stats(),
        scan_infrastructure_link(),
        scan_persistence(),
        scan_users(),
        scan_connections(),
    ]

    # ── 2. Build evaluation context (maps rule data_key → raw output) ──────
    context: Dict[str, str] = {
        "hotfix_audit":    next((r["command_output"] for r in report if r["category"] == "Hotfix Audit"), ""),
        "software":        next((r["command_output"] for r in report if r["category"] == "Software Inventory"), ""),
        "service_status":  next((r["command_output"] for r in report if r["category"] == "Service Status"), ""),
        "edr_health":      next((r["command_output"] for r in report if r["category"] == "EDR / AV Health"), ""),
        "audit_policy":    next((r["command_output"] for r in report if r["category"] == "Audit Policy"), ""),
        "persistence":     next((r["command_output"] for r in report if r["category"] == "Persistence Mechanisms"), ""),
        "users":           next((r["command_output"] for r in report if r["category"] == "User / Group Audit"), ""),
        "firewall":        next((r["command_output"] for r in report if r["category"] == "Firewall Rules"), ""),
        "interface_stats": next((r["command_output"] for r in report if r["category"] == "Interface Statistics"), ""),
        "infrastructure_link": next((r["command_output"] for r in report if r["category"] == "Infrastructure Link"), ""),
    }

    # ── 3. Baseline rule engine (CONFIGURATION findings) ─────────────────
    # evaluate_rules() matches each VULNERABILITY_RULE condition against
    # the corresponding raw scan output captured in `context`.
    all_findings: List[Dict[str, Any]] = evaluate_rules(context)
    print(f"[Rule Engine] {len(all_findings)} configuration finding(s) detected.")

    # ── 4. Software classification engine ────────────────────────────────
    # analyze_software_security() labels each app SECURE/INSECURE/UNASSESSED
    # and queries NVD via the legacy CPE path for INSECURE apps.
    software_analysis: List[Dict[str, Any]] = analyze_software_security(context["software"])

    # ── 5. NVD CVE correlation engine (new) ──────────────────────────────
    # Initialise NVDClient with the optional API key from the environment.
    # If no key is present, NVDClient operates in unauthenticated mode with
    # a slightly longer rate-limit sleep (0.6 s per request).
    nvd_client = NVDClient(api_key=NVD_API_KEY)
    correlator = VulnerabilityCorrelator(client=nvd_client)

    # correlate_software() parses the raw software inventory text, queries
    # NVD per product keyword (results cached in nvd_client), and returns
    # a filtered list of HIGH/CRITICAL CVE findings for Windows 10/11.
    cve_findings: List[Dict[str, Any]] = correlator.correlate_software(
        software_output=context["software"]
    )
    print(f"[NVD Correlator] {len(cve_findings)} CVE finding(s) identified.")

    # ── 6. Calculate aggregate risk score ────────────────────────────────
    # Risk score = sum of severity weights from rule findings
    #            + MEDIUM weight per INSECURE app
    #            + HIGH weight per CVE finding
    total_risk = calculate_risk_score(all_findings, software_analysis)
    # Additional weight from CVE findings (HIGH = 7 each by default)
    total_risk += len(cve_findings) * SEVERITY_WEIGHTS["HIGH"]

    # ── 7. Map categories → data keys for associating rule findings ───────
    # Each VULNERABILITY_RULE has a data_key that maps to a scan category.
    # This dict reverses that mapping so we can attach rules to the correct
    # category block in the report.
    category_data_key_map: Dict[str, str] = {
        "Hotfix Audit":           "hotfix_audit",
        "Software Inventory":     "software",
        "Service Status":         "service_status",
        "EDR / AV Health":        "edr_health",
        "Audit Policy":           "audit_policy",
        "Persistence Mechanisms": "persistence",
        "User / Group Audit":     "users",
        "Firewall Rules":         "firewall",
        "Interface Statistics":   "interface_stats",
        "Infrastructure Link":    "infrastructure_link",
    }

    # ── 8. Attach findings to report blocks ───────────────────────────────
    for item in report:
        cat = item["category"]
        data_key = category_data_key_map.get(cat)

        # Rule-based findings for this category
        cat_findings: List[Dict[str, Any]] = (
            [
                f for f in all_findings
                if any(
                    r["data_key"] == data_key
                    for r in VULNERABILITY_RULES
                    if r["id"] == f["id"]
                )
            ]
            if data_key else []
        )
        item["detected_vulnerabilities"] = cat_findings
        item["risk_score"] = sum(
            SEVERITY_WEIGHTS.get(f["severity"], 1) for f in cat_findings
        )

        if cat == "Software Inventory":
            # Software classification table (SECURE/INSECURE/UNASSESSED)
            item["software_analysis"] = software_analysis
            item["risk_score"] += sum(
                SEVERITY_WEIGHTS["MEDIUM"]
                for s in software_analysis
                if s["status"] == "INSECURE"
            )
            # NVD CVE findings (new key — separate from detected_vulnerabilities)
            # Each entry: {id, title, severity, description, cvss_score,
            #              published, source, affected_product, affected_version}
            item["cve_findings"] = cve_findings
            item["risk_score"] += len(cve_findings) * SEVERITY_WEIGHTS["HIGH"]
        else:
            # Ensure the key is always present so downstream code doesn't KeyError
            item.setdefault("cve_findings", [])

    # Attach aggregate risk score to the OS Profiling block (summary entry)
    for item in report:
        if item["category"] == "OS Profiling":
            item["risk_score"] = total_risk
            break

    # ── 9. Export ─────────────────────────────────────────────────────────
    json_path = export_json(report, run_ts)
    pdf_path = export_pdf(report, run_ts)

    print("\n═" * 55)
    print("Scan complete.")
    print(f"  Configuration findings : {len(all_findings)}")
    print(f"  CVE findings (NVD)     : {len(cve_findings)}")
    print(f"  Aggregate risk score   : {total_risk}")
    print(f"  JSON report (appended) : {json_path}")
    print(f"  PDF report (new)       : {pdf_path}")
    print("═" * 55)


if __name__ == "__main__":
    # Enable INFO-level logging so NVD query progress is visible at runtime.
    # Operators can set NVD_API_KEY env var for higher rate limits.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    main()
