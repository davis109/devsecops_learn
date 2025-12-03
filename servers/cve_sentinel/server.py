"""
CVE Sentinel MCP Server - The Eyes
Monitors vulnerability databases and analyzes CVE reports
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel

from helios.mcp_protocol import (
    MCPServer,
    MCPServerInfo,
    MCPToolParameter,
)
from helios.logging_config import get_logger

logger = get_logger(__name__)


class CVEDetails(BaseModel):
    """CVE vulnerability details"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: datetime
    affected_products: List[str]
    remediation_summary: Optional[str] = None
    references: List[str]


class CVESentinelServer(MCPServer):
    """MCP Server for CVE monitoring and analysis"""
    
    def __init__(self, nvd_api_key: Optional[str] = None, github_token: Optional[str] = None):
        server_info = MCPServerInfo(
            name="CVE Sentinel",
            version="1.0.0",
            description="Monitors vulnerability databases and analyzes CVE reports",
            capabilities=["cve_monitoring", "vulnerability_analysis", "remediation_extraction"]
        )
        super().__init__(server_info)
        
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.github_advisories_url = "https://api.github.com/advisories"
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all CVE Sentinel tools"""
        
        # Tool 1: Get new critical vulnerabilities
        self.tool_registry.register_tool(
            name="tools.cve.get_new_critical_vulnerabilities",
            description="Fetches new critical vulnerabilities from NVD and GitHub Advisories",
            parameters=[
                MCPToolParameter(
                    name="since_timestamp",
                    type="string",
                    description="ISO format timestamp to fetch CVEs from (e.g., '2024-01-01T00:00:00Z')",
                    required=False
                ),
                MCPToolParameter(
                    name="severity_threshold",
                    type="string",
                    description="Minimum severity level (LOW, MEDIUM, HIGH, CRITICAL)",
                    required=False,
                    default="HIGH"
                ),
                MCPToolParameter(
                    name="limit",
                    type="integer",
                    description="Maximum number of CVEs to return",
                    required=False,
                    default=50
                )
            ],
            handler=self.get_new_critical_vulnerabilities,
            category="monitoring"
        )
        
        # Tool 2: Analyze vulnerability report
        self.tool_registry.register_tool(
            name="tools.cve.analyze_vulnerability_report",
            description="Analyzes a CVE report and extracts remediation strategy using LLM",
            parameters=[
                MCPToolParameter(
                    name="cve_id",
                    type="string",
                    description="CVE identifier (e.g., 'CVE-2024-1234')",
                    required=True
                )
            ],
            handler=self.analyze_vulnerability_report,
            category="analysis"
        )
        
        # Tool 3: Search CVEs by package
        self.tool_registry.register_tool(
            name="tools.cve.search_by_package",
            description="Search for CVEs affecting a specific package or product",
            parameters=[
                MCPToolParameter(
                    name="package_name",
                    type="string",
                    description="Package or product name to search for",
                    required=True
                ),
                MCPToolParameter(
                    name="severity_threshold",
                    type="string",
                    description="Minimum severity level",
                    required=False,
                    default="MEDIUM"
                )
            ],
            handler=self.search_cves_by_package,
            category="search"
        )
    
    async def get_new_critical_vulnerabilities(
        self,
        since_timestamp: Optional[str] = None,
        severity_threshold: str = "HIGH",
        limit: int = 50
    ) -> Dict[str, Any]:
        """Fetch new critical vulnerabilities from NVD"""
        logger.info(f"Fetching vulnerabilities since {since_timestamp}")
        
        try:
            # Default to last 7 days if no timestamp provided
            if not since_timestamp:
                since_date = datetime.utcnow() - timedelta(days=7)
                since_timestamp = since_date.isoformat() + "Z"
            
            vulnerabilities = []
            
            # Fetch from NVD
            nvd_cves = await self._fetch_from_nvd(since_timestamp, severity_threshold, limit)
            vulnerabilities.extend(nvd_cves)
            
            # Fetch from GitHub Advisories
            github_cves = await self._fetch_from_github_advisories(since_timestamp, severity_threshold)
            vulnerabilities.extend(github_cves)
            
            # Deduplicate by CVE ID
            unique_cves = {}
            for cve in vulnerabilities:
                if cve["cve_id"] not in unique_cves:
                    unique_cves[cve["cve_id"]] = cve
            
            result = list(unique_cves.values())[:limit]
            
            logger.info(f"Found {len(result)} unique vulnerabilities")
            return {
                "count": len(result),
                "vulnerabilities": result,
                "fetched_at": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {e}", exc_info=True)
            raise
    
    async def _fetch_from_nvd(
        self,
        since_timestamp: str,
        severity_threshold: str,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from NIST NVD"""
        
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        
        params = {
            "pubStartDate": since_timestamp,
            "resultsPerPage": min(limit, 2000)  # NVD max is 2000
        }
        
        severity_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 0.1
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self.nvd_base_url,
                    params=params,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                
                vulnerabilities = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    
                    # Extract CVSS score
                    metrics = cve.get("metrics", {})
                    cvss_score = 0.0
                    
                    # Try CVSS v3.1 first, then v3.0, then v2.0
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version in metrics and metrics[version]:
                            cvss_data = metrics[version][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            break
                    
                    # Filter by severity threshold
                    if cvss_score < severity_map.get(severity_threshold, 0.0):
                        continue
                    
                    # Determine severity
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    
                    # Extract description
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d.get("value") for d in descriptions if d.get("lang") == "en"),
                        "No description available"
                    )
                    
                    # Extract references
                    references = [
                        ref.get("url") for ref in cve.get("references", [])
                    ]
                    
                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "published_date": cve.get("published"),
                        "affected_products": [],  # Would need CPE parsing
                        "references": references,
                        "source": "NVD"
                    })
                
                return vulnerabilities
            
            except httpx.HTTPError as e:
                logger.warning(f"Failed to fetch from NVD: {e}")
                return []
    
    async def _fetch_from_github_advisories(
        self,
        since_timestamp: str,
        severity_threshold: str
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from GitHub Security Advisories"""
        
        if not self.github_token:
            logger.info("GitHub token not provided, skipping GitHub Advisories")
            return []
        
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json"
        }
        
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_severity_index = severity_order.index(severity_threshold)
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    self.github_advisories_url,
                    headers=headers,
                    params={"per_page": 100, "sort": "published", "direction": "desc"},
                    timeout=30.0
                )
                response.raise_for_status()
                advisories = response.json()
                
                vulnerabilities = []
                for advisory in advisories:
                    # Filter by date
                    published = datetime.fromisoformat(
                        advisory["published_at"].replace("Z", "+00:00")
                    )
                    since_date = datetime.fromisoformat(
                        since_timestamp.replace("Z", "+00:00")
                    )
                    if published < since_date:
                        continue
                    
                    # Filter by severity
                    severity = advisory.get("severity", "LOW").upper()
                    if severity_order.index(severity) < min_severity_index:
                        continue
                    
                    # Map CVSS score
                    cvss_score = {
                        "CRITICAL": 9.5,
                        "HIGH": 8.0,
                        "MEDIUM": 5.0,
                        "LOW": 2.0
                    }.get(severity, 0.0)
                    
                    vulnerabilities.append({
                        "cve_id": advisory.get("cve_id") or advisory["ghsa_id"],
                        "description": advisory.get("summary", ""),
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "published_date": advisory["published_at"],
                        "affected_products": [
                            vuln.get("package", {}).get("name")
                            for vuln in advisory.get("vulnerabilities", [])
                        ],
                        "references": [advisory.get("html_url")],
                        "source": "GitHub"
                    })
                
                return vulnerabilities
            
            except httpx.HTTPError as e:
                logger.warning(f"Failed to fetch from GitHub Advisories: {e}")
                return []
    
    async def analyze_vulnerability_report(self, cve_id: str) -> Dict[str, Any]:
        """Analyze a CVE report and extract remediation strategy"""
        logger.info(f"Analyzing CVE: {cve_id}")
        
        try:
            # Fetch the full CVE details
            vulnerabilities = await self.get_new_critical_vulnerabilities(limit=1)
            
            # Search for the specific CVE
            cve_data = None
            async with httpx.AsyncClient() as client:
                # Try NVD first
                response = await client.get(
                    f"{self.nvd_base_url}",
                    params={"cveId": cve_id},
                    timeout=30.0
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("vulnerabilities"):
                        cve_item = data["vulnerabilities"][0]["cve"]
                        
                        descriptions = cve_item.get("descriptions", [])
                        description = next(
                            (d.get("value") for d in descriptions if d.get("lang") == "en"),
                            "No description available"
                        )
                        
                        # Extract remediation hints from description
                        remediation_summary = self._extract_remediation_hints(description)
                        
                        cve_data = {
                            "cve_id": cve_id,
                            "description": description,
                            "remediation_summary": remediation_summary,
                            "analysis_timestamp": datetime.utcnow().isoformat()
                        }
            
            if not cve_data:
                return {
                    "error": f"CVE {cve_id} not found",
                    "cve_id": cve_id
                }
            
            return cve_data
        
        except Exception as e:
            logger.error(f"Error analyzing CVE {cve_id}: {e}", exc_info=True)
            raise
    
    def _extract_remediation_hints(self, description: str) -> str:
        """Extract remediation hints from CVE description"""
        # Simple keyword-based extraction (in production, use LLM)
        keywords = ["upgrade", "update", "patch", "version", "fix"]
        sentences = description.split(".")
        
        remediation_sentences = []
        for sentence in sentences:
            if any(keyword in sentence.lower() for keyword in keywords):
                remediation_sentences.append(sentence.strip())
        
        if remediation_sentences:
            return ". ".join(remediation_sentences) + "."
        
        return "Please refer to the CVE references for remediation details."
    
    async def search_cves_by_package(
        self,
        package_name: str,
        severity_threshold: str = "MEDIUM"
    ) -> Dict[str, Any]:
        """Search for CVEs affecting a specific package"""
        logger.info(f"Searching CVEs for package: {package_name}")
        
        try:
            # Use GitHub Advisories for package-specific search
            if not self.github_token:
                return {
                    "error": "GitHub token required for package search",
                    "package_name": package_name
                }
            
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github+json"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.github_advisories_url,
                    headers=headers,
                    params={
                        "per_page": 100,
                        "affects": package_name
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                advisories = response.json()
                
                matching_cves = []
                for advisory in advisories:
                    severity = advisory.get("severity", "LOW").upper()
                    
                    matching_cves.append({
                        "cve_id": advisory.get("cve_id") or advisory["ghsa_id"],
                        "summary": advisory.get("summary"),
                        "severity": severity,
                        "published_at": advisory["published_at"],
                        "url": advisory.get("html_url")
                    })
                
                return {
                    "package_name": package_name,
                    "count": len(matching_cves),
                    "vulnerabilities": matching_cves
                }
        
        except Exception as e:
            logger.error(f"Error searching CVEs for {package_name}: {e}", exc_info=True)
            raise
