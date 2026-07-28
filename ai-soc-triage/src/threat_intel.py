"""Automated Threat Intelligence enrichment for SOC phishing analysis.

Integrates with:
- VirusTotal API (domains, URLs, IPs, file hashes)
- Whois lookup (domain registration info)
- URLVoid/URLInfo (URL reputation)
- AbuseIPDB (IP reputation)
- Shodan (IP/port enumeration)

All results are cached and returned in a structured format for the AI analyst.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────
# Configuration from environment variables
# ─────────────────────────────────────────────────────────────

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")  # Optional: whoisxmlapi.com
URLVOID_API_KEY = os.getenv("URLVOID_API_KEY", "")    # Optional: urlvoid.com

# Rate limiting (requests per minute)
VT_RATE_LIMIT = 4
ABUSEIPDB_RATE_LIMIT = 10
SHODAN_RATE_LIMIT = 10

# Cache TTL (seconds)
CACHE_TTL = 3600  # 1 hour


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────

@dataclass
class VTReport:
    """VirusTotal analysis result."""
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    total_engines: int = 0
    reputation: str = "unknown"
    categories: list[str] = field(default_factory=list)
    last_analysis_date: str = ""
    permalink: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class WhoisInfo:
    """Domain registration information."""
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    age_days: int = 0
    registrant_country: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    is_new_domain: bool = False
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AbuseIPDBReport:
    """AbuseIPDB IP reputation report."""
    ip: str = ""
    abuse_score: int = 0
    total_reports: int = 0
    last_reported: str = ""
    confidence: str = ""
    usage_type: str = ""
    country_code: str = ""
    isp: str = ""
    domain: str = ""
    reports: list[dict[str, Any]] = field(default_factory=list)
    is_whitelisted: bool = False


@dataclass
class ShodanInfo:
    """Shodan IP/host information."""
    ip: str = ""
    open_ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    organization: str = ""
    os: str = ""
    country: str = ""
    city: str = ""
    vulns: list[str] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ThreatIntelResult:
    """Aggregated threat intelligence for an IOC."""
    ioc_type: str  # ip, domain, url, email, hash
    ioc_value: str
    virus_total: VTReport | None = None
    whois: WhoisInfo | None = None
    abuse_ipdb: AbuseIPDBReport | None = None
    shodan: ShodanInfo | None = None
    risk_score: int = 0  # 0-100
    risk_label: str = "unknown"
    recommendations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Simple in-memory cache
# ─────────────────────────────────────────────────────────────

_cache: dict[str, tuple[Any, float]] = {}


def _cache_get(key: str) -> Any | None:
    """Get cached value if not expired."""
    if key in _cache:
        value, timestamp = _cache[key]
        if time.time() - timestamp < CACHE_TTL:
            return value
        del _cache[key]
    return None


def _cache_set(key: str, value: Any) -> None:
    """Set cache value with timestamp."""
    _cache[key] = (value, time.time())


# ─────────────────────────────────────────────────────────────
# VirusTotal API
# ─────────────────────────────────────────────────────────────

def _vt_get_headers() -> dict[str, str]:
    return {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}


def vt_analyze_domain(domain: str) -> VTReport | None:
    """Analyze a domain using VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    cache_key = f"vt_domain:{domain}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=_vt_get_headers(), timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            
            report = VTReport(
                malicious=last_analysis.get("malicious", 0),
                suspicious=last_analysis.get("suspicious", 0),
                clean=last_analysis.get("harmless", 0),
                total_engines=sum(last_analysis.values()),
                last_analysis_date=datetime.fromtimestamp(attrs.get("last_analysis_date", 0)).isoformat() if attrs.get("last_analysis_date") else "",
                categories=attrs.get("categories", []),
                permalink=f"https://www.virustotal.com/gui/domain/{domain}",
                raw_data=data
            )
            
            # Calculate reputation
            if report.malicious >= 5:
                report.reputation = "malicious"
            elif report.malicious >= 1 or report.suspicious >= 3:
                report.reputation = "suspicious"
            elif report.clean > 10:
                report.reputation = "clean"
            
            _cache_set(cache_key, report)
            return report
        elif response.status_code == 404:
            # Domain not found in VT - create empty report
            report = VTReport(reputation="unknown")
            _cache_set(cache_key, report)
            return report
            
    except requests.RequestException as e:
        pass
    
    return None


def vt_analyze_url(url: str) -> VTReport | None:
    """Analyze a URL using VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    cache_key = f"vt_url:{url}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        # First submit the URL for analysis
        submit_url = "https://www.virustotal.com/api/v3/urls"
        url_id = hashlib.sha256(url.encode()).hexdigest()[:64]
        
        # Get existing analysis
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        response = requests.get(analysis_url, headers=_vt_get_headers(), timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            
            report = VTReport(
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                clean=stats.get("harmless", 0),
                total_engines=sum(stats.values()),
                permalink=f"https://www.virustotal.com/gui/url/{url_id}",
                raw_data=data
            )
            
            if report.malicious >= 3:
                report.reputation = "malicious"
            elif report.malicious >= 1:
                report.reputation = "suspicious"
            elif report.clean > 5:
                report.reputation = "clean"
            
            _cache_set(cache_key, report)
            return report
            
    except requests.RequestException:
        pass
    
    return None


def vt_analyze_ip(ip: str) -> VTReport | None:
    """Analyze an IP address using VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    cache_key = f"vt_ip:{ip}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=_vt_get_headers(), timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            
            report = VTReport(
                malicious=last_analysis.get("malicious", 0),
                suspicious=last_analysis.get("suspicious", 0),
                clean=last_analysis.get("harmless", 0),
                total_engines=sum(last_analysis.values()),
                last_analysis_date=datetime.fromtimestamp(attrs.get("last_analysis_date", 0)).isoformat() if attrs.get("last_analysis_date") else "",
                permalink=f"https://www.virustotal.com/gui/ip-address/{ip}",
                raw_data=data
            )
            
            if report.malicious >= 3:
                report.reputation = "malicious"
            elif report.malicious >= 1:
                report.reputation = "suspicious"
            elif report.clean > 5:
                report.reputation = "clean"
            
            _cache_set(cache_key, report)
            return report
            
    except requests.RequestException:
        pass
    
    return None


def vt_analyze_file_hash(file_hash: str) -> VTReport | None:
    """Analyze a file hash (MD5/SHA1/SHA256) using VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    cache_key = f"vt_hash:{file_hash}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=_vt_get_headers(), timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            
            report = VTReport(
                malicious=last_analysis.get("malicious", 0),
                suspicious=last_analysis.get("suspicious", 0),
                clean=last_analysis.get("undetected", 0),
                total_engines=sum(last_analysis.values()),
                last_analysis_date=datetime.fromtimestamp(attrs.get("last_analysis_date", 0)).isoformat() if attrs.get("last_analysis_date") else "",
                permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
                raw_data=data
            )
            
            if report.malicious >= 5:
                report.reputation = "malicious"
            elif report.malicious >= 1:
                report.reputation = "suspicious"
            elif report.clean > 10:
                report.reputation = "clean"
            
            _cache_set(cache_key, report)
            return report
            
    except requests.RequestException:
        pass
    
    return None


# ─────────────────────────────────────────────────────────────
# Whois Lookup
# ─────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> WhoisInfo | None:
    """Perform Whois lookup for domain registration info."""
    cache_key = f"whois:{domain}"
    if cached := _cache_get(cache_key):
        return cached
    
    # Try WhoisXML API first if key is available
    if WHOISXML_API_KEY:
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&apiKey={WHOISXML_API_KEY}&outputFormat=JSON"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                whois_data = data.get("WhoisRecord", {})
                
                registry_dates = whois_data.get("registryData", {})
                created = registry_dates.get("createdDate", "")
                expires = registry_dates.get("expiresDate", "")
                updated = registry_dates.get("updatedDate", "")
                
                # Calculate domain age
                age_days = 0
                if created:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                    except Exception:
                        pass
                
                info = WhoisInfo(
                    domain=domain,
                    registrar=whois_data.get("registrarName", ""),
                    creation_date=created,
                    expiration_date=expires,
                    updated_date=updated,
                    age_days=age_days,
                    registrant_country=whois_data.get("registrant", {}).get("country", ""),
                    name_servers=whois_data.get("nameServers", {}).get("hostNames", []),
                    status=whois_data.get("status", ""),
                    is_new_domain=age_days < 30,
                    raw_data=data
                )
                
                _cache_set(cache_key, info)
                return info
                
        except requests.RequestException:
            pass
    
    # Fallback: simple whois command (Linux/Mac)
    try:
        import subprocess
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            info = WhoisInfo(domain=domain, raw_data={"raw_whois": result.stdout})
            
            # Parse common fields
            for line in result.stdout.split("\n"):
                line_lower = line.lower()
                if "registrar:" in line_lower:
                    info.registrar = line.split(":", 1)[1].strip()
                elif "creation date:" in line_lower or "created:" in line_lower:
                    info.creation_date = line.split(":", 1)[1].strip()
                elif "expiry date:" in line_lower or "expires:" in line_lower:
                    info.expiration_date = line.split(":", 1)[1].strip()
            
            # Check if new domain (< 30 days)
            if info.creation_date:
                try:
                    created_dt = datetime.strptime(info.creation_date[:10], "%Y-%m-%d")
                    info.age_days = (datetime.now() - created_dt).days
                    info.is_new_domain = info.age_days < 30
                except Exception:
                    pass
            
            _cache_set(cache_key, info)
            return info
            
    except Exception:
        pass
    
    return None


# ─────────────────────────────────────────────────────────────
# AbuseIPDB
# ─────────────────────────────────────────────────────────────

def abuseipdb_check(ip: str) -> AbuseIPDBReport | None:
    """Check IP reputation using AbuseIPDB API."""
    if not ABUSEIPDB_API_KEY:
        return None
    
    cache_key = f"abuseipdb:{ip}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get("data", {})
            
            report = AbuseIPDBReport(
                ip=ip,
                abuse_score=ip_data.get("abuseConfidenceScore", 0),
                total_reports=ip_data.get("totalReports", 0),
                last_reported=ip_data.get("lastReportedAt", ""),
                confidence="high" if ip_data.get("abuseConfidenceScore", 0) > 75 else "medium" if ip_data.get("abuseConfidenceScore", 0) > 25 else "low",
                usage_type=ip_data.get("usageType", ""),
                country_code=ip_data.get("countryCode", ""),
                isp=ip_data.get("isp", ""),
                domain=ip_data.get("domain", ""),
                is_whitelisted=ip_data.get("isWhitelisted", False),
                reports=ip_data.get("reports", [])[:5],  # Last 5 reports
                raw_data=data
            )
            
            _cache_set(cache_key, report)
            return report
            
    except requests.RequestException:
        pass
    
    return None


# ─────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────

def shodan_ip_lookup(ip: str) -> ShodanInfo | None:
    """Lookup IP information using Shodan API."""
    if not SHODAN_API_KEY:
        return None
    
    cache_key = f"shodan:{ip}"
    if cached := _cache_get(cache_key):
        return cached
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            info = ShodanInfo(
                ip=ip,
                open_ports=data.get("ports", []),
                hostnames=data.get("hostnames", []),
                organization=data.get("org", ""),
                os=data.get("os", ""),
                country=data.get("country_name", ""),
                city=data.get("city", ""),
                vulns=data.get("vulns", []),
                services=[{"port": s.get("port"), "service": s.get("product"), "version": s.get("version")} 
                         for s in data.get("data", [])[:10]],
                raw_data=data
            )
            
            _cache_set(cache_key, info)
            return info
            
    except requests.RequestException:
        pass
    
    return None


# ─────────────────────────────────────────────────────────────
# Main enrichment function
# ─────────────────────────────────────────────────────────────

def extract_iocs_from_email(email_data: dict[str, Any]) -> dict[str, list[str]]:
    """Extract IOCs from parsed email data."""
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "hashes": []
    }
    
    # Extract origin IP
    if origin_ip := email_data.get("originIP"):
        iocs["ips"].append(origin_ip)
    
    # Extract sender/reply-to domains
    for field in ["from", "replyTo", "to"]:
        if email := email_data.get(field, ""):
            iocs["emails"].append(email)
            if "@" in email:
                domain = email.split("@")[-1]
                if domain not in iocs["domains"]:
                    iocs["domains"].append(domain)
    
    # Extract URLs and their domains
    urls = email_data.get("urls", [])
    for url_item in urls:
        url_str = url_item.get("url", "") if isinstance(url_item, dict) else str(url_item)
        if url_str:
            iocs["urls"].append(url_str)
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_str)
                if parsed.netloc:
                    domain = parsed.netloc.split(":")[0]
                    if domain not in iocs["domains"]:
                        iocs["domains"].append(domain)
            except Exception:
                pass
    
    # Extract attachment hashes
    attachments = email_data.get("attachments", [])
    for att in attachments:
        if isinstance(att, dict):
            if sha256 := att.get("sha256"):
                iocs["hashes"].append(sha256)
            elif md5 := att.get("md5"):
                iocs["hashes"].append(md5)
    
    return iocs


def enrich_iocs(iocs: dict[str, list[str]]) -> list[ThreatIntelResult]:
    """Enrich all IOCs with threat intelligence data."""
    results = []
    
    # Enrich IPs
    for ip in iocs.get("ips", []):
        result = ThreatIntelResult(ioc_type="ip", ioc_value=ip)
        
        # VirusTotal
        if vt_report := vt_analyze_ip(ip):
            result.virus_total = vt_report
        
        # AbuseIPDB
        if abuse_report := abuseipdb_check(ip):
            result.abuse_ipdb = abuse_report
        
        # Shodan
        if shodan_info := shodan_ip_lookup(ip):
            result.shodan = shodan_info
        
        # Calculate risk score
        risk = 0
        recommendations = []
        
        if result.virus_total and result.virus_total.reputation == "malicious":
            risk += 40
            recommendations.append(f"Block IP {ip} at firewall - flagged malicious by VT")
        elif result.virus_total and result.virus_total.reputation == "suspicious":
            risk += 20
            recommendations.append(f"Monitor traffic from {ip} - suspicious VT reputation")
        
        if result.abuse_ipdb and result.abuse_ipdb.abuse_score > 75:
            risk += 35
            recommendations.append(f"High abuse score ({result.abuse_ipdb.abuse_score}%) - consider blocking")
        elif result.abuse_ipdb and result.abuse_ipdb.abuse_score > 25:
            risk += 15
        
        if result.shodan and result.shodan.vulns:
            risk += 15
            recommendations.append(f"IP has known vulnerabilities: {', '.join(result.shodan.vulns[:3])}")
        
        if result.shodan and len(result.shodan.open_ports) > 10:
            risk += 5
            recommendations.append(f"Multiple open ports detected ({len(result.shodan.open_ports)})")
        
        result.risk_score = min(risk, 100)
        result.risk_label = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low"
        result.recommendations = recommendations
        
        results.append(result)
    
    # Enrich Domains
    for domain in iocs.get("domains", []):
        result = ThreatIntelResult(ioc_type="domain", ioc_value=domain)
        
        # VirusTotal
        if vt_report := vt_analyze_domain(domain):
            result.virus_total = vt_report
        
        # Whois
        if whois_info := whois_lookup(domain):
            result.whois = whois_info
        
        # Calculate risk score
        risk = 0
        recommendations = []
        
        if result.virus_total and result.virus_total.reputation == "malicious":
            risk += 50
            recommendations.append(f"Block domain {domain} - flagged malicious by VT ({result.virus_total.malicious}/{result.virus_total.total_engines} engines)")
        elif result.virus_total and result.virus_total.reputation == "suspicious":
            risk += 25
            recommendations.append(f"Investigate domain {domain} - suspicious VT reputation")
        
        if result.whois and result.whois.is_new_domain:
            risk += 20
            recommendations.append(f"Newly registered domain ({result.whois.age_days} days old) - common in phishing")
        
        if result.whois and result.whois.registrar and "privacy" in result.whois.registrar.lower():
            risk += 10
            recommendations.append("Domain uses privacy protection - harder to trace owner")
        
        result.risk_score = min(risk, 100)
        result.risk_label = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low"
        result.recommendations = recommendations
        
        results.append(result)
    
    # Enrich URLs
    for url in iocs.get("urls", []):
        result = ThreatIntelResult(ioc_type="url", ioc_value=url)
        
        # VirusTotal
        if vt_report := vt_analyze_url(url):
            result.virus_total = vt_report
        
        # Calculate risk score
        risk = 0
        recommendations = []
        
        if result.virus_total and result.virus_total.reputation == "malicious":
            risk += 60
            recommendations.append(f"Block URL immediately - confirmed malicious by VT")
        elif result.virus_total and result.virus_total.reputation == "suspicious":
            risk += 30
            recommendations.append(f"Suspicious URL - verify before allowing access")
        
        # Check for suspicious patterns
        suspicious_patterns = ["login", "verify", "account", "secure", "update", "bit.ly", "tinyurl"]
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            risk += 15
            recommendations.append("URL contains phishing-related keywords")
        
        result.risk_score = min(risk, 100)
        result.risk_label = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low"
        result.recommendations = recommendations
        
        results.append(result)
    
    # Enrich File Hashes
    for file_hash in iocs.get("hashes", []):
        result = ThreatIntelResult(ioc_type="hash", ioc_value=file_hash)
        
        # VirusTotal
        if vt_report := vt_analyze_file_hash(file_hash):
            result.virus_total = vt_report
        
        # Calculate risk score
        risk = 0
        recommendations = []
        
        if result.virus_total and result.virus_total.reputation == "malicious":
            risk += 70
            recommendations.append(f"Quarantine/delete file - confirmed malware by VT ({result.virus_total.malicious}/{result.virus_total.total_engines} engines)")
        elif result.virus_total and result.virus_total.reputation == "suspicious":
            risk += 35
            recommendations.append(f"Submit file for sandbox analysis - suspicious hash")
        
        result.risk_score = min(risk, 100)
        result.risk_label = "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low"
        result.recommendations = recommendations
        
        results.append(result)
    
    return results


def enrich_email_threat_intel(email_data: dict[str, Any]) -> dict[str, Any]:
    """Main function to enrich email with automated threat intelligence.
    
    Returns a structured dict with all IOC enrichment results.
    """
    # Extract IOCs
    iocs = extract_iocs_from_email(email_data)
    
    # Enrich all IOCs
    enriched_iocs = enrich_iocs(iocs)
    
    # Build summary
    critical_count = sum(1 for r in enriched_iocs if r.risk_label == "critical")
    high_count = sum(1 for r in enriched_iocs if r.risk_label == "high")
    medium_count = sum(1 for r in enriched_iocs if r.risk_label == "medium")
    
    overall_risk = "critical" if critical_count > 0 else "high" if high_count > 0 else "medium" if medium_count > 0 else "low"
    
    # Collect all recommendations
    all_recommendations = []
    for result in enriched_iocs:
        all_recommendations.extend(result.recommendations)
    
    # Format results for frontend/AI consumption
    return {
        "summary": {
            "overall_risk": overall_risk,
            "critical_iocs": critical_count,
            "high_risk_iocs": high_count,
            "medium_risk_iocs": medium_count,
            "total_iocs_enriched": len(enriched_iocs),
            "recommendations": list(set(all_recommendations))[:10]  # Dedupe, limit to 10
        },
        "iocs": [
            {
                "type": r.ioc_type,
                "value": r.ioc_value,
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "virus_total": {
                    "reputation": r.virus_total.reputation if r.virus_total else None,
                    "malicious": r.virus_total.malicious if r.virus_total else 0,
                    "suspicious": r.virus_total.suspicious if r.virus_total else 0,
                    "permalink": r.virus_total.permalink if r.virus_total else None
                } if r.virus_total else None,
                "whois": {
                    "age_days": r.whois.age_days if r.whois else 0,
                    "is_new_domain": r.whois.is_new_domain if r.whois else False,
                    "registrar": r.whois.registrar if r.whois else "",
                    "creation_date": r.whois.creation_date if r.whois else ""
                } if r.whois else None,
                "abuse_ipdb": {
                    "abuse_score": r.abuse_ipdb.abuse_score if r.abuse_ipdb else 0,
                    "total_reports": r.abuse_ipdb.total_reports if r.abuse_ipdb else 0,
                    "confidence": r.abuse_ipdb.confidence if r.abuse_ipdb else ""
                } if r.abuse_ipdb else None,
                "shodan": {
                    "open_ports": r.shodan.open_ports if r.shodan else [],
                    "vulns": r.shodan.vulns if r.shodan else [],
                    "organization": r.shodan.organization if r.shodan else ""
                } if r.shodan else None,
                "recommendations": r.recommendations
            }
            for r in enriched_iocs
        ],
        "raw_results": {
            "ips_checked": iocs["ips"],
            "domains_checked": iocs["domains"],
            "urls_checked": iocs["urls"],
            "hashes_checked": iocs["hashes"]
        }
    }


if __name__ == "__main__":
    # Test example
    test_email = {
        "originIP": "185.220.101.1",
        "from": "support@microsft-login.com",
        "replyTo": "attacker@protonmail.com",
        "urls": [
            {"url": "https://microsft-login.com/verify/account", "risk": "Suspicious"},
            {"url": "https://bit.ly/3xyz123", "risk": "External"}
        ],
        "attachments": [
            {"filename": "invoice.pdf.exe", "sha256": "a1b2c3d4e5f6...", "riskLevel": "CRITICAL"}
        ]
    }
    
    result = enrich_email_threat_intel(test_email)
    import json
    print(json.dumps(result, indent=2))
