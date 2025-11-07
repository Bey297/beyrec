
import aiohttp
import asyncio
from typing import Dict, Any, List, Optional

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Basic mapping for common technologies to CPE vendor/product
# This is a simplified mapping and might need expansion for more accuracy
CPE_MAPPING = {
    "wordpress": {"vendor": "wordpress", "product": "wordpress"},
    "nginx": {"vendor": "nginx", "product": "nginx"},
    "apache": {"vendor": "apache", "product": "http_server"},
    "microsoft iis": {"vendor": "microsoft", "product": "internet_information_services"},
    "joomla": {"vendor": "joomla", "product": "joomla!"},
    "drupal": {"vendor": "drupal", "product": "drupal"},
    "php": {"vendor": "php", "product": "php"},
    "mysql": {"vendor": "mysql", "product": "mysql"},
    "postgresql": {"vendor": "postgresql", "product": "postgresql"},
    "ubuntu": {"vendor": "canonical", "product": "ubuntu_linux"},
    "debian": {"vendor": "debian", "product": "debian_linux"},
    "centos": {"vendor": "centos", "product": "centos"},
    "red hat": {"vendor": "redhat", "product": "enterprise_linux"},
    "openssl": {"vendor": "openssl", "product": "openssl"},
    "jquery": {"vendor": "jquery", "product": "jquery"},
    "bootstrap": {"vendor": "getbootstrap", "product": "bootstrap"},
    "react": {"vendor": "facebook", "product": "react"},
    "angular": {"vendor": "angularjs", "product": "angularjs"},
    "node.js": {"vendor": "nodejs", "product": "node.js"},
    "express": {"vendor": "expressjs", "product": "express"},
    "django": {"vendor": "djangoproject", "product": "django"},
    "flask": {"vendor": "pocoo", "product": "flask"},
    "ruby on rails": {"vendor": "rubyonrails", "product": "ruby_on_rails"},
    "spring framework": {"vendor": "vmware", "product": "spring_framework"},
    "tomcat": {"vendor": "apache", "product": "tomcat"},
    "jetty": {"vendor": "eclipse", "product": "jetty"},
    "jenkins": {"vendor": "jenkins", "product": "jenkins"},
    "gitlab": {"vendor": "gitlab", "product": "gitlab"},
    "docker": {"vendor": "docker", "product": "docker"},
    "kubernetes": {"vendor": "kubernetes", "product": "kubernetes"},
    "redis": {"vendor": "redis", "product": "redis"},
    "memcached": {"vendor": "memcached", "product": "memcached"},
    "elasticsearch": {"vendor": "elastic", "product": "elasticsearch"},
    "mongodb": {"vendor": "mongodb", "product": "mongodb"},
    "nginx unit": {"vendor": "nginx", "product": "nginx_unit"},
    "varnish": {"vendor": "varnish-software", "product": "varnish_cache"},
    "haproxy": {"vendor": "haproxy", "product": "haproxy"},
    "cloudflare": {"vendor": "cloudflare", "product": "cloudflare"},
    "aws": {"vendor": "amazon", "product": "amazon_web_services"},
    "google cloud": {"vendor": "google", "product": "google_cloud_platform"},
    "azure": {"vendor": "microsoft", "product": "azure"}
}

# NVD API has a rate limit of 5 requests in a 30-second window without an API key.
# We'll implement a simple delay to respect this.
LAST_API_CALL_TIME = 0
CALL_COUNT = 0
RATE_LIMIT_WINDOW = 30 # seconds
MAX_CALLS_IN_WINDOW = 5

async def _wait_for_rate_limit():
    global LAST_API_CALL_TIME, CALL_COUNT
    current_time = asyncio.get_event_loop().time()

    if current_time - LAST_API_CALL_TIME > RATE_LIMIT_WINDOW:
        CALL_COUNT = 0
        LAST_API_CALL_TIME = current_time

    if CALL_COUNT >= MAX_CALLS_IN_WINDOW:
        wait_time = RATE_LIMIT_WINDOW - (current_time - LAST_API_CALL_TIME)
        if wait_time > 0:
            print(f"[*] Batas laju NVD API tercapai. Menunggu {wait_time:.2f} detik...")
            await asyncio.sleep(wait_time)
        CALL_COUNT = 0
        LAST_API_CALL_TIME = asyncio.get_event_loop().time()

    CALL_COUNT += 1

async def analyze(session: aiohttp.ClientSession, tech_name: str, tech_version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Queries NVD API for CVEs related to a given technology and version."""
    cve_findings = []
    tech_name_lower = tech_name.lower()

    if tech_name_lower not in CPE_MAPPING:
        # print(f"[-] Tidak ada pemetaan CPE untuk teknologi: {tech_name}")
        return []

    vendor = CPE_MAPPING[tech_name_lower]["vendor"]
    product = CPE_MAPPING[tech_name_lower]["product"]

    # Construct CPE string for NVD API query
    # Example: cpe:/a:apache:http_server:2.4.50
    cpe_string = f"cpe:/a:{vendor}:{product}"
    if tech_version:
        # NVD API expects version to be part of the CPE string for filtering
        # However, direct version matching in CPE is tricky due to different versioning schemes.
        # A simpler approach for NVD API is to search by cpeName and then filter results.
        # For now, we'll just search by vendor and product and let NVD filter.
        # A more precise CPE string would be cpe:/a:{vendor}:{product}:{tech_version}
        # But NVD API's cpeName parameter often works better with just vendor:product
        # and then filtering by version in the results if needed.
        # Let's try to include version in cpeName for more specific search if possible.
        cpe_string_with_version = f"{cpe_string}:{tech_version}"
    else:
        cpe_string_with_version = cpe_string

    params = {
        "cpeName": cpe_string_with_version,
        "resultsPerPage": 10 # Limit results to avoid large responses
    }

    try:
        await _wait_for_rate_limit()
        async with session.get(NVD_API_BASE_URL, params=params) as response:
            response.raise_for_status() # Raise an exception for HTTP errors
            data = await response.json()

            if "vulnerabilities" in data:
                for vuln_entry in data["vulnerabilities"]:
                    cve = vuln_entry["cve"]
                    cve_id = cve["id"]
                    description = "Tidak ada deskripsi tersedia."
                    if "descriptions" in cve:
                        for desc in cve["descriptions"]:
                            if desc["lang"] == "en": # Prefer English description
                                description = desc["value"]
                                break
                    
                    severity = "Tidak Diketahui"
                    # NVD API v2.0 has CVSS metrics under metrics field
                    if "metrics" in cve and "cvssMetricV31" in cve["metrics"] and cve["metrics"]["cvssMetricV31"]:
                        severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                    elif "metrics" in cve and "cvssMetricV2" in cve["metrics"] and cve["metrics"]["cvssMetricV2"]:
                        severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]

                    # Filter by version if tech_version is provided and NVD didn't filter perfectly
                    # This manual filtering is a fallback if CPE matching isn't precise enough
                    affected_versions = []
                    if "configurations" in cve and cve["configurations"]:
                        for conf in cve["configurations"]:
                            if "nodes" in conf:
                                for node in conf["nodes"]:
                                    if "cpeMatch" in node:
                                        for cpe_match in node["cpeMatch"]:
                                            if "criteria" in cpe_match:
                                                affected_versions.append(cpe_match["criteria"])
                    
                    # Simple version check (can be improved)
                    version_match_found = False
                    if tech_version:
                        for affected_cpe in affected_versions:
                            if tech_version in affected_cpe: # Basic substring match
                                version_match_found = True
                                break
                        if not version_match_found and affected_versions: # If no match and affected versions exist, skip this CVE
                            continue

                    cve_findings.append({
                        "cve_id": cve_id,
                        "description": description,
                        "severity": severity,
                        "affected_versions_cpe": affected_versions, # Keep full CPE for detail
                        "source": "NVD API"
                    })
            
            # print(f"[+] Ditemukan {len(cve_findings)} CVE untuk {tech_name} {tech_version or ''}")

    except aiohttp.ClientResponseError as e:
        print(f"[-] NVD API Client Error untuk {tech_name} {tech_version or ''}: {e.status} - {e.message}")
    except aiohttp.ClientError as e:
        print(f"[-] NVD API Network Error untuk {tech_name} {tech_version or ''}: {e}")
    except json.JSONDecodeError:
        print(f"[-] Gagal mendekode respons JSON dari NVD API untuk {tech_name} {tech_version or ''}")
    except Exception as e:
        print(f"[-] Terjadi kesalahan tak terduga saat memanggil NVD API untuk {tech_name} {tech_version or ''}: {e}")

    return cve_findings
