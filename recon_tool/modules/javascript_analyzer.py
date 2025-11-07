
import re
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Dict, Any, List, Optional

async def analyze(response_text: str, session: aiohttp.ClientSession, base_url: str) -> Dict[str, Any]:
    """Extracts and analyzes JavaScript content for endpoints, API keys, and sensitive data."""
    js_analysis_results = {
        'js_endpoints': [],
        'api_keys': [],
        'emails_found': []
    }

    soup = BeautifulSoup(response_text, 'html.parser')
    script_tags = soup.find_all('script')

    js_contents = []
    external_js_urls = []

    # Extract inline and external JS URLs
    for script in script_tags:
        if script.get('src'):
            external_js_urls.append(urljoin(base_url, script['src']))
        elif script.string:
            js_contents.append(script.string)

    # Fetch external JS content concurrently
    if external_js_urls:
        print(f"  -> Mengambil {len(external_js_urls)} file JavaScript eksternal...")
        tasks = []
        for url in external_js_urls:
            tasks.append(_fetch_js_content(session, url))
        fetched_contents = await asyncio.gather(*tasks)
        js_contents.extend([content for content in fetched_contents if content])

    # Analyze all collected JS content
    for js_content in js_contents:
        # Extract URLs/endpoints
        url_patterns = [
            r'["\'](/[^"\']+\.(?:json|xml|php|asp|jsp|py|rb|js|css))["\']',  # Internal files
            r'["\']https?://[^"\']+(?:api|ajax|endpoint)[^"\']*["\']',  # API endpoints
            r'["\']([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']'  # Emails
        ]

        for pattern in url_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/'):
                    js_analysis_results['js_endpoints'].append(urljoin(base_url, match))
                elif '@' in match:
                    js_analysis_results['emails_found'].append(match)
                else:
                    js_analysis_results['js_endpoints'].append(match)

        # Look for API keys and tokens
        key_patterns = [
            r'(?:api[_-]?key|token|secret|password)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})["\']?',  # API keys
            r'["\']([A-Za-z0-9+/]{20,}=)["\']',  # Base64 encoded data
            r'["\']([0-9a-f]{32,})["\']'  # Hashes/MD5
        ]

        for pattern in key_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if len(match) > 15: # Reasonable length for keys
                    js_analysis_results['api_keys'].append({
                        'value': match,
                        'context': 'JavaScript',
                        'potential_type': 'Kunci API/Token'
                    })

    # Remove duplicates
    js_analysis_results['js_endpoints'] = list(set(js_analysis_results['js_endpoints']))
    js_analysis_results['emails_found'] = list(set(js_analysis_results['emails_found']))

    return js_analysis_results

async def _fetch_js_content(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetches content of an external JavaScript file."""
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        print(f"[-] Gagal mengambil file JS eksternal {url}: {e}")
        return None
    except Exception as e:
        print(f"[-] Terjadi kesalahan tak terduga saat mengambil file JS eksternal {url}: {e}")
        return None
