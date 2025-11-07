
import aiohttp
from typing import Dict, Any, Optional

async def analyze(session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
    """Gathers network and infrastructure intelligence using an external IP geolocation API."""
    network_info = {
        'ip': None,
        'isp': None,
        'organization': None,
        'country': None,
        'region': None,
        'city': None,
        'asn': None,
        'hosting_type': None,
        'error': None
    }

    try:
        # Use ip-api.com for IP geolocation
        async with session.get(f"http://ip-api.com/json/{domain}") as response:
            if response.status == 200:
                ip_data = await response.json()
                if ip_data.get('status') == 'success':
                    network_info['ip'] = ip_data.get('query')
                    network_info['isp'] = ip_data.get('isp')
                    network_info['organization'] = ip_data.get('org')
                    network_info['country'] = ip_data.get('country')
                    network_info['region'] = ip_data.get('regionName')
                    network_info['city'] = ip_data.get('city')
                    network_info['asn'] = ip_data.get('as')
                    network_info['hosting_type'] = _identify_hosting_type(ip_data.get('org', ''))
                else:
                    network_info['error'] = f"IP geolocation API returned status: {ip_data.get('message', 'unknown')}"
            else:
                network_info['error'] = f"IP geolocation API request failed with status: {response.status}"
    except aiohttp.ClientError as e:
        network_info['error'] = f"Kesalahan jaringan selama geolokasi IP: {e}"
    except Exception as e:
        network_info['error'] = f"Terjadi kesalahan tak terduga selama analisis jaringan: {e}"

    return network_info

def _identify_hosting_type(org_name: str) -> str:
    """Helper function to identify hosting provider type from organization name."""
    cloud_providers = ['amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure',
                      'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner']
    cdns = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'maxcdn', 'jsdelivr']

    org_lower = org_name.lower()
    if any(provider in org_lower for provider in cloud_providers):
        return "Infrastruktur Cloud"
    elif any(cdn in org_lower for cdn in cdns):
        return "CDN"
    elif 'shared' in org_lower or 'hosting' in org_lower:
        return "Shared Hosting"
    elif any(vps in org_lower for vps in ['vps', 'dedicated', 'virtual']):
        return "VPS/Dedicated"
    else:
        return "Tidak Dikenal/Perusahaan"
