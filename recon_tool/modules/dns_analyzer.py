
import dns.resolver
from typing import Dict, Any, List

async def analyze(domain: str) -> Dict[str, Any]:
    """Gathers comprehensive DNS intelligence for a given domain."""
    dns_results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'NS': [],
        'SOA': {},
        'TXT': [],
        'CNAME': [],
        'PTR': [] # For reverse DNS
    }

    # Create a resolver with explicit nameservers to avoid /etc/resolv.conf issues
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT']

    for rtype in record_types:
        try:
            # Use the custom resolver
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == 'MX':
                    records.append({'preference': rdata.preference, 'exchange': str(rdata.exchange).strip('.')})
                elif rtype == 'SOA':
                    dns_results['SOA'] = {
                        'mname': str(rdata.mname).strip('.'),
                        'rname': str(rdata.rname).strip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum,
                    }
                    break # Only one SOA record expected
                else:
                    records.append(str(rdata).strip('.'))
            if records and rtype != 'SOA': # SOA is handled separately
                dns_results[rtype] = records

        except dns.resolver.NoAnswer:
            pass # Tidak ada catatan dari tipe ini
        except dns.resolver.NXDOMAIN:
            dns_results['error'] = f"Domain {domain} tidak ada."
            return dns_results
        except dns.resolver.Timeout:
            dns_results['error'] = f"Permintaan DNS untuk {rtype} habis waktu."
        except Exception as e:
            dns_results['error'] = f"[Penganalisis DNS] Terjadi kesalahan tak terduga untuk catatan {rtype}: {e}"

    # Tangani CNAME secara spesifik karena mungkin menimpa catatan lain
    try:
        cname_answers = resolver.resolve(domain, 'CNAME')
        for rdata in cname_answers:
            dns_results['CNAME'].append(str(rdata.target).strip('.'))
    except dns.resolver.NoAnswer:
        pass
    except Exception: # Menangkap kesalahan DNS lainnya, misal jika CNAME ada maka pencarian lain gagal
        pass

    # Pencarian DNS terbalik untuk catatan A utama jika tersedia
    if dns_results['A']:
        main_ip = dns_results['A'][0]
        try:
            reverse_results = resolver.resolve_address(main_ip)
            for rdata in reverse_results:
                dns_results['PTR'].append(str(rdata).strip('.'))
        except Exception:
            pass # DNS terbalik mungkin tidak selalu tersedia
            
    return dns_results
