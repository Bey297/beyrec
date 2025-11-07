
import asyncio
import ssl
import socket
from datetime import datetime
import hashlib
from typing import Dict, Any, List

async def analyze(domain: str) -> Dict[str, Any]:
    """Performs deep SSL/TLS certificate analysis for a given domain."""
    ssl_info = {
        'subject': {},
        'issuer': {},
        'not_before': None,
        'not_after': None,
        'days_until_expiry': None,
        'sha256_fingerprint': None,
        'sans': [],
        'error': None
    }

    try:
        # Create a default SSL context
        context = ssl.create_default_context()
        
        # Connect to the domain on port 443
        # Use asyncio.open_connection for non-blocking socket operations
        reader, writer = await asyncio.open_connection(domain, 443, ssl=context)
        
        # Get the peer certificate
        cert = writer.get_extra_info('peercert')
        
        if cert:
            # Basic certificate info
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])

            ssl_info['subject'] = {k: v for k, v in subject.items() if isinstance(k, str)}
            ssl_info['issuer'] = {k: v for k, v in issuer.items() if isinstance(k, str)}

            # Dates
            not_before_str = cert['notBefore']
            not_after_str = cert['notAfter']
            
            # Example format: 'Nov 10 12:00:00 2025 GMT'
            # Need to handle different possible formats or parse carefully
            try:
                not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days

                ssl_info['not_before'] = not_before.isoformat()
                ssl_info['not_after'] = not_after.isoformat()
                ssl_info['days_until_expiry'] = days_until_expiry
            except ValueError:
                ssl_info['not_before'] = not_before_str
                ssl_info['not_after'] = not_after_str
                ssl_info['error'] = "Tidak dapat mengurai tanggal sertifikat."

            # SANs (Subject Alternative Names)
            if 'subjectAltName' in cert:
                for san_type, san_value in cert['subjectAltName']:
                    ssl_info['sans'].append(f"{san_type}: {san_value}")

            # Certificate fingerprint (SHA256)
            ssl_info['sha256_fingerprint'] = "Tidak diimplementasikan secara langsung melalui asyncio.open_connection"

        else:
            ssl_info['error'] = "Tidak ada sertifikat peer yang ditemukan."

        writer.close()
        await writer.wait_closed()

    except ConnectionRefusedError:
        ssl_info['error'] = "Koneksi ditolak. Target mungkin tidak mendengarkan di port 443."
    except ssl.SSLError as e:
        ssl_info['error'] = f"Kesalahan SSL/TLS: {e}"
    except socket.gaierror:
        ssl_info['error'] = "Nama host tidak dapat diselesaikan."
    except asyncio.TimeoutError:
        ssl_info['error'] = "Koneksi habis waktu."
    except Exception as e:
        ssl_info['error'] = f"Terjadi kesalahan tak terduga selama analisis SSL: {e}"

    return ssl_info
