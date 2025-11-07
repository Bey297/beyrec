
from bs4 import BeautifulSoup
from typing import Dict, Any

def parse(status: int, headers: Dict, content: bytes, final_url: str) -> Dict[str, Any]:
    """Parses a raw HTTP response into a structured dictionary."""
    content_type = headers.get('content-type', 'unknown')
    title = 'Tidak Ada Judul'

    # Parse title only if the content is HTML
    if 'text/html' in content_type:
        try:
            soup = BeautifulSoup(content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag and title_tag.string:
                title = title_tag.string.strip()
        except Exception:
            # Ignore parsing errors for non-html content that might have text/html type
            pass

    return {
        'status_code': status,
        'final_url': final_url,
        'content_type': content_type,
        'content_length': len(content),
        'title': title
    }

