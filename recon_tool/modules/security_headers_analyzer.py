
from typing import Dict, Any, List

def analyze(headers: Dict, security_header_definitions: Dict) -> Dict[str, Any]:
    """Analyzes HTTP response headers for security best practices."""
    analysis_results = {
        'present_headers': [],
        'missing_headers': [],
        'score': 0,
        'total_headers': len(security_header_definitions)
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_name, description in security_header_definitions.items():
        if header_name.lower() in headers_lower:
            analysis_results['present_headers'].append({
                'name': header_name,
                'value': headers_lower[header_name.lower()],
                'description': description
            })
            analysis_results['score'] += 1
        else:
            analysis_results['missing_headers'].append({
                'name': header_name,
                'description': description
            })

    return analysis_results
