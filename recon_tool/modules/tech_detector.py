
import re
from typing import Dict, Any, List, Optional

# Define a threshold for technology detection
DETECTION_THRESHOLD = 70 # Technologies with a score >= this will be reported

async def detect(response_text: str, headers: Dict, final_url: str, tech_signatures: Dict) -> List[Dict[str, Any]]:
    """Detects technologies based on response content, headers, and signatures using a scoring system."""
    detected_techs = []
    response_text_lower = response_text.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for tech_name, patterns in tech_signatures.items():
        current_score = 0
        evidence = []
        version = None

        for pattern_info in patterns:
            pattern_type = pattern_info.get('type')
            pattern_value = pattern_info.get('pattern')
            score_value = pattern_info.get('score', 10) # Default score if not specified

            if not pattern_value: # Skip if no pattern is defined
                continue

            match = False
            if pattern_type == 'html' or pattern_type == 'body':
                if pattern_value.lower() in response_text_lower:
                    match = True
            elif pattern_type == 'header':
                header_name = pattern_info.get('name', '').lower()
                if header_name and header_name in headers_lower:
                    if re.search(pattern_value, headers_lower[header_name], re.IGNORECASE):
                        match = True
            elif pattern_type == 'js':
                # For JS patterns, we check in the entire response text for simplicity for now
                # A more advanced approach would parse JS files separately
                if pattern_value.lower() in response_text_lower:
                    match = True
            elif pattern_type == 'url':
                if pattern_value.lower() in final_url.lower():
                    match = True
            
            # Version detection patterns are special, they don't add to score directly
            # but extract version if a match is found.
            if pattern_type == 'version' and not version:
                version_match = re.search(pattern_value, response_text, re.IGNORECASE)
                if version_match and version_match.groups():
                    version = version_match.group(1)
                    evidence.append(f"Pola versi '{pattern_value}' cocok")

            if match:
                current_score += score_value
                evidence.append(f"Pola {pattern_type.upper()} '{pattern_value}' cocok (skor: {score_value})")

        if current_score >= DETECTION_THRESHOLD:
            detected_techs.append({
                'name': tech_name,
                'score': current_score,
                'version': version,
                'evidence': evidence[:5] # Limit evidence for readability
            })

    return detected_techs

