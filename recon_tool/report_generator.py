
import json
from typing import Dict, Any, List, Optional
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# Define the template environment
TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

def generate_html_report(results: Dict, output_file: str):
    """Generates a human-readable HTML report from the scan results using Jinja2 template."""
    template = env.get_template("report_template.html")

    # Prepare data for rendering
    data = {
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'target_url': results.get('http_info', {}).get('final_url', 'N/A'),
        'domain': results.get('dns_records', {}).get('domain', 'N/A'),
        'http_info': json.dumps(results.get('http_info', {}), indent=2, ensure_ascii=False),
        'technologies': _format_technologies(results.get('technologies', [])),
        'security_headers': _format_security_headers(results.get('security_headers', {})),
        'dns_records': json.dumps(results.get('dns_records', {}), indent=2, ensure_ascii=False),
        'ssl_info': json.dumps(results.get('ssl_info', {}), indent=2, ensure_ascii=False),
        'discovery': _format_discovery(results.get('discovery', {})),
        'discovered_endpoints': _format_discovered_endpoints(results.get('discovery', {}).get('discovered_endpoints', [])),
        'discovered_parameters': _format_discovered_parameters(results.get('discovery', {}).get('discovered_parameters', {})),
        'network_info': json.dumps(results.get('network_info', {}), indent=2, ensure_ascii=False),
        'osint_suggestions': _format_osint(results.get('osint_suggestions', {})),
        'vulnerability_indicators': _format_vulnerabilities(results.get('vulnerability_indicators', [])),
        'waf_info': _format_waf_info(results.get('waf_info', {})),
        'vulnerability_suggestions': _format_vulnerability_suggestions(results.get('vulnerability_suggestions', [])),
        'javascript_analysis': json.dumps(results.get('javascript_analysis', {}), indent=2, ensure_ascii=False),
        'cve_findings': _format_cve_findings(results.get('cve_findings', [])),
        'error': _format_error(results.get('error'))
    }

    html_content = template.render(data)

    try:
        with open(f"output/{output_file}", 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[+] Laporan HTML disimpan ke output/{output_file}")
    except Exception as e:
        print(f"[-] Gagal menyimpan laporan HTML: {e}")

def _format_technologies(techs: List[Dict]) -> str:
    if not techs:
        return "<p>Tidak ada teknologi yang terdeteksi.</p>"
    html = "<ul>"
    for tech in techs:
        version_str = f" (v{tech['version']})" if tech['version'] else ""
        html += f"<li><strong>{tech['name']}{version_str}</strong> <span class=\"tech-score\">(Skor: {tech['score']})</span><br/>"
        html += "<ul>"
        for evidence in tech.get('evidence', []):
            html += f"<li>{evidence}</li>"
        html += "</ul></li>"
    html += "</ul>"
    return html

def _format_security_headers(headers_info: Dict) -> str:
    html = "<h3>Header Hadir:</h3>"
    if headers_info.get('present_headers'):
        html += "<ul>"
        for header in headers_info['present_headers']:
            html += f"<li><span class=\"header-present\">{header['name']}</span>: {header['value']} - <em>{header['description']}</em></li>"
        html += "</ul>"
    else:
        html += "<p>Tidak ada header keamanan yang hadir.</p>"

    html += "<h3>Header Hilang:</h3>"
    if headers_info.get('missing_headers'):
        html += "<ul>"
        for header in headers_info['missing_headers']:
            html += f"<li><span class=\"header-missing\">{header['name']}</span>: <em>{header['description']}</em></li>"
        html += "</ul>"
    else:
        html += "<p>Semua header keamanan penting hadir.</p>"
    
    html += f"<p><strong>Skor Keamanan:</strong> {headers_info.get('score', 0)} dari {headers_info.get('total_headers', 0)}</p>"
    return html

def _format_discovery(discovery_info: Dict) -> str:
    html = "<h3>File Ditemukan:</h3>"
    if discovery_info.get('found_files'):
        html += "<ul>"
        for f in discovery_info['found_files']:
            html += f"<li>{f}</li>"
        html += "</ul>"
    else:
        html += "<p>Tidak ada file yang ditemukan.</p>"

    html += "<h3>Direktori Ditemukan:</h3>"
    if discovery_info.get('found_directories'):
        html += "<ul>"
        for d in discovery_info['found_directories']:
            html += f"<li>{d}</li>"
        html += "</ul>"
    else:
        html += "<p>Tidak ada direktori yang ditemukan.</p>"
    return html

def _format_discovered_endpoints(endpoints: List[str]) -> str:
    if not endpoints:
        return "<p>Tidak ada endpoint yang ditemukan melalui perayapan.</p>"
    html = "<ul>"
    for ep in endpoints:
        html += f"<li><a href=\"{ep}\" target=\"_blank\">{ep}</a></li>"
    html += "</ul>"
    return html

def _format_discovered_parameters(parameters: Dict[str, List[str]]) -> str:
    html = ""
    if parameters.get('get'):
        html += "<h4>Parameter GET:</h4><ul>"
        for param in parameters['get']:
            html += f"<li>{param}</li>"
        html += "</ul>"
    else:
        html += "<p>Tidak ada parameter GET yang ditemukan.</p>"

    if parameters.get('post'):
        html += "<h4>Parameter POST:</h4><ul>"
        for param in parameters['post']:
            html += f"<li>{param}</li>"
        html += "</ul>"
    else:
        html += "<p>Tidak ada parameter POST yang ditemukan.</p>"
    return html

def _format_osint(osint_suggestions: Dict) -> str:
    html = "<ul>"
    for name, url in osint_suggestions.items():
        html += f"<li><strong>{name.replace('_', ' ').title()}:</strong> <a href=\"{url}\" target=\"_blank\">{url}</a></li>"
    html += "</ul>"
    return html

def _format_vulnerabilities(vulns: List[Dict]) -> str:
    if not vulns:
        return "<p>Tidak ada indikator kerentanan yang terdeteksi.</p>"
    html = "<table><tr><th>Nama</th><th>Risiko</th><th>Deskripsi</th></tr>"
    for vuln in vulns:
        risk_color = "red" if vuln['risk'] == 'Tinggi' else "orange"
        html += f"<tr><td>{vuln['name']}</td><td style=\"color: {risk_color};\">{vuln['risk']}</td><td>{vuln['description']}</td></tr>"
    html += "</table>"
    return html

def _format_cve_findings(cve_findings: List[Dict]) -> str:
    if not cve_findings:
        return "<p>Tidak ada CVE yang ditemukan untuk teknologi yang terdeteksi.</p>"
    html = "<table><tr><th>ID CVE</th><th>Deskripsi</th><th>Tingkat Keparahan</th><th>Sumber</th></tr>"
    for cve in cve_findings:
        severity_class = "severity-unknown"
        if cve['severity'] == 'HIGH':
            severity_class = "severity-high"
        elif cve['severity'] == 'MEDIUM':
            severity_class = "severity-medium"
        elif cve['severity'] == 'LOW':
            severity_class = "severity-low"
        
        html += f"<tr>"
        html += f"<td><a href=\"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}\" target=\"_blank\">{cve['cve_id']}</a></td>"
        html += f"<td>{cve['description']}</td>"
        html += f"<td class=\"{severity_class}\">{cve['severity']}</td>"
        html += f"<td>{cve['source']}</td>"
        html += f"</tr>"
    html += "</table>"
    return html

def _format_waf_info(waf_info: Dict) -> str:
    if not waf_info or not waf_info.get('detected'):
        return "<p>Tidak ada WAF yang terdeteksi.</p>"
    
    html = f"<p><strong>WAF Terdeteksi:</strong> {waf_info.get('name', 'Tidak Diketahui')}</p>"
    if waf_info.get('provider'):
        html += f"<p><strong>Penyedia:</strong> {waf_info['provider']}</p>"
    if waf_info.get('version'):
        html += f"<p><strong>Versi:</strong> {waf_info['version']}</p>"
    if waf_info.get('ruleset'):
        html += f"<p><strong>Aturan:</strong> {waf_info['ruleset']}</p>"
    if waf_info.get('notes'):
        html += f"<p><strong>Catatan:</strong> {waf_info['notes']}</p>"
    return html

def _format_vulnerability_suggestions(suggestions: List[Dict]) -> str:
    if not suggestions:
        return "<p>Tidak ada saran kerentanan yang dihasilkan.</p>"
    
    html = "<table><tr><th>Tipe</th><th>Deskripsi</th><th>Rekomendasi</th></tr>"
    for suggestion in suggestions:
        html += f"<tr><td>{suggestion.get('type', 'N/A')}</td><td>{suggestion.get('description', 'N/A')}</td><td>{suggestion.get('recommendation', 'N/A')}</td></tr>"
    html += "</table>"
    return html

def _format_error(error_msg: Optional[str]) -> str:
    if error_msg:
        return f"<div class=\"section\"><h2 class=\"error\">Kesalahan Umum</h2><p>{error_msg}</p></div>"
    return ""

