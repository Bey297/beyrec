
import json
import aiohttp
import aiofiles
from urllib.parse import urlparse
import os

# Import analysis modules
from .modules import http_analyzer, tech_detector, security_headers_analyzer, dns_analyzer, ssl_analyzer, discovery_analyzer, network_analyzer, osint_analyzer, vulnerability_analyzer, javascript_analyzer, cve_analyzer

class Scanner:
    def __init__(self, target_url: str, timeout: int = 10, wordlist_path: str = None):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc.replace('www.', '')
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}" # Use parsed_url.netloc to keep original subdomain if any
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.wordlist_path = wordlist_path

        self.results = {}
        self.config = {}

        # Get the absolute path of the directory where this file is located
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

    async def load_configs(self):
        """Loads all JSON configuration files."""
        config_files = {
            "technologies": "../config/technologies.json",
            "security_headers": "../config/security_headers.json",
            "discovery": "../config/discovery_patterns.json"
        }
        for name, path in config_files.items():
            abs_path = os.path.join(self.base_dir, path)
            self.config[name] = await self._load_json_config(abs_path)

    async def _load_json_config(self, file_path: str) -> dict:
        """Helper to load a single JSON config file."""
        try:
            async with aiofiles.open(file_path, 'r') as f:
                return json.loads(await f.read())
        except FileNotFoundError:
            print(f"[-] File konfigurasi tidak ditemukan: {file_path}")
            return {}
        except json.JSONDecodeError:
            print(f"[-] Gagal mendekode JSON dari {file_path}")
            return {}

    async def scan(self):
        """The main method to run all reconnaissance modules."""
        print("[*] Menginisialisasi pemindai...")
        await self.load_configs()
        print("[*] Konfigurasi dimuat.")

        async with aiohttp.ClientSession(timeout=self.timeout, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}) as session:
            
            # --- Fetch main target URL once ---
            print("[*] Mengambil URL target utama...")
            try:
                response = await session.get(self.target_url, allow_redirects=True)
                response_content = await response.read()
                response_text = await response.text()
                response_headers = response.headers
                response_status = response.status
                final_url = str(response.url)
            except aiohttp.ClientError as e:
                print(f"[-] Terjadi kesalahan kritis saat mengambil URL utama: {e}")
                self.results['error'] = str(e)
                return self.results

            # --- Run analysis modules ---
            print("[*] Menjalankan modul analisis...")
            
            # 1. HTTP Analysis
            print("  -> Menjalankan Penganalisis HTTP...")
            self.results['http_info'] = http_analyzer.parse(response_status, response_headers, response_content, final_url)

            # 2. Technology Detection
            print("  -> Menjalankan Detektor Teknologi...")
            self.results['technologies'] = await tech_detector.detect(response_text, response_headers, final_url, self.config.get('technologies', {}))

            # 3. Security Headers Analysis
            print("  -> Menjalankan Penganalisis Header Keamanan...")
            self.results['security_headers'] = security_headers_analyzer.analyze(response_headers, self.config.get('security_headers', {}))

            # 4. DNS Analysis
            print("  -> Menjalankan Penganalisis DNS...")
            self.results['dns_records'] = await dns_analyzer.analyze(self.domain)

            # 5. SSL/TLS Analysis
            print("  -> Menjalankan Penganalisis SSL/TLS...")
            self.results['ssl_info'] = await ssl_analyzer.analyze(self.domain)

            # 6. Content Discovery
            print("  -> Menjalankan Penemuan Konten...")
            self.results['discovery'] = await discovery_analyzer.analyze(session, self.base_url, self.config.get('discovery', {}), self.wordlist_path)

            # 7. Network Analysis
            print("  -> Menjalankan Penganalisis Jaringan...")
            self.results['network_info'] = await network_analyzer.analyze(session, self.domain)

            # 8. OSINT Suggestions
            print("  -> Menjalankan Penganalisis OSINT...")
            self.results['osint_suggestions'] = osint_analyzer.analyze(self.domain)

            # 9. Vulnerability Indicators, WAF Detection, and PoC Suggestions
            print("  -> Menjalankan Penganalisis Kerentanan, Deteksi WAF, dan Saran PoC...")
            vuln_analysis_results = await vulnerability_analyzer.analyze(
                response_text, response_headers, final_url,
                self.results['discovery'],
                self.results['discovery'].get('discovered_parameters') # Pass discovered parameters
            )
            self.results['vulnerability_indicators'] = vuln_analysis_results['indicators']
            self.results['waf_info'] = vuln_analysis_results['waf_info']
            self.results['vulnerability_suggestions'] = vuln_analysis_results['vulnerability_suggestions']

            # 10. JavaScript Analysis
            print("  -> Menjalankan Penganalisis JavaScript...")
            self.results['javascript_analysis'] = await javascript_analyzer.analyze(response_text, session, self.base_url)

            # 11. CVE Analysis
            print("  -> Menjalankan Penganalisis CVE...")
            cve_findings = []
            for tech in self.results['technologies']:
                if tech['version']:
                    cve_findings.extend(await cve_analyzer.analyze(session, tech['name'], tech['version']))
            self.results['cve_findings'] = cve_findings

        print("[*] Pemindaian selesai.")
        return self.results
