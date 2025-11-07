
import argparse
import asyncio
import json
import os
from urllib.parse import urlparse

from recon_tool.scanner import Scanner
from recon_tool.report_generator import generate_html_report

# --- Banner --- 
try:
    os.system('figlet -f slant beyrec')
except:
    print("beyrec")
print('\n\tCreated By Bebey v2.0\n')
print('='*30)

os.system("mkdir -p output")

def main():
    parser = argparse.ArgumentParser(
        # description='Recon Tool v2.0 - Alat rekognisi web canggih.',
        formatter_class=argparse.HelpFormatter,
        # epilog='Contoh: python main.py -u https://example.com atau python main.py -u http://target.local:8080 -o hasil.json'
    )
    parser.add_argument('-u', '--url', required=True, help='URL target untuk dipindai')
    parser.add_argument('-d','--timeout', type=int, default=10, help='Batas waktu permintaan dalam detik (default: 10)')
    parser.add_argument('-o', '--output', help='File output untuk hasil (format JSON)')
    parser.add_argument('-w','--wordlist', help='Path ke wordlist kustom untuk penemuan konten')
    parser.add_argument('-oh','--html-output', help='File output untuk laporan HTML')

    args = parser.parse_args()

    # Validasi dan normalisasi URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"URL tidak valid: {args.url}. Harap sertakan http:// atau https://")
        return

    print(f"[*] Memulai pemindaian untuk target: {args.url}")

    # Inisialisasi dan jalankan pemindai
    scanner = Scanner(args.url, timeout=args.timeout, wordlist_path=args.wordlist)
    results = asyncio.run(scanner.scan())

    if args.output:
        try:
            with open(f"output/{args.output}", 'w') as f:
                json.dump(results, f, indent=4, default=str) # Gunakan default=str untuk data yang tidak dapat diserialkan
            print(f"[+] Hasil pemindaian disimpan ke output/{args.output}")
        except Exception as e:
            print(f"[-] Gagal menyimpan hasil ke file: {e}")

    if args.html_output:
        generate_html_report(results, args.html_output)

    if not args.output and not args.html_output:
        # Cetak ke konsol jika tidak ada file output yang ditentukan
        print(json.dumps(results, indent=4, default=str))


if __name__ == "__main__":
    main()
