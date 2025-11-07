
import asyncio
import aiohttp
import aiofiles
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

MAX_CRAWL_DEPTH = 2 # Limit the crawling depth to prevent excessive scanning

async def _check_path(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    """Makes a HEAD request to check if a path exists and returns its status."""
    try:
        async with session.head(url, allow_redirects=False) as response:
            return {'url': url, 'status': response.status}
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return {'url': url, 'status': -1} # Indicate an error

async def _fetch_page_content(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetches the HTML content of a given URL, handling various encodings."""
    try:
        async with session.get(url, allow_redirects=True) as response:
            response.raise_for_status() # Raise an exception for HTTP errors

            # Try to get encoding from Content-Type header
            content_type = response.headers.get('Content-Type', '').lower()
            encoding = 'utf-8' # Default encoding
            if 'charset=' in content_type:
                encoding = content_type.split('charset=')[-1].split(';')[0].strip()

            try:
                return await response.text(encoding=encoding)
            except UnicodeDecodeError:
                # Fallback to more permissive encodings if UTF-8 fails
                try:
                    return await response.text(encoding='latin-1')
                except UnicodeDecodeError:
                    # If even latin-1 fails, return None or handle as binary
                    print(f"[-] Gagal mendekode konten dari {url} dengan UTF-8 atau latin-1.")
                    return None
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"[-] Gagal mengambil konten dari {url}: {e}")
        return None

def _extract_links_and_forms(html_content: str, base_url: str) -> Dict[str, Any]:
    """Extracts links and form details from HTML content."""
    new_urls = set()
    discovered_parameters = {
        'get': set(),
        'post': set()
    }
    discovered_endpoints = set()

    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract links from <a> tags
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        if urlparse(full_url).netloc == urlparse(base_url).netloc: # Only internal links
            new_urls.add(full_url)
            discovered_endpoints.add(full_url)
            # Extract GET parameters
            query_params = parse_qs(urlparse(full_url).query)
            for param_name in query_params.keys():
                discovered_parameters['get'].add(param_name)

    # Extract links from <script> and <link> tags (src/href attributes)
    for tag in soup.find_all(['script', 'link']):
        attr = 'src' if tag.name == 'script' else 'href'
        if tag.has_attr(attr):
            link = tag[attr]
            full_url = urljoin(base_url, link)
            if urlparse(full_url).netloc == urlparse(base_url).netloc: # Only internal links
                new_urls.add(full_url)
                discovered_endpoints.add(full_url)

    # Extract form details
    for form_tag in soup.find_all('form'):
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'get').lower()
        full_action_url = urljoin(base_url, action)
        if urlparse(full_action_url).netloc == urlparse(base_url).netloc: # Only internal forms
            discovered_endpoints.add(full_action_url)
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    discovered_parameters[method].add(name)

    return {
        'new_urls': new_urls,
        'discovered_parameters': discovered_parameters,
        'discovered_endpoints': discovered_endpoints
    }

async def analyze(session: aiohttp.ClientSession, base_url: str, discovery_patterns: Dict, wordlist_path: Optional[str] = None) -> Dict[str, Any]:
    """Performs content discovery by crawling, checking wordlists, and extracting parameters."""
    results = {
        'found_files': set(),
        'found_directories': set(),
        'discovered_endpoints': set(),
        'discovered_parameters': {
            'get': set(),
            'post': set()
        }
    }

    visited_urls = set()
    urls_to_visit = asyncio.Queue()
    current_depth = 0

    # Start with the base URL
    await urls_to_visit.put((base_url, 0))
    results['discovered_endpoints'].add(base_url)

    # Add URLs from wordlist/internal lists for initial checks
    all_paths_to_check = []
    if wordlist_path:
        print(f"  -> Memuat jalur dari wordlist kustom: {wordlist_path}...")
        all_paths_to_check.extend(await _load_paths_from_wordlist(wordlist_path))
    if not all_paths_to_check:
        print("  -> Menggunakan daftar jalur internal untuk penemuan konten...")
        files_to_check = discovery_patterns.get('extensions', [])
        dirs_to_check = [
            'admin', 'administrator', 'dashboard', 'panel', 'cpanel', 'webmail',
            'phpmyadmin', 'adminer', 'manager', 'control', 'login', 'auth',
            'api', 'v1', 'v2', 'graphql', 'rest', 'soap',
            'assets', 'static', 'public', 'dist', 'build', 'css', 'js', 'img',
            'uploads', 'files', 'documents', 'media', 'images', 'videos',
            'backup', 'backups', 'tmp', 'temp', 'cache', 'logs',
            'config', 'configs', 'settings', 'includes', 'inc', 'lib',
            'test', 'tests', 'dev', 'development', 'staging', 'beta'
        ]
        all_paths_to_check.extend(files_to_check)
        all_paths_to_check.extend(dirs_to_check)

    # Perform initial HEAD checks for wordlist paths concurrently
    head_tasks = []
    for path in all_paths_to_check:
        full_url = urljoin(base_url, path)
        if urlparse(full_url).netloc == urlparse(base_url).netloc: # Only internal paths
            head_tasks.append(_check_path(session, full_url))
    
    if head_tasks:
        print(f"  -> Memeriksa {len(head_tasks)} jalur wordlist umum...")
        head_responses = await asyncio.gather(*head_tasks)
        for res in head_responses:
            if res['status'] == 200:
                if res['url'].endswith('/'):
                    results['found_directories'].add(res['url'])
                else:
                    results['found_files'].add(res['url'])
                # Add found paths to urls_to_visit for potential crawling if not already visited
                if res['url'] not in visited_urls:
                    await urls_to_visit.put((res['url'], 0)) # Treat as depth 0 for crawling purposes

    # Main crawling loop
    print(f"  -> Memulai perayapan dengan kedalaman maksimum {MAX_CRAWL_DEPTH}...")
    while not urls_to_visit.empty() and current_depth <= MAX_CRAWL_DEPTH:
        url, depth = await urls_to_visit.get()

        if url in visited_urls or depth > MAX_CRAWL_DEPTH:
            continue

        visited_urls.add(url)
        # print(f"    -> Merayapi: {url} (Kedalaman: {depth})")

        html_content = await _fetch_page_content(session, url)
        if html_content:
            extracted_data = _extract_links_and_forms(html_content, base_url)
            
            # Add new URLs to queue
            for new_url in extracted_data['new_urls']:
                if new_url not in visited_urls:
                    await urls_to_visit.put((new_url, depth + 1))
            
            # Update discovered endpoints and parameters
            results['discovered_endpoints'].update(extracted_data['discovered_endpoints'])
            results['discovered_parameters']['get'].update(extracted_data['discovered_parameters']['get'])
            results['discovered_parameters']['post'].update(extracted_data['discovered_parameters']['post'])

    # Convert sets to lists for JSON serialization
    results['found_files'] = list(results['found_files'])
    results['found_directories'] = list(results['found_directories'])
    results['discovered_endpoints'] = list(results['discovered_endpoints'])
    results['discovered_parameters']['get'] = list(results['discovered_parameters']['get'])
    results['discovered_parameters']['post'] = list(results['discovered_parameters']['post'])

    return results
