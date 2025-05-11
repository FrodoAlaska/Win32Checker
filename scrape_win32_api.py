import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import time

def get_win32_functions_from_msdocs():
    """
    Updated scraper for current Microsoft Win32 API documentation
    """
    BASE_URL = "https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list"
    API_REF_BASE = "https://learn.microsoft.com/en-us/windows/win32/api/"
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    })
    
    print("Fetching main API index...")
    try:
        response = session.get(BASE_URL)
        response.raise_for_status()
        
        # Debug: Save the page for inspection
        with open('debug_page.html', 'w', encoding='utf-8') as f:
            f.write(response.text)
        print("Saved page content to debug_page.html for inspection")
        
    except requests.RequestException as e:
        print(f"Failed to fetch main index: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    functions = set()

    # NEW: Find API categories using updated selectors
    api_sections = soup.find_all('div', class_='card')
    if not api_sections:
        api_sections = soup.select('div.li')
        if not api_sections:
            print("Error: Couldn't find API sections. Page structure may have changed.")
            print("Please check debug_page.html to identify current structure")
            return []

    print(f"Found {len(api_sections)} API sections")
    
    # Extract all API library links
    api_links = []
    for section in api_sections:
        for link in section.find_all('a', href=True):
            href = link['href']
            if '/windows/win32/api/' in href and 'index' not in href:
                full_url = urljoin(API_REF_BASE, href)
                if full_url not in api_links:
                    api_links.append(full_url)

    if not api_links:
        print("Warning: No API links found in sections")
        return []

    print(f"Found {len(api_links)} API reference pages to scan")

    # Process each API reference page (with rate limiting)
    for i, url in enumerate(api_links[:10], 1):  # Process first 10 for testing
        try:
            print(f"Processing page {i}/{len(api_links)}: {url}")
            time.sleep(2)  # Increased delay
            
            response = session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find function declarations in syntax sections
            for h2 in soup.find_all('h2', string=re.compile('Syntax')):
                code_block = h2.find_next('pre')
                if code_block:
                    text = code_block.get_text().strip()
                    matches = re.findall(
                        r'\b([A-Z][a-zA-Z0-9_]+)\s*\([^)]*\)',  # FunctionName(params)
                        text
                    )
                    for func in matches:
                        func_name = func.split('(')[0].strip()
                        if len(func_name) > 3 and not func_name.startswith(('WINAPI', 'CALLBACK')):
                            functions.add(func_name)
            
            # Additional function discovery in tables
            for table in soup.find_all('table'):
                for row in table.find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) >= 1:
                        potential_func = cols[0].get_text().strip()
                        if re.match(r'^[A-Z][a-zA-Z0-9_]+$', potential_func):
                            functions.add(potential_func)
            
        except Exception as e:
            print(f"  Error processing {url}: {e}")
            continue

    return sorted(functions)

def save_functions_to_file(functions, filename="win32_functions_list.txt"):
    """Save the function list to a file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(functions))
    print(f"Saved {len(functions)} functions to {filename}")

if __name__ == "__main__":
    print("Starting Win32 API function scraping...")
    functions = get_win32_functions_from_msdocs()
    
    if functions:
        save_functions_to_file(functions)
        print("Scraping completed successfully!")
        print(f"Total functions collected: {len(functions)}")
        print("Sample functions:", ', '.join(functions[:10]))
    else:
        print("No functions were collected. Please check the script or website structure.")
