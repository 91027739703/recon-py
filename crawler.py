import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import dns.resolver
import socket
import threading
import re
import whois
import tldextract
from Wappalyzer import Wappalyzer, WebPage
from playwright.sync_api import sync_playwright
from concurrent.futures import ThreadPoolExecutor
import os
# import argparse

important_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 500, 993, 995]

data_ports = {}

# # Locks for thread safety
# print_lock = threading.Lock()
# file_lock = threading.Lock()


# Load subdomains from file
with open("subdomains.txt", "r") as file:
    subdomains = file.read().splitlines()
    
    
def SubDomains(domain: str):
    subdomains_data = []
    for subdomain in subdomains:
        try:
            answers = dns.resolver.resolve(f"{subdomain}.{domain}", "A")
            for ip in answers:
                subdomains_data.append(f"https://{subdomain}.{domain}, IP address: {ip}")
        except Exception as e:
            subdomains_data.append(f"Error performing DNS resolution for {subdomain}.{domain}: {e}")
    return subdomains_data

def MyStatus(url: str):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return "Success", response.status_code
    except requests.HTTPError as e:
        return f"HTTP Error: {e.response.status_code}", e.response.status_code
    except requests.RequestException as e:
        return f"Failed: {e}", None

def ip_address(domain):
    
    try:
        answer = urlparse(domain).netloc
        ips = socket.gethostbyname_ex(answer)
        if ips is not None:
            return ips[2][0]
    except socket.gaierror as e:
        return f"Error resolving IP: {e}"

def scan_port(ip_address, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        result = s.connect_ex((ip_address, port))
        s.close()
        
        if result == 0:
            status = f"Port {port} is open"
            results.append(status)
            data_ports[ip_address] = results
        else:
            status = f"Port {port} is closed"
            results.append(status)
            data_ports[ip_address] = results            
      
        
        with open("ports.txt", "a", encoding="utf-8") as file:
            for ip_address, port in data_ports.items():
                file.write(f"open or closed ports of {ip_address} is : {port}\n")
                
    except Exception as e:
        results.append(f"Error scanning port {port}: {e}")


def is_valid_phone_number(number):
    
    digits = re.sub(r'\D', '', number)
    if len(digits) < 10:
        return False
    if len(set(digits)) <= 4:
        return False
    return True

def extract_emails_and_phone_numbers(url):
    if not urlparse(url).scheme:
        url = "https://" + url
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        text = response.text
        
        pattern_email = re.compile(r"\b[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}\b") 
        pattern_phone = r'\b09\d{9}\b'
        
        emails = pattern_email.findall(text)
        phone_numbers = re.findall(pattern_phone, text)
        
        valid_numbers = set()
        for number in phone_numbers:
            number_str = ''.join(number)
            if is_valid_phone_number(number_str):
                valid_numbers.add(number_str)
        
        return emails, list(valid_numbers)
    except requests.RequestException as e:
        return f"Error extracting emails/phone numbers: {e}"


def WhoInformation(url: str):
    domain = urlparse(url).netloc
    try:
        who_info = whois.whois(domain)
        return who_info
    except Exception as e:
        return f"WHOIS lookup failed: {e}"


def is_valid_url(url):
    parsed_url = urlparse(url)
    return parsed_url.scheme in ['http', 'https']

def download_files(url : str, suffix : int):
    if not is_valid_url(url):
        return
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
      
        download_folder = os.path.join(os.getcwd(), 'download_files')
        os.makedirs(download_folder, exist_ok=True)
        
        img_tags = soup.find_all('img')
        img_tags += soup.find_all('script')
        
        for img_tag in img_tags:
            img_url = img_tag.get('src')
            if img_url and img_url.startswith('http'):
                
                img_name = f"{os.path.basename(urlparse(img_url).path)}.{suffix}"
                img_content = requests.get(img_url).content
                img_path = os.path.join(download_folder, img_name)
                
                with open(img_path, 'wb') as img_file:
                    img_file.write(img_content)
                print(f"Image {img_name} downloaded successfully!!")
        
        print(f"All images downloaded successfully!!")
    except Exception as e:
        print(f"Error downloading images from page: {e}")

def wappalyzer_integrated(url: str):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=25)
        results = wappalyzer.analyze_with_versions_and_categories(webpage)
        return results
    except Exception as e:
        return f"Wappalyzer analysis failed: {e}"

def run(playwright, url: str, suffix):
    try:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(url, timeout=50)
        screenshot_path = f'static/screenshots/screenshot{suffix}.png'
        page.screenshot(path=screenshot_path, full_page=True)
        return screenshot_path
    except Exception as e:
        return f"Error taking screenshot: {e}"
    finally:
        browser.close()

def crawl_site(url: str):
    links1 = set()
    unique_links = {}
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            full_url = urljoin(url, href)
            if full_url.startswith("http") and full_url not in unique_links:
                links1.add(full_url)
                unique_links[full_url] = 1
    except (requests.RequestException, ValueError) as e:
        print(f"Error crawling site {url}: {e}")

    for link in list(links1):
        try:
            response = requests.get(link)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            for sub_link in soup.find_all("a", href=True):
                href = sub_link.get("href")
                full_url = urljoin(link, href)
                if full_url.startswith("http") and full_url not in unique_links:
                    unique_links[full_url] = 2
        except (requests.RequestException, ValueError) as e:
            print(f"Error processing link {link}: {e}")
            
    written_links = set()
    with open("links.txt", "w", encoding="utf-8") as file:
        for link, depth in unique_links.items():
            if link not in written_links:
                file.write(f"{link} at depth {depth}\n")
                written_links.add(link)

    return unique_links

def process_link(link, depth, count):
    try:
        if depth == 1:
            response = requests.get(link)
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.find('title').text.strip() if soup.find('title') else 'No title'
            
            status, status_code = MyStatus(link)
            domain = urlparse(link).netloc
            extracted = tldextract.extract(domain)
            
            subdomains_data = SubDomains(f"{extracted.domain}.{extracted.suffix}")

            ip = ip_address(link)
            results = []
            threads = [threading.Thread(target=scan_port, args=(ip, port, results)) for port in important_ports]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
                
            emails, phone_numbers = extract_emails_and_phone_numbers(link)
            who_info = WhoInformation(link)
            wappalyzer_results = wappalyzer_integrated(link)
            # while True:
            count+=1
             
            download_files(link, count)
            screenshot_path = ""
            with sync_playwright() as playwright:
                screenshot_path = run(playwright, link, count)
            
            data = {
                "url": link,
                "title": title,
                "status": status,
                "status_code": status_code,
                "subdomains": subdomains_data,
                "ip": ip,
                "ports": results,
                "emails": emails,
                "phone_numbers": phone_numbers,
                "whois_info": who_info,
                "wappalyzer_results": wappalyzer_results,
                "screenshot_path": screenshot_path,
            }
            
            return data
        else:
            return link
            
    except Exception as e:
        
        print(f"Error processing {link}: {e}")
        return {}
    
def main_crawler(urls):
    count = 0
    results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        crawled_links_list = list(executor.map(crawl_site, urls))
    
    for crawled_links in enumerate(crawled_links_list):
        with ThreadPoolExecutor(max_workers=5) as executor:
            results.extend(executor.map(lambda x: process_link(x[0], x[1], count), crawled_links.items()))
            count += 1
    
    return results
