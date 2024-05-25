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
import argparse

important_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 500, 993, 995]

data_subdomains = {}
data_status_code = {}
data_ip_addresses = {}
data_ports = {}
data_email_phone = {}
data_whois = {}
data_wappalyzer = {}

# Locks for thread safety
print_lock = threading.Lock()
file_lock = threading.Lock()

# Argument parser
parser = argparse.ArgumentParser(description='Crawl a website and collect information.')
parser.add_argument('url', help='URL of the website to crawl')
parser.add_argument('-d', '--depth', type=int, default=2, help='Depth of crawling (default: 2)')
args = parser.parse_args()

count = 0

with open("subdomains.txt", "r") as file:
    subdomains = file.read().splitlines()

print_lock = threading.Lock()
file_lock = threading.Lock()

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
        ip = socket.gethostbyname(answer)
        return ip
    except socket.gaierror as e:
        return f"Error resolving IP: {e}"

def scan_port(ip_address, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((ip_address, port))
        s.close()
        
        if result == 0:
            status = f"Port {port} is open" 
        else :
            f"Port {port} is closed"
            
        results.append(status)
        data_ports[ip_address] = results
        # with file_lock:
        with open("extracted information/ports.txt", "w", encoding="utf-8") as file:
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
        pattern_email = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b") 
        # pattern_phone = re.compile(
        #     r'(\+\d{1,3}[\s-]?)?(\d{3}[\s-]?\d{3}[\s-]?\d{4}|\(\d{3}\)[\s-]?\d{3}[\s-]?\d{4})'
        # )
        pattern_phone = r"09\d{9}"
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

def download_images(url):
    if not is_valid_url(url):
        return
    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        img_tags = soup.find_all('img') + soup.find_all('link') + soup.find_all('script')
        directory = 'static/screenshots'
        if not os.path.exists(directory):
            os.makedirs(directory)
        downloaded_files = {}
        for img_tag in img_tags:
            img_url = img_tag.get('src') or img_tag.get('href')
            if img_url:
                img_url = urljoin(url, img_url)
                img_filename = os.path.basename(urlparse(img_url).path)
                if img_filename in downloaded_files:
                    counter = downloaded_files[img_filename]
                    img_filename = f"{os.path.splitext(img_filename)[0]}_{counter}{os.path.splitext(img_filename)[1]}"
                    downloaded_files[img_filename] = counter + 1
                else:
                    downloaded_files[img_filename] = 1
                img_response = requests.get(img_url)
                if (img_response.status_code == 200):
                    with open(os.path.join(directory, img_filename), 'wb') as img_file:
                        img_file.write(img_response.content)
    except Exception as e:
        with print_lock:
            print(f"Error downloading images: {e}")

def wappalyzer_integrated(url: str):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=20)
        results = wappalyzer.analyze_with_versions_and_categories(webpage)
        return results
    except Exception as e:
        return f"Wappalyzer analysis failed: {e}"

def run(playwright, url: str, suffix):
    try:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(url)
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
    with open("extracted information/links.txt", "w", encoding="utf-8") as file:
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
       
            with open("statuses_code.txt", "w", encoding="utf-8") as file:
                file.write(f"status and status_code of the link are --> {status} : {status_code}\n")
                
            with open("ip_addresses.txt", "w", encoding="utf-8") as file:
                file.write(f"ip addresses of the link are : {ip}\n")         
                
            with open("emails & phones.txt", "w", encoding="utf-8") as file:
                file.write(f"emails of the link are : {emails}\n")
                file.write(f"phone numbers of the link are : {phone_numbers}\n")
                
            with open("whois.txt", "w", encoding="utf-8") as file:
                file.write(f"whois information of the link are : \n{who_info} \n")
            
            with open("wappalyzer.txt", "w", encoding="utf-8") as file:           
                file.write(f"wappalyzer (with versions and categories) of the link are : \n{wappalyzer_results} \n")  
                      
            return data
        else:
            return link
    except Exception as e:
        with print_lock:
            print(f"Error processing {link}: {e}")
        return {}

def main_crawler(urls):
    count = 0
    results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        crawled_links_list = list(executor.map(crawl_site, urls))
    
    for i, crawled_links in enumerate(crawled_links_list):
        with ThreadPoolExecutor(max_workers=5) as executor:
            results.extend(executor.map(lambda x: process_link(x[0], x[1], count), crawled_links.items()))
            count += 1
    
    return results
