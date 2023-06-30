import requests
import logging
import random
import concurrent.futures

from fake_useragent import UserAgent

# List of vulnerable URLs to scan
urls = ["http://example.com/vulnerable1", "http://example.com/vulnerable2", ...]

# List of known vulnerabilities to check
vulnerabilities = [
    {
        "name": "SQL Injection",
        "payloads": ["' OR 1=1 --", ...],
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "payloads": ["<script>alert('XSS');</script>", ...],
    },
    ...
]

# Set up logging
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO)

# User Agent
ua = UserAgent()

def scan_url(url):
    for vulnerability in vulnerabilities:
        logging.info(f"Scanning {url} for {vulnerability['name']}...")
        for payload in vulnerability['payloads']:
            headers = {'User-Agent': ua.random}
            try:
                # Send a GET request with the payload
                response = requests.get(url + payload, headers=headers)
                # Check if the response indicates a vulnerability
                if vulnerability_detected(response):
                    logging.warning(f"Vulnerability found: {vulnerability['name']}")
                    logging.warning(f"Payload: {payload}")
                    break
            except requests.exceptions.RequestException as e:
                logging.error(f"Request exception: {e}")
                continue
        logging.info("Scan complete!")

def vulnerability_detected(response):
    if response.status_code == 200 and "Error" in response.text:
        return True
    return False

# Start scanning each URL in the list using multithreading
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(scan_url, urls)

