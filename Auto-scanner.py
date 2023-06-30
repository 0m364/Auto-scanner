import requests

# List of vulnerable URLs to scan
urls = [
    "http://example.com/vulnerable1",
    "http://example.com/vulnerable2",
    ...
]

# List of known vulnerabilities to check
vulnerabilities = [
    {
        "name": "SQL Injection",
        "payloads": [
            "' OR 1=1 --",
            ...
        ]
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "payloads": [
            "<script>alert('XSS');</script>",
            ...
        ]
    },
    ...
]

def scan_url(url):
    for vulnerability in vulnerabilities:
        print(f"Scanning {url} for {vulnerability['name']}...")
        for payload in vulnerability['payloads']:
            # Send a GET request with the payload
            response = requests.get(url + payload)

            # Check if the response indicates a vulnerability
            if vulnerability_detected(response):
                print(f"Vulnerability found: {vulnerability['name']}")
                print(f"Payload: {payload}")
                break

        print("Scan complete!")

def vulnerability_detected(response):
    # Conditions to check for vulnerability detection
    # For example, if response status code is 200 and error message is present
    if response.status_code == 200 and "Error" in response.text:
        return True
    return False

# Start scanning each URL in the list
for url in urls:
    scan_url(url)
